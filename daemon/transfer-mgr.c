/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <unistd.h>
#include <limits.h>
#include <string.h>

#include <ccnet.h>
#include "utils.h"
#include "db.h"

#include <openssl/rand.h>

#include "seafile-session.h"
#include "transfer-mgr.h"
#include "commit-mgr.h"
#include "fs-mgr.h"
#include "block-mgr.h"
#include "seafile-error.h"
#include "vc-common.h"
#include "merge.h"
#include "sync-mgr.h"
#include "clone-mgr.h"
#include "vc-utils.h"
#include "mq-mgr.h"
#include "seafile-config.h"

#include "processors/check-tx-v2-proc.h"
#include "processors/check-tx-v3-proc.h"
#include "processors/sendfs-proc.h"
#include "processors/getfs-proc.h"
#include "processors/getcs-proc.h"
#include "processors/sendbranch-proc.h"
#include "processors/getcommit-v2-proc.h"
#include "processors/getcommit-v3-proc.h"
#include "processors/sendcommit-v3-proc.h"
#include "processors/sendcommit-v3-new-proc.h"
#include "processors/checkbl-proc.h"
#include "processors/getcs-v2-proc.h"
#include "processors/sendcommit-v4-proc.h"
#include "processors/sendfs-v2-proc.h"
#include "processors/getfs-v2-proc.h"

#include "block-tx-client.h"

#include "diff-simple.h"

#define TRANSFER_DB "transfer.db"

#define SCHEDULE_INTERVAL   1   /* 1s */
#define MAX_QUEUED_BLOCKS   50

#define DEFAULT_BLOCK_SIZE  (1 << 20)

static int schedule_task_pulse (void *vmanager);
static void state_machine_tick (TransferTask *task);
static void
transition_state (TransferTask *task, int state, int rt_state);

/**
 * transfer task states:
 *
 *          INIT        COMMIT      FS      DATA        FINISHED   NETDOWN
 * ------------------------------------------------------------------------
 * NORMAL   1           2           3       4           x          15
 * CANCELED x           9           10      11          12         x
 * FINISHED x           x           x       x           13         x
 * ERROR    x           x           x       x           14         x
 *
 * state transitions:
 * Event                                        Transition
 * -------------------------------------------------------
 * start commit tx                              1 --> 2
 * start fs tx                                  2 --> 3
 * start block tx                               3 --> 4
 * complete block tx                            4 --> 13
 *
 * user cancel task                             2 --> 9, 3 --> 10,
 *                                              4 --> 11, 15 -->12
 * 
 * on_commit_uploaded(),                        
 * on_commit_downloaded()
 * checks task canceled                         9 --> 12
 * if connection lost                           9 --> 15
 *
 * on_fs_uploaded(),                            
 * on_fs_downloaded()
 * checks task canceled                         10 --> 12
 * if connection lost                           10 --> 15
 *
 * state_machine_tick()     
 * checks task canceled in DATA state           11 --> 12
 *
 * error in COMMIT or FS state                  --> 14
 *
 * User can remove a task only when its runtime state is 'FINISHED'.
 * User can cancel a task only when its state is 'NORMAL'.
 */

/*
 * Transfer Task.
 */

static const char *transfer_task_state_str[] = {
    "normal",
    "canceled",
    "finished",
    "error",
};

static const char *transfer_task_rt_state_str[] = {
    "init",
    "check",
    "commit",
    "fs",
    "check-blocks",
    "get-chunk-server",
    "data",
    "update-branch",
    "finished",
    "netdown",
};

static const char *transfer_task_error_strs[] = {
    "Successful",
    "Unknown error",
    "Service on remote server is not available",
    "Access denied to service. Please check your registration on server.",
    "Internal error when preparing upload",
    "Internal error when preparing download",
    "No permission to access remote library",
    "Library doesn't exist on the remote end",
    "Internal error when starting to send revision information",
    "Internal error when starting to get revision information",
    "Failed to upload revision information to remote library",
    "Failed to get revision information from remote library",
    "Internal error when starting to send file information",
    "Internal error when starting to get file information",
    "Incomplete file information in the local library",
    "Failed to upload file information to remote library",
    "Failed to get file information from remote library",
    "Incomplete file information in the local library",
    "Internal error when starting to update remote library",
    "Others have concurrent updates to the remote library. You need to sync again.",
    "Storage quota full",
    "Server failed to check storage quota",
    "Transfer protocol outdated. You need to upgrade seafile.",
    "Incomplete revision information in the local library",
    "Failed to compare data to server.",
    "Failed to get block server list.",
    "Failed to start block transfer client.",
    "Failed to upload blocks.",
    "Failed to download blocks.",
    "Server version is too old."
    "Files are locked by other application.",
};

const char *
task_state_to_str (int state)
{
    return transfer_task_state_str[state];
}

const char *
task_rt_state_to_str (int rt_state)
{
    return transfer_task_rt_state_str[rt_state];
}

const char *
task_error_str (int task_errno)
{
    return transfer_task_error_strs[task_errno];
}

static TransferTask *
seaf_transfer_task_new (SeafTransferManager *manager,
                        const char *tx_id,
                        const char *repo_id,
                        const char *dest_id,
                        const char *from_branch,
                        const char *to_branch,
                        const char *token,
                        int task_type)
{
    TransferTask *task;
    char *uuid;

    g_return_val_if_fail (repo_id != NULL, NULL);
    g_return_val_if_fail (from_branch != NULL, NULL);
    g_return_val_if_fail (to_branch != NULL, NULL);
    g_return_val_if_fail (token != NULL, NULL);

    task = g_new0 (TransferTask, 1);
    task->manager = manager;
    memcpy (task->repo_id, repo_id, 37);
    task->repo_id[36] = '\0';
    task->type = task_type;
    task->runtime_state = TASK_RT_STATE_INIT;
    task->from_branch = g_strdup(from_branch);
    task->to_branch = g_strdup(to_branch);
    task->token = g_strdup(token);
    if (!tx_id) {
        uuid = gen_uuid();
        memcpy (task->tx_id, uuid, 37);
        g_free (uuid);
    } else {
        memcpy (task->tx_id, tx_id, 37);
    }

    if (dest_id)
        task->dest_id = g_strdup(dest_id);

    task->rsize = -1;
    task->dsize = 0;
    return task;
}

static void
free_block_id (gpointer data, gpointer user_data)
{
    g_free (data);
}

static void
free_chunk_server (gpointer data, gpointer user_data)
{
    ChunkServer *cs = data;
    g_free (cs->addr);
    g_free (cs);
}

static void
seaf_transfer_task_free (TransferTask *task)
{
    g_free (task->session_token);
    g_free (task->dest_id);
    g_free (task->from_branch);
    g_free (task->to_branch);
    g_free (task->token);

    if (task->fs_roots)
        object_list_free (task->fs_roots);

    if (task->commits)
        object_list_free (task->commits);

    if (task->protocol_version < 7 && task->block_ids) {
        g_queue_foreach (task->block_ids, free_block_id, NULL);
        g_queue_free (task->block_ids);
    }

    if (task->protocol_version >= 4) {
        g_list_foreach (task->chunk_servers, free_chunk_server, NULL);
        g_list_free (task->chunk_servers);
        if (task->block_list)
            block_list_free (task->block_list);
    }

    g_free (task);
}

int
transfer_task_get_rate (TransferTask *task)
{
    return task->last_tx_bytes;
}

int
transfer_task_get_done_blocks (TransferTask *task)
{
    if (task->runtime_state != TASK_RT_STATE_DATA)
        return 0;

    if (task->protocol_version >= 7 && task->type == TASK_TYPE_DOWNLOAD)
        return task->n_downloaded;

    if (task->protocol_version >= 4) {
        int n_left = g_queue_get_length (task->block_ids);
        return task->block_list->n_blocks - n_left;
    }

    if (task->type == TASK_TYPE_UPLOAD)
        return task->n_uploaded;
    else
        return task->block_list->n_valid_blocks;
}

static void
emit_transfer_done_signal (TransferTask *task)
{
    if (task->type == TASK_TYPE_DOWNLOAD)
        g_signal_emit_by_name (seaf, "repo-fetched", task);
    else
        g_signal_emit_by_name (seaf, "repo-uploaded", task);
}

static void
transition_state (TransferTask *task, int state, int rt_state)
{
    seaf_message ("Transfer repo '%.8s': ('%s', '%s') --> ('%s', '%s')\n",
                  task->repo_id,
                  task_state_to_str(task->state),
                  task_rt_state_to_str(task->runtime_state),
                  task_state_to_str(state),
                  task_rt_state_to_str(rt_state));

    task->last_runtime_state = task->runtime_state;

    if (rt_state == TASK_RT_STATE_FINISHED) {
        /* Clear download head info. */
        if (task->protocol_version >= 7 && task->type == TASK_TYPE_DOWNLOAD &&
            state == TASK_STATE_FINISHED)
            seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                                 task->repo_id,
                                                 REPO_PROP_DOWNLOAD_HEAD,
                                                 EMPTY_SHA1);

        task->state = state;
        task->runtime_state = rt_state;

        emit_transfer_done_signal (task);

        return;
    }

    if (state != task->state)
        task->state = state;
    task->runtime_state = rt_state;
}

void
transition_state_to_error (TransferTask *task, int task_errno)
{
    g_return_if_fail (task_errno != 0);

    seaf_message ("Transfer repo '%.8s': ('%s', '%s') --> ('%s', '%s'): %s\n",
                  task->repo_id,
                  task_state_to_str(task->state),
                  task_rt_state_to_str(task->runtime_state),
                  task_state_to_str(TASK_STATE_ERROR),
                  task_rt_state_to_str(TASK_RT_STATE_FINISHED),
                  task_error_str(task_errno));

    task->last_runtime_state = task->runtime_state;

    task->state = TASK_STATE_ERROR;
    task->runtime_state = TASK_RT_STATE_FINISHED;
    task->error = task_errno;

    emit_transfer_done_signal (task);
}

void
transfer_task_set_error (TransferTask *task, int error)
{
    transition_state_to_error (task, error);
}

void
transfer_task_set_netdown (TransferTask *task)
{
    g_return_if_fail (task->state == TASK_STATE_NORMAL);
    if (task->runtime_state == TASK_RT_STATE_NETDOWN)
        return;
    transition_state (task, TASK_STATE_NORMAL, TASK_RT_STATE_NETDOWN);
}

static void
transfer_task_with_proc_failure (TransferTask *task,
                                 CcnetProcessor *proc,
                                 int defalut_error)
{
    seaf_debug ("Transfer repo '%.8s': proc %s(%d) failure: %d\n",
                task->repo_id,
                GET_PNAME(proc), PRINT_ID(proc->id),
                proc->failure);

    switch (proc->failure) {
    case PROC_DONE:
        /* It can never happen */
        g_return_if_reached ();
    case PROC_REMOTE_DEAD:
        seaf_warning ("[tr-mgr] Shutdown processor with failure %d\n",
                   proc->failure);
        transfer_task_set_netdown (task);
        break;
    case PROC_NO_SERVICE:
        transition_state_to_error (task, TASK_ERR_NO_SERVICE);
        break;
    case PROC_PERM_ERR:
        transition_state_to_error (task, TASK_ERR_PROC_PERM_ERR);
        break;
    case PROC_BAD_RESP:
    case PROC_NOTSET:
    default:
        transition_state_to_error (task, defalut_error);
    }
}

inline static gboolean is_peer_relay (const char *peer_id)
{
    CcnetPeer *peer = ccnet_get_peer(seaf->ccnetrpc_client, peer_id);

    if (!peer)
        return FALSE;

    gboolean is_relay = string_list_is_exists(peer->role_list, "MyRelay");
    g_object_unref (peer);
    return is_relay;
}

/*
 * Transfer Manager.
 */

SeafTransferManager*
seaf_transfer_manager_new (struct _SeafileSession *seaf)
{
    SeafTransferManager *mgr = g_new0 (SeafTransferManager, 1);

    mgr->seaf = seaf;
    mgr->download_tasks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                 (GDestroyNotify) g_free,
                                                 (GDestroyNotify) seaf_transfer_task_free);
    mgr->upload_tasks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                               (GDestroyNotify) g_free,
                                               (GDestroyNotify) seaf_transfer_task_free);

    char *db_path = g_build_path (PATH_SEPERATOR, seaf->seaf_dir, TRANSFER_DB, NULL);
    if (sqlite_open_db (db_path, &mgr->db) < 0) {
        g_critical ("[Transfer mgr] Failed to open transfer db\n");
        g_free (db_path);
        g_free (mgr);
        return NULL;
    }

    return mgr;
}

static void register_processors (CcnetClient *client)
{
    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-check-tx-v2",
                                           SEAFILE_TYPE_CHECK_TX_V2_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-check-tx-v3",
                                           SEAFILE_TYPE_CHECK_TX_V3_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-sendfs",
                                           SEAFILE_TYPE_SENDFS_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-getfs",
                                           SEAFILE_TYPE_GETFS_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-sendbranch",
                                           SEAFILE_TYPE_SENDBRANCH_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-getcs",
                                           SEAFILE_TYPE_GETCS_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-getcommit-v2",
                                           SEAFILE_TYPE_GETCOMMIT_V2_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-getcommit-v3",
                                           SEAFILE_TYPE_GETCOMMIT_V3_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-sendcommit-v3",
                                           SEAFILE_TYPE_SENDCOMMIT_V3_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-sendcommit-v3-new",
                                           SEAFILE_TYPE_SENDCOMMIT_V3_NEW_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-checkbl",
                                           SEAFILE_TYPE_CHECKBL_PROC);
    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-getcs-v2",
                                           SEAFILE_TYPE_GETCS_V2_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-sendcommit-v4",
                                           SEAFILE_TYPE_SENDCOMMIT_V4_PROC);
    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-sendfs-v2",
                                           SEAFILE_TYPE_SENDFS_V2_PROC);
    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-getfs-v2",
                                           SEAFILE_TYPE_GETFS_V2_PROC);
}

int
seaf_transfer_manager_start (SeafTransferManager *manager)
{
    const char *sql;

    sql = "CREATE TABLE IF NOT EXISTS CloneHeads "
        "(repo_id TEXT PRIMARY KEY, head TEXT);";
    if (sqlite_query_exec (manager->db, sql) < 0)
        return -1;

    register_processors (seaf->session);

    manager->schedule_timer = ccnet_timer_new (schedule_task_pulse, manager,
                                               SCHEDULE_INTERVAL * 1000);

    return 0;
}

/*
 * We don't want to have two tasks for the same repo to run
 * simultaneously.
 */
static gboolean
is_duplicate_task (SeafTransferManager *manager,
                   const char *repo_id)
{
    GHashTableIter iter;
    gpointer key, value;
    TransferTask *task;

    g_hash_table_iter_init (&iter, manager->download_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        if (strcmp(task->repo_id, repo_id) == 0 &&
            task->runtime_state != TASK_RT_STATE_FINISHED)
            return TRUE;
    }

    g_hash_table_iter_init (&iter, manager->upload_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        if (strcmp(task->repo_id, repo_id) == 0 &&
            task->runtime_state != TASK_RT_STATE_FINISHED)
            return TRUE;
    }

    return FALSE;
}

static gboolean
remove_task_help (gpointer key, gpointer value, gpointer user_data)
{
    TransferTask *task = value;
    const char *repo_id = user_data;

    if (strcmp(task->repo_id, repo_id) != 0)
        return FALSE;

    return TRUE;
}

static void
clean_tasks_for_repo (SeafTransferManager *manager,
                      const char *repo_id)
{
    g_hash_table_foreach_remove (manager->download_tasks,
                                 remove_task_help, (gpointer)repo_id);

    g_hash_table_foreach_remove (manager->upload_tasks,
                                 remove_task_help, (gpointer)repo_id);
}

char *
seaf_transfer_manager_add_download (SeafTransferManager *manager,
                                    const char *repo_id,
                                    int repo_version,
                                    const char *peer_id,
                                    const char *from_branch,
                                    const char *to_branch,
                                    const char *token,
                                    gboolean server_side_merge,
                                    const char *passwd,
                                    const char *worktree,
                                    GError **error)
{
    TransferTask *task;

    if (!repo_id || !from_branch || !to_branch || !token) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Empty argument(s)");
        return NULL;
    }

    if (is_duplicate_task (manager, repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Task is already in progress");
        return NULL;
    }
    clean_tasks_for_repo (manager, repo_id);

    task = seaf_transfer_task_new (manager, NULL, repo_id, peer_id,
                                   from_branch, to_branch, token,
                                   TASK_TYPE_DOWNLOAD);
    task->state = TASK_STATE_NORMAL;
    task->repo_version = repo_version;

    task->server_side_merge = server_side_merge;

    /* Mark task "clone" if it's a new repo. */
    if (!seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id))
        task->is_clone = TRUE;

    if (task->is_clone) {
        task->passwd = g_strdup(passwd);
        task->worktree = g_strdup(worktree);
    }

    g_hash_table_insert (manager->download_tasks,
                         g_strdup(task->tx_id),
                         task);

    return g_strdup(task->tx_id);
}

char *
seaf_transfer_manager_add_upload (SeafTransferManager *manager,
                                  const char *repo_id,
                                  int repo_version,
                                  const char *peer_id,
                                  const char *from_branch,
                                  const char *to_branch,
                                  const char *token,
                                  gboolean server_side_merge,
                                  GError **error)
{
    TransferTask *task;
    SeafRepo *repo;

    if (!repo_id || !from_branch || !to_branch || !token) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Empty argument(s)");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Repo not found");
        return NULL;
    }

    if (is_duplicate_task (manager, repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Task is already in progress");
        return NULL;
    }
    clean_tasks_for_repo (manager, repo_id);

    task = seaf_transfer_task_new (manager, NULL, repo_id, peer_id,
                                   from_branch, to_branch, token,
                                   TASK_TYPE_UPLOAD);
    task->state = TASK_STATE_NORMAL;
    task->repo_version = repo_version;
    task->server_side_merge = server_side_merge;

    g_hash_table_insert (manager->upload_tasks,
                         g_strdup(task->tx_id),
                         task);

    return g_strdup(task->tx_id);
}

/* find running tranfer of a repo */
TransferTask*
seaf_transfer_manager_find_transfer_by_repo (SeafTransferManager *manager,
                                             const char *repo_id)
{
    GHashTableIter iter;
    gpointer key, value;
    TransferTask *task;

    g_hash_table_iter_init (&iter, manager->download_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        if (strcmp(task->repo_id, repo_id) == 0 &&
            task->state != TASK_STATE_FINISHED)
            return task;
    }

    g_hash_table_iter_init (&iter, manager->upload_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        if (strcmp(task->repo_id, repo_id) == 0 &&
            task->state != TASK_STATE_FINISHED)
            return task;
    }

    return NULL;
}


static void
remove_task(SeafTransferManager *manager, TransferTask *task)
{
    if (task->type == TASK_TYPE_DOWNLOAD) {
        g_hash_table_remove (manager->download_tasks, task->tx_id);
    } else {
        g_hash_table_remove (manager->upload_tasks, task->tx_id);
    }
}

void
seaf_transfer_manager_remove_task (SeafTransferManager *manager,
                                    const char *tx_id,
                                    int task_type)
{
    TransferTask *task = NULL;

    if (task_type == TASK_TYPE_DOWNLOAD)
        task = g_hash_table_lookup (manager->download_tasks, tx_id);
    else
        task = g_hash_table_lookup (manager->upload_tasks, tx_id);

    if (!task)
        return;

    if (task->runtime_state != TASK_RT_STATE_FINISHED) {
        seaf_warning ("[tr-mgr] Try to remove running task!\n");
        return;
    }

    remove_task (manager, task);
}

static void
cancel_task (TransferTask *task)
{
    if (task->runtime_state == TASK_RT_STATE_NETDOWN ||
        task->runtime_state == TASK_RT_STATE_INIT) {
        transition_state (task, TASK_STATE_CANCELED, TASK_RT_STATE_FINISHED);
    } else {
        /*
         * Only transition state, not runtime state.
         * Runtime state transition is handled asynchronously.
         */
        if (task->protocol_version >= 4 &&
            task->runtime_state == TASK_RT_STATE_DATA)
            block_tx_client_run_command (task->tx_info, BLOCK_CLIENT_CMD_CANCEL);
        transition_state (task, TASK_STATE_CANCELED, task->runtime_state);
    }
}

void
seaf_transfer_manager_cancel_task (SeafTransferManager *manager,
                                   const char *tx_id,
                                   int task_type)
{
    TransferTask *task = NULL;

    if (task_type == TASK_TYPE_DOWNLOAD)
        task = g_hash_table_lookup (manager->download_tasks, tx_id);
    else
        task = g_hash_table_lookup (manager->upload_tasks, tx_id);

    if (!task)
        return;

    if (task->state != TASK_STATE_NORMAL) {
        seaf_warning ("Task cannot be canceled!\n");
        return;
    }

    cancel_task (task);
}


GList*
seaf_transfer_manager_get_upload_tasks (SeafTransferManager *manager)
{
    return g_hash_table_get_values (manager->upload_tasks);
}

GList*
seaf_transfer_manager_get_download_tasks (SeafTransferManager *manager)
{
    return g_hash_table_get_values (manager->download_tasks);
}

int
seaf_transfer_manager_download_file_blocks (SeafTransferManager *manager,
                                            TransferTask *task,
                                            const char *file_id)
{
    Seafile *file;

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                        task->repo_id,
                                        task->repo_version,
                                        file_id);
    if (!file) {
        seaf_warning ("Failed to find seafile object %s in repo %.8s.\n",
                      file_id, task->repo_id);
        return -1;
    }

    int i;
    char *block_id;
    for (i = 0; i < file->n_blocks; ++i) {
        block_id = file->blk_sha1s[i];
        if (!seaf_block_manager_block_exists (seaf->block_mgr,
                                              task->repo_id,
                                              task->repo_version,
                                              block_id))
            g_queue_push_tail (task->block_ids, g_strdup(block_id));
    }

    seafile_unref (file);

    BlockTxInfo *info = task->tx_info;
    int rsp;

retry:
    if (g_queue_get_length (task->block_ids) == 0)
        return BLOCK_CLIENT_SUCCESS;

    block_tx_client_run_command (info, BLOCK_CLIENT_CMD_TRANSFER);

    /* Wait until block download is done. */
    piperead (info->done_pipe[0], &rsp, sizeof(rsp));

    /* The server closes the socket after 30 seconds without data,
     * so just retry if we encounter network error.
     */
    if (rsp == BLOCK_CLIENT_NET_ERROR) {
        block_tx_client_run_command (info, BLOCK_CLIENT_CMD_RESTART);

        piperead (info->done_pipe[0], &rsp, sizeof(rsp));
        if (rsp == BLOCK_CLIENT_READY)
            goto retry;
    }

    while ((block_id = g_queue_pop_head(task->block_ids)) != NULL)
        g_free (block_id);

    return rsp;
}

/* Utility functions. */

static BlockList *
load_blocklist_with_local_history (TransferTask *task)
{
    BlockList *bl1, *bl2, *bl = NULL;
    int i;
    ObjectList *commits = task->commits;
    char *commit_id;
    SeafCommit *commit;
    GList *parents = NULL;

    /* Upload the blocks pointed by new commits, excluding
     * blocks that have been uploaded before.
     */

    bl1 = block_list_new ();

    for (i = 0; i < commits->obj_ids->len; ++i) {
        commit_id = g_ptr_array_index (commits->obj_ids, i);
        commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id,
                                                 task->repo_version,
                                                 commit_id);
        if (!commit) {
            seaf_warning ("Failed to get commit %s.\n", commit_id);
            block_list_free (bl1);
            return NULL;
        }

        if (seaf_fs_manager_populate_blocklist (seaf->fs_mgr,
                                                task->repo_id,
                                                task->repo_version,
                                                commit->root_id,
                                                bl1) < 0) {
            seaf_commit_unref (commit);
            block_list_free (bl1);
            return NULL;
        }

        if (commit->parent_id && !object_list_exists (commits, commit->parent_id))
            parents = g_list_prepend (parents, g_strdup(commit->parent_id));

        if (commit->second_parent_id &&
            !object_list_exists (commits, commit->second_parent_id))
            parents = g_list_prepend (parents, g_strdup(commit->second_parent_id));

        seaf_commit_unref (commit);
    }

    GList *p;
    char *parent_id;
    SeafCommit *parent;

    for (p = parents; p; p = p->next) {
        parent_id = p->data;
        parent = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id,
                                                 task->repo_version,
                                                 parent_id);
        if (!parent) {
            block_list_free (bl1);
            return NULL;
        }

        bl2 = block_list_new ();
        if (seaf_fs_manager_populate_blocklist (seaf->fs_mgr,
                                                task->repo_id,
                                                task->repo_version,
                                                parent->root_id, bl2) < 0) {
            seaf_commit_unref (parent);
            block_list_free (bl1);
            block_list_free (bl2);
            return NULL;
        }

        bl = block_list_difference (bl1, bl2);
        block_list_free (bl1);
        bl1 = bl;

        seaf_commit_unref (parent);
        block_list_free (bl2);
    }

    seaf_debug ("Uploading %u blocks.\n", bl1->n_blocks);

    return bl1;
}

static int
seaf_transfer_task_load_blocklist (TransferTask *task)
{
    SeafRepo *repo;
    BlockList *bl;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, task->repo_id);
    if (!repo && !task->is_clone)
        return -1;

    if (task->type == TASK_TYPE_UPLOAD) {
        bl = load_blocklist_with_local_history (task);
        if (!bl) {
            seaf_warning ("[tr-mgr]Failed to populate blocklist.\n");
            return -1;
        }
    } else {
        SeafCommit *remote;

        remote = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id,
                                                 task->repo_version,
                                                 task->head);
        if (!remote) {
            seaf_warning ("[tr-mgr] Failed to find commit %s.\n", task->head);
            return -1;
        }

        if (!task->is_clone) {
            /* If we're merging, only get new blocks that need to be checked out.
             */
            if (merge_get_new_block_list (repo, remote, &bl) < 0) {
                seaf_warning ("[tr-mgr] Failed to get new blocks for merge.\n");
                seaf_commit_unref (remote);
                return -1;
            }
        } else {
            /* If we're cloning, only get blocks pointed by the lastest commit.
             */
            bl = block_list_new ();
            if (seaf_fs_manager_populate_blocklist (seaf->fs_mgr,
                                                    task->repo_id,
                                                    task->repo_version,
                                                    remote->root_id,
                                                    bl) < 0) {
                seaf_warning ("[tr-mgr] Failed to get blocks of commit %s.\n",
                           remote->commit_id);
                seaf_commit_unref (remote);
                return -1;
            }
        }
        seaf_commit_unref (remote);

        g_return_val_if_fail (bl != NULL, -1);
    }

    task->block_list = bl;

    return 0;
}

typedef struct DiffTreesData {
    BlockList *bl;
    TransferTask *task;
} DiffTreesData;

static int
diff_files (int n, const char *basedir, SeafDirent *files[], void *vdata)
{
    SeafDirent *file1 = files[0];
    SeafDirent *file2 = files[1];
    DiffTreesData *data = vdata;
    BlockList *bl = data->bl;
    TransferTask *task = data->task;
    Seafile *f1 = NULL, *f2 = NULL;
    int i;

    if (file1 && strcmp (file1->id, EMPTY_SHA1) != 0) {
        if (!file2) {
            f1 = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                              task->repo_id, task->repo_version,
                                              file1->id);
            if (!f1) {
                seaf_warning ("Failed to get seafile object %s.\n", file1->id);
                return -1;
            }
            for (i = 0; i < f1->n_blocks; ++i)
                block_list_insert (bl, f1->blk_sha1s[i]);
            seafile_unref (f1);
        } else if (strcmp (file1->id, file2->id) != 0) {
            f1 = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                              task->repo_id, task->repo_version,
                                              file1->id);
            if (!f1) {
                seaf_warning ("Failed to get seafile object %s.\n", file1->id);
                return -1;
            }
            f2 = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                              task->repo_id, task->repo_version,
                                              file2->id);
            if (!f2) {
                seafile_unref (f1);
                seaf_warning ("Failed to get seafile object %s.\n", file2->id);
                return -1;
            }

            GHashTable *h = g_hash_table_new (g_str_hash, g_str_equal);
            int dummy;
            for (i = 0; i < f2->n_blocks; ++i)
                g_hash_table_insert (h, f2->blk_sha1s[i], &dummy);

            for (i = 0; i < f1->n_blocks; ++i)
                if (!g_hash_table_lookup (h, f1->blk_sha1s[i]))
                    block_list_insert (bl, f1->blk_sha1s[i]);

            seafile_unref (f1);
            seafile_unref (f2);
            g_hash_table_destroy (h);
        }
    }

    return 0;
}

static int
diff_dirs (int n, const char *basedir, SeafDirent *dirs[], void *data,
           gboolean *recurse)
{
    /* Do nothing */
    return 0;
}

static int
load_blocklist_v2 (TransferTask *task)
{
    int ret = 0;

    SeafBranch *local = NULL, *master = NULL;
    local = seaf_branch_manager_get_branch (seaf->branch_mgr, task->repo_id, "local");
    if (!local) {
        seaf_warning ("Branch local not found for repo %.8s.\n", task->repo_id);
        ret = -1;
        goto out;
    }
    master = seaf_branch_manager_get_branch (seaf->branch_mgr, task->repo_id, "master");
    if (!master) {
        seaf_warning ("Branch master not found for repo %.8s.\n", task->repo_id);
        ret = -1;
        goto out;
    }

    SeafCommit *local_head = NULL, *master_head = NULL;
    local_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id, task->repo_version,
                                                 local->commit_id);
    if (!local_head) {
        seaf_warning ("Local head commit not found for repo %.8s.\n",
                      task->repo_id);
        ret = -1;
        goto out;
    }
    master_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id, task->repo_version,
                                                 master->commit_id);
    if (!master_head) {
        seaf_warning ("Master head commit not found for repo %.8s.\n",
                      task->repo_id);
        ret = -1;
        goto out;
    }

    BlockList *bl = block_list_new ();
    DiffTreesData data;
    data.bl = bl;
    data.task = task;

    DiffOptions opts;
    memset (&opts, 0, sizeof(opts));
    memcpy (opts.store_id, task->repo_id, 36);
    opts.version = task->repo_version;
    opts.file_cb = diff_files;
    opts.dir_cb = diff_dirs;
    opts.data = &data;

    const char *trees[2];
    trees[0] = local_head->root_id;
    trees[1] = master_head->root_id;
    if (diff_trees (2, trees, &opts) < 0) {
        seaf_warning ("Failed to diff local and master head for repo %.8s.\n",
                      task->repo_id);
        ret = -1;
        goto out;
    }

    task->block_list = bl;

out:
    seaf_branch_unref (local);
    seaf_branch_unref (master);
    seaf_commit_unref (local_head);
    seaf_commit_unref (master_head);
    return ret;
}

/*
 * Loading block list may take a lot of disk I/O, so do it in a thread.
 */

typedef void (*LoadBLCB) (TransferTask *); 

typedef struct LoadBLData {
    TransferTask *task;
    gboolean success;
    LoadBLCB callback;
} LoadBLData;

static void
load_block_list_done (void *vdata)
{
    LoadBLData *data = vdata;
    TransferTask *task = data->task;

    if (task->state == TASK_STATE_CANCELED) {
        transition_state (task, task->state, TASK_RT_STATE_FINISHED);
        g_free (data);
        return;
    }

    if (data->success)
        data->callback (task);
    else
        transition_state_to_error (task, TASK_ERR_LOAD_BLOCK_LIST);

    g_free (data);
}

static void *
load_block_list_thread (void *vdata)
{
    LoadBLData *data = vdata;
    int ret = 0;

    if (data->task->protocol_version >= 7 &&
        data->task->type == TASK_TYPE_UPLOAD)
        ret = load_blocklist_v2 (data->task);
    else
        ret = seaf_transfer_task_load_blocklist (data->task);

    if (ret < 0)
        data->success = FALSE;
    else
        data->success = TRUE;

    return data;
}

static int
start_load_block_list_thread (TransferTask *task, LoadBLCB callback)
{
    LoadBLData *data = g_new0 (LoadBLData, 1);
    data->task = task;
    data->callback = callback;

    return ccnet_job_manager_schedule_job (seaf->job_mgr,
                                           load_block_list_thread,
                                           load_block_list_done,
                                           data);
}

static gboolean
fs_root_collector (SeafCommit *commit, void *data, gboolean *stop)
{
    ObjectList *ol = data;

    if (strcmp(commit->root_id, EMPTY_SHA1) != 0)
        object_list_insert (ol, commit->root_id);

    return TRUE;
}

static int
generate_session_key (BlockTxInfo *info, const char *peer_id)
{
    char *sk_base64, *sk_enc_base64;
    gsize enc_key_len;

    if (RAND_bytes (info->session_key, sizeof(info->session_key)) != 1) {
        seaf_warning ("Failed to generate random session key with RAND_bytes(), "
                      "switch to RAND_pseudo_bytes().\n");
        RAND_pseudo_bytes (info->session_key, sizeof(info->session_key));
    }

    sk_base64 = g_base64_encode (info->session_key, sizeof(info->session_key));
    sk_enc_base64 = ccnet_pubkey_encrypt (seaf->ccnetrpc_client,
                                          sk_base64, peer_id);
    info->enc_session_key = g_base64_decode (sk_enc_base64, &enc_key_len);
    info->enc_key_len = (int)enc_key_len;

    g_free (sk_base64);
    g_free (sk_enc_base64);
    return 0;
}

static int
update_remote_branch (TransferTask *task);

static int
update_local_repo (TransferTask *task);

static void
block_tx_client_once_mode_done_cb (BlockTxInfo *info)
{
    switch (info->result) {
    case BLOCK_CLIENT_SUCCESS:
        if (info->task->type == TASK_TYPE_UPLOAD)
            update_remote_branch (info->task);
        else {
            if (update_local_repo (info->task) == 0)
                transition_state (info->task, TASK_STATE_FINISHED,
                                  TASK_RT_STATE_FINISHED);
        }
        break;
    case BLOCK_CLIENT_FAILED:
    case BLOCK_CLIENT_UNKNOWN:
        if (info->task->type == TASK_TYPE_UPLOAD)
            transition_state_to_error (info->task, TASK_ERR_UPLOAD_BLOCKS);
        else
            transition_state_to_error (info->task, TASK_ERR_DOWNLOAD_BLOCKS);
        break;
    case BLOCK_CLIENT_CANCELED:
        transition_state (info->task, TASK_STATE_CANCELED, TASK_RT_STATE_FINISHED);
        break;
    case BLOCK_CLIENT_NET_ERROR:
    case BLOCK_CLIENT_SERVER_ERROR:
        if (info->task->type == TASK_TYPE_UPLOAD)
            transition_state_to_error (info->task, TASK_ERR_UPLOAD_BLOCKS);
        else
            transition_state_to_error (info->task, TASK_ERR_DOWNLOAD_BLOCKS);
        break;
    }

    g_free (info->enc_session_key);
    pipeclose (info->cmd_pipe[0]);
    pipeclose (info->cmd_pipe[1]);
    g_free (info);
}

static void
start_block_tx_client_run_once (TransferTask *task)
{
    BlockTxInfo *info;

    info = g_new0 (BlockTxInfo, 1);

    info->task = task;
    /* Only use the first chunk server. */
    info->cs = task->chunk_servers->data;

    if (generate_session_key (info, task->dest_id) < 0) {
        transition_state_to_error (task, TASK_ERR_START_BLOCK_CLIENT);
        return;
    }

    if (ccnet_pipe (info->cmd_pipe) < 0) {
        seaf_warning ("Failed to create command pipe: %s.\n", strerror(errno));
        transition_state_to_error (task, TASK_ERR_START_BLOCK_CLIENT);
        return;
    }

    /* For old syncing protocol, set block-tx-client to run-once mode. */
    info->transfer_once = TRUE;

    task->tx_info = info;

    if (block_tx_client_start (info, block_tx_client_once_mode_done_cb) < 0) {
        seaf_warning ("Failed to start block tx client.\n");
        transition_state_to_error (task, TASK_ERR_START_BLOCK_CLIENT);
        return;
    }

    transition_state (task, task->state, TASK_RT_STATE_DATA);
}

static void
block_tx_client_interactive_done_cb (BlockTxInfo *info)
{

}

static void
start_block_tx_client_interactive (TransferTask *task)
{
    BlockTxInfo *info;

    info = g_new0 (BlockTxInfo, 1);

    info->task = task;
    /* Only use the first chunk server. */
    info->cs = task->chunk_servers->data;

    task->block_ids = g_queue_new();

    if (generate_session_key (info, task->dest_id) < 0) {
        transition_state_to_error (task, TASK_ERR_START_BLOCK_CLIENT);
        return;
    }

    if (ccnet_pipe (info->cmd_pipe) < 0) {
        seaf_warning ("Failed to create command pipe: %s.\n", strerror(errno));
        transition_state_to_error (task, TASK_ERR_START_BLOCK_CLIENT);
        return;
    }

    if (ccnet_pipe (info->done_pipe) < 0) {
        seaf_warning ("Failed to create done pipe: %s.\n", strerror(errno));
        transition_state_to_error (task, TASK_ERR_START_BLOCK_CLIENT);
        return;
    }

    task->tx_info = info;

    if (block_tx_client_start (info, block_tx_client_interactive_done_cb) < 0) {
        seaf_warning ("Failed to start block tx client.\n");
        transition_state_to_error (task, TASK_ERR_START_BLOCK_CLIENT);
        return;
    }

    transition_state (task, task->state, TASK_RT_STATE_DATA);
}

typedef struct DownloadFilesData {
    TransferTask *task;
    int status;
} DownloadFilesData;

static void *
download_and_checkout_files_thread (void *vdata)
{
    DownloadFilesData *data = vdata;
    TransferTask *task = data->task;
    int rsp;

    piperead (task->tx_info->done_pipe[0], &rsp, sizeof(rsp));

    if (rsp == BLOCK_CLIENT_READY) {
        data->status = seaf_repo_fetch_and_checkout (task, NULL, FALSE, task->head);

        block_tx_client_run_command (task->tx_info, BLOCK_CLIENT_CMD_END);

        piperead (task->tx_info->done_pipe[0], &rsp, sizeof(rsp));
    } else
        /* block-tx-client thread should have exited. */
        data->status = FETCH_CHECKOUT_FAILED;

    return vdata;
}

static void
download_and_checkout_files_done (void *vdata)
{
    DownloadFilesData *data = vdata;
    TransferTask *task = data->task;
    BlockTxInfo *info = task->tx_info;

    g_free (info->enc_session_key);
    pipeclose (info->cmd_pipe[0]);
    pipeclose (info->cmd_pipe[1]);
    pipeclose (info->done_pipe[0]);
    pipeclose (info->done_pipe[1]);
    g_queue_free (info->task->block_ids);
    g_free (info);

    switch (data->status) {
    case FETCH_CHECKOUT_SUCCESS:
        if (update_local_repo (task) == 0)
            transition_state (task, TASK_STATE_FINISHED, TASK_RT_STATE_FINISHED);
        break;
    case FETCH_CHECKOUT_FAILED:
    case FETCH_CHECKOUT_TRANSFER_ERROR:
        transition_state_to_error (task, TASK_ERR_DOWNLOAD_BLOCKS);
        break;
    case FETCH_CHECKOUT_CANCELED:
        transition_state (task, TASK_STATE_CANCELED, TASK_RT_STATE_FINISHED);
        break;
    case FETCH_CHECKOUT_LOCKED:
        transition_state_to_error (task, TASK_ERR_FILES_LOCKED);
        break;
    }

    g_free (vdata);
}

static void
on_getcs_v2_done (CcnetProcessor *processor, gboolean success, void *data)
{
    TransferTask *task = data;

    /* if the user stopped or canceled this task, stop processing. */
    /* state #6, #10 */
    if (task->state == TASK_STATE_CANCELED) {
        transition_state (task, task->state, TASK_RT_STATE_FINISHED);
        goto out;
    }

    if (success) {
        if (task->type == TASK_TYPE_DOWNLOAD && task->protocol_version >= 7) {
            /* Record download head commit id, so that we can resume download
             * if this download is interrupted.
             */
            seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                                 task->repo_id,
                                                 REPO_PROP_DOWNLOAD_HEAD,
                                                 task->head);

            start_block_tx_client_interactive (task);

            DownloadFilesData *data = g_new0 (DownloadFilesData, 1);
            data->task = task;

            /* This thread uses block-tx-client thread to download blocks. */
            ccnet_job_manager_schedule_job (seaf->job_mgr,
                                            download_and_checkout_files_thread,
                                            download_and_checkout_files_done,
                                            data);
        } else 
            start_block_tx_client_run_once (task);
    } else if (task->state != TASK_STATE_ERROR) {
        transfer_task_with_proc_failure (
            task, processor, TASK_ERR_GET_CHUNK_SERVER);
    }

out:
    g_signal_handlers_disconnect_by_func (processor, on_getcs_v2_done, data);
}

static void
get_chunk_server_address (TransferTask *task)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor (
                seaf->session->proc_factory, "seafile-getcs-v2", task->dest_id);
    ((SeafileGetcsV2Proc *)processor)->task = task;
    g_signal_connect (processor, "done", (GCallback)on_getcs_v2_done, task);

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("failed to start getcs-v2 proc.\n");
        transition_state_to_error (task, TASK_ERR_GET_CHUNK_SERVER);
    }

    transition_state (task, task->state, TASK_RT_STATE_CHUNK_SERVER);
}

/* -------- download -------- */

static int
start_getcommit_proc (TransferTask *task, const char *peer_id, GCallback done_cb)
{
    CcnetProcessor *processor;

    if (task->protocol_version <= 5)
        processor = ccnet_proc_factory_create_remote_master_processor (
                    seaf->session->proc_factory, "seafile-getcommit-v2", peer_id);
    else
        processor = ccnet_proc_factory_create_remote_master_processor (
                    seaf->session->proc_factory, "seafile-getcommit-v3", peer_id);
    if (!processor) {
        seaf_warning ("failed to create getcommit proc.\n");
        return -1;
    }

    if (task->protocol_version <= 5)
        ((SeafileGetcommitV2Proc *)processor)->tx_task = task;
    else
        ((SeafileGetcommitV3Proc *)processor)->tx_task = task;
    g_signal_connect (processor, "done", done_cb, task);

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("failed to start getcommit proc.\n");
        return -1;
    }

    return 0;
}


static int
start_getfs_proc (TransferTask *task, const char *peer_id, GCallback done_cb)
{
    CcnetProcessor *processor;

    if (task->protocol_version <= 6)
        processor = ccnet_proc_factory_create_remote_master_processor (
            seaf->session->proc_factory, "seafile-getfs", peer_id);
    else
        processor = ccnet_proc_factory_create_remote_master_processor (
            seaf->session->proc_factory, "seafile-getfs-v2", peer_id);
    if (!processor) {
        seaf_warning ("failed to create getfs proc.\n");
        return -1;
    }

    ((SeafileGetfsProc *)processor)->tx_task = task;
    g_signal_connect (processor, "done", done_cb, task);

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("failed to start getfs proc.\n");
        return -1;
    }

    return 0;
}

static void
check_block_ids_for_download (TransferTask *task)
{
    int i;
    BlockList *bl = task->block_list;
    char *block_id;

    task->block_ids = g_queue_new ();

    /* Add all blocks we don't have into task->block_ids. */
    for (i = 0; i < bl->n_blocks; ++i) {
        block_id = g_ptr_array_index (bl->block_ids, i);
        if (!seaf_block_manager_block_exists (seaf->block_mgr,
                                              task->repo_id, task->repo_version,
                                              block_id))
            g_queue_push_tail (task->block_ids, g_strdup(block_id));
        else
            ++bl->n_valid_blocks;
    }
}

static void
start_block_download (TransferTask *task)
{
    check_block_ids_for_download (task);

    if (task->block_list->n_blocks == task->block_list->n_valid_blocks) {
        seaf_debug ("No block to download.\n");
        if (update_local_repo (task) == 0)
            transition_state (task, TASK_STATE_FINISHED, TASK_RT_STATE_FINISHED);
    } else {
        get_chunk_server_address (task);
    }
}

static void
on_fs_downloaded (CcnetProcessor *processor, gboolean success, void *data)
{
    TransferTask *task = data;

    /* if the user stopped or canceled this task, stop processing. */
    /* state #6, #10 */
    if (task->state == TASK_STATE_CANCELED) {
        transition_state (task, task->state, TASK_RT_STATE_FINISHED);
        goto out;
    }

    if (success) {
        if (task->protocol_version <= 6)
            start_load_block_list_thread (task, start_block_download);
        else
            get_chunk_server_address (task);
    } else if (task->state != TASK_STATE_ERROR
               && task->runtime_state == TASK_RT_STATE_FS) {
        transfer_task_with_proc_failure (
            task, processor, TASK_ERR_DOWNLOAD_FS);
    }

out:
    g_signal_handlers_disconnect_by_func (processor, on_fs_downloaded, data);
}

static void
start_fs_download (TransferTask *task, const char *peer_id)
{
    int ret;
    ObjectList *ol;

    if (task->protocol_version == 1) {
        ol = object_list_new ();
        ret = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                        task->repo_id,
                                                        task->repo_version,
                                                        task->head,
                                                        fs_root_collector,
                                                        ol, FALSE);
        if (ret == FALSE) {
            object_list_free (ol);
            transition_state_to_error (task, TASK_ERR_LOAD_FS);
            return;
        }
        task->fs_roots = ol;
    }

    if (task->protocol_version <= 6 &&
        object_list_length(task->fs_roots) == 0) {
        if (update_local_repo (task) == 0)
            transition_state (task, TASK_STATE_FINISHED, TASK_RT_STATE_FINISHED);
        return;
    }

    if (start_getfs_proc (task, peer_id, (GCallback)on_fs_downloaded) < 0)
        transition_state_to_error (task, TASK_ERR_DOWNLOAD_FS_START);
    else
        transition_state (task, task->state, TASK_RT_STATE_FS);
}

static int start_download (TransferTask *task);
static int start_commit_download (TransferTask *task);

static void
on_commit_downloaded (CcnetProcessor *processor, gboolean success, void *data)
{
    TransferTask *task = data;

    /* if the user stopped or canceled this task, stop processing. */
    /* state #5, #9 */
    if (task->state == TASK_STATE_CANCELED) {
        transition_state (task, task->state, TASK_RT_STATE_FINISHED);
        goto out;
    }

    if (success) {
        start_fs_download (task, processor->peer_id);
    } else if (task->state != TASK_STATE_ERROR
               && task->runtime_state == TASK_RT_STATE_COMMIT) {
        /* The task state will be transfered to error                  */
        /* if a error occurred in getcommit-proc, otherwise, it means  */
        /* the processor is shutdown and the reason is recorded in     */
        /* processor->failure.     */
        transfer_task_with_proc_failure (
            task, processor, TASK_ERR_DOWNLOAD_COMMIT);
    }

out:
    g_signal_handlers_disconnect_by_func (processor, on_commit_downloaded, data);
}

static int
start_commit_download (TransferTask *task)
{
    const char *dest_id = task->dest_id;

    task->rsize = -1;
    task->dsize = 0;

    /* Also get the head id of the destination branch and store at task->head. */
    if (start_getcommit_proc (task, dest_id, (GCallback)on_commit_downloaded) < 0) {
        transition_state_to_error (task, TASK_ERR_DOWNLOAD_COMMIT_START);
        return -1;
    }
    transition_state (task, task->state, TASK_RT_STATE_COMMIT);

    return 0;
}

static void
check_download_cb (CcnetProcessor *processor, gboolean success, void *data)
{
    TransferTask *task = data;

    /* if the user stopped or canceled this task, stop processing. */
    /* state #5, #9 */
    if (task->state == TASK_STATE_CANCELED) {
        transition_state (task, task->state, TASK_RT_STATE_FINISHED);
        goto out;
    }

    if (success) {
        start_commit_download (task);
    } else if (task->state != TASK_STATE_ERROR
               && task->runtime_state == TASK_RT_STATE_CHECK) {
        transfer_task_with_proc_failure (
            task, processor, TASK_ERR_UNKNOWN);
    }

    /* Errors have been processed in the processor. */

out:
    g_signal_handlers_disconnect_by_func (processor, check_download_cb, data);
}

static int
start_download (TransferTask *task)
{
    const char *dest_id = task->dest_id;
    CcnetProcessor *processor;

    if (!dest_id)
        return -1;

    if (!ccnet_peer_is_ready (seaf->ccnetrpc_client, dest_id))
        return -1;

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-check-tx-v3", dest_id);
    if (!processor) {
        seaf_warning ("failed to create check-tx proc for download.\n");
        transition_state_to_error (task, TASK_ERR_CHECK_DOWNLOAD_START);
        return -1;
    }

    g_signal_connect (processor, "done", (GCallback)check_download_cb, task);

    ((SeafileCheckTxV3Proc *)processor)->task = task;
    if (ccnet_processor_startl (processor, "download", NULL) < 0) {
        seaf_warning ("failed to start check-tx proc for download.\n");
        return -1;
    }

    transition_state (task, task->state, TASK_RT_STATE_CHECK);
    return 0;
}

static int
update_local_repo (TransferTask *task)
{
    SeafRepo *repo;
    SeafCommit *new_head;
    SeafBranch *branch;
    int ret = 0;

    new_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                               task->repo_id,
                                               task->repo_version,
                                               task->head);
    if (!new_head) {
        seaf_warning ("Failed to get commit %s.\n", task->head);
        transition_state_to_error (task, TASK_ERR_UNKNOWN);
        return -1;
    }

    /* If repo doesn't exist, create it.
     * Note that branch doesn't exist either in this case.
     */
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, new_head->repo_id);
    if (task->is_clone) {
        if (repo != NULL)
            goto out;

        repo = seaf_repo_new (new_head->repo_id, NULL, NULL);
        if (repo == NULL) {
            /* create repo failed */
            transition_state_to_error (task, TASK_ERR_UNKNOWN);
            ret = -1;
            goto out;
        }

        seaf_repo_from_commit (repo, new_head);

        seaf_repo_manager_add_repo (seaf->repo_mgr, repo);

        /* If it's a new repo, create 'local' and 'master' branch */
        branch = seaf_branch_new ("local", task->repo_id, task->head);
        seaf_branch_manager_add_branch (seaf->branch_mgr, branch);
        seaf_branch_unref (branch);

        branch = seaf_branch_new ("master", task->repo_id, task->head);
        seaf_branch_manager_add_branch (seaf->branch_mgr, branch);
        seaf_branch_unref (branch);
    } else {
        if (!repo) {
            transition_state_to_error (task, TASK_ERR_UNKNOWN);
            ret = -1;
            goto out;
        }

        branch = seaf_branch_manager_get_branch (seaf->branch_mgr, 
                                                 task->repo_id,
                                                 "master");
        if (!branch) {
            seaf_warning ("Branch master not found for repo %.8s.\n", task->repo_id);
            transition_state_to_error (task, TASK_ERR_UNKNOWN);
            ret = -1;
            goto out;
        }
        seaf_branch_set_commit (branch, new_head->commit_id);
        seaf_branch_manager_update_branch (seaf->branch_mgr, branch);
        seaf_branch_unref (branch);

        /* Update repo head branch. */
        if (task->protocol_version >= 7) {
            seaf_branch_set_commit (repo->head, new_head->commit_id);
            seaf_branch_manager_update_branch (seaf->branch_mgr, repo->head);
        }
    }

out:
    seaf_commit_unref (new_head);
    return ret;
}


static void
schedule_download_task (TransferTask *task)
{
    /* This can happen when:
     * 1. A repo was deleted, but we're also syncing that repo;
     * 2. So we just mark the repo as deleted.
     * 3. Before the repo is actually deleted, the user clones
     *    the same repo.
     */
    SyncInfo *s_info = seaf_sync_manager_get_sync_info (seaf->sync_mgr,
                                                        task->repo_id);
    if (task->is_clone && s_info != NULL && s_info->in_sync)
        return;

    switch (task->runtime_state) {
    case TASK_RT_STATE_INIT:
        start_download (task);
        break;
    case TASK_RT_STATE_DATA:
        break;
    default:
        break;
    }
}

/* -------- upload -------- */

static int
start_sendfs_proc (TransferTask *task, const char *peer_id, GCallback done_cb)
{
    CcnetProcessor *processor;

    if (task->protocol_version <= 6)
        processor = ccnet_proc_factory_create_remote_master_processor (
            seaf->session->proc_factory, "seafile-sendfs", peer_id);
    else
        processor = ccnet_proc_factory_create_remote_master_processor (
            seaf->session->proc_factory, "seafile-sendfs-v2", peer_id);
    if (!processor) {
        seaf_warning ("failed to create sendfs proc.\n");
        return -1;
    }

    ((SeafileSendfsProc *)processor)->tx_task = task;
    g_signal_connect (processor, "done", done_cb, task);

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("failed to start sendfs proc.\n");
        return -1;
    }

    return 0;
}

static int
start_sendcommit_proc (TransferTask *task, const char *peer_id, GCallback done_cb)
{
    CcnetProcessor *processor;

    if (task->protocol_version <= 5)
        processor = ccnet_proc_factory_create_remote_master_processor (
                    seaf->session->proc_factory, "seafile-sendcommit-v3", peer_id);
    else if (task->protocol_version == 6)
        processor = ccnet_proc_factory_create_remote_master_processor (
                    seaf->session->proc_factory, "seafile-sendcommit-v3-new", peer_id);
    else
        processor = ccnet_proc_factory_create_remote_master_processor (
                    seaf->session->proc_factory, "seafile-sendcommit-v4", peer_id);
    if (!processor) {
        seaf_warning ("failed to create sendcommit proc.\n");
        return -1;
    }

    ((SeafileSendcommitV3Proc *)processor)->tx_task = task;
    g_signal_connect (processor, "done", done_cb, task);

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("failed to start sendcommit proc.\n");
        return -1;
    }

    return 0;
}

static void
update_branch_cb (CcnetProcessor *processor, gboolean success, void *data)
{
    TransferTask *task = data;

    if (success) {
        transition_state (task, TASK_STATE_FINISHED, TASK_RT_STATE_FINISHED);

        /* update local master branch in our usage model */
        if (strcmp(task->from_branch, "local") == 0 &&
            strcmp(task->to_branch, "master") == 0)
        {
            SeafBranch *branch;
            branch = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                     task->repo_id,
                                                     "master");
            if (!branch) {
                branch = seaf_branch_new ("master", task->repo_id, task->head);
                seaf_branch_manager_add_branch (seaf->branch_mgr, branch);
                seaf_branch_unref (branch);
            } else {
                seaf_branch_set_commit (branch, task->head);
                seaf_branch_manager_update_branch (seaf->branch_mgr, branch);
                seaf_branch_unref (branch);
            }
        }
    } else if (task->state != TASK_STATE_ERROR
               && task->runtime_state == TASK_RT_STATE_UPDATE_BRANCH) {
        transfer_task_with_proc_failure (
            task, processor, TASK_ERR_UNKNOWN);
    }
    /* Errors have been processed in the processor. */
}

static int
update_remote_branch (TransferTask *task)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-sendbranch", task->dest_id);
    if (!processor) {
        seaf_warning ("failed to create sendbranch proc.\n");
        goto fail;
    }

    g_signal_connect (processor, "done", (GCallback)update_branch_cb, task);

    ((SeafileSendbranchProc *)processor)->task = task;
    if (ccnet_processor_startl (processor, task->repo_id, 
                                task->to_branch, task->head, NULL) < 0)
    {
        seaf_warning ("failed to start sendbranch proc.\n");
        goto fail;
    }

    transition_state (task, task->state, TASK_RT_STATE_UPDATE_BRANCH);
    return 0;

fail:
    transition_state_to_error (task, TASK_ERR_START_UPDATE_BRANCH);
    return -1;
}


static void
on_checkbl_done (CcnetProcessor *processor, gboolean success, void *data)
{
    TransferTask *task = data;

    /* if the user stopped or canceled this task, stop processing. */
    /* state #6, #10 */
    if (task->state == TASK_STATE_CANCELED) {
        transition_state (task, task->state, TASK_RT_STATE_FINISHED);
        goto out;
    }

    if (success) {
        if (g_queue_get_length (task->block_ids) == 0) {
            seaf_debug ("All blocks are on server already.\n");
            update_remote_branch (task);
            goto out;
        }

        get_chunk_server_address (task);
    } else if (task->state != TASK_STATE_ERROR) {
        transfer_task_with_proc_failure (
            task, processor, TASK_ERR_CHECK_BLOCK_LIST);
    }

out:
    g_signal_handlers_disconnect_by_func (processor, on_checkbl_done, data);
}

static void
start_check_block_list_proc (TransferTask *task)
{
    CcnetProcessor *processor;

    if (task->block_ids) {
        g_queue_foreach (task->block_ids, free_block_id, NULL);
        g_queue_free (task->block_ids);
    }
    task->block_ids = g_queue_new ();

    processor = ccnet_proc_factory_create_remote_master_processor (
                seaf->session->proc_factory, "seafile-checkbl", task->dest_id);
    ((SeafileCheckblProc *)processor)->task = task;
    if (task->protocol_version < 6)
        ((SeafileCheckblProc *)processor)->send_session_token = FALSE;
    else
        ((SeafileCheckblProc *)processor)->send_session_token = TRUE;
    g_signal_connect (processor, "done", (GCallback)on_checkbl_done, task);

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("failed to start checkbl proc.\n");
        transition_state_to_error (task, TASK_ERR_CHECK_BLOCK_LIST);
    }

    transition_state (task, task->state, TASK_RT_STATE_CHECK_BLOCKS);
}

static void
start_block_upload (TransferTask *task)
{
#if 0
    if (task->block_list->n_valid_blocks != task->block_list->n_blocks) {
        seaf_warning ("Some blocks are missing locally, stop upload.\n");
        transition_state_to_error (task, TASK_ERR_LOAD_BLOCK_LIST); 
        return;
    }
#endif

    if (task->block_list->n_blocks == 0) {
        seaf_debug ("No block to upload.\n");
        update_remote_branch (task);
    } else
        start_check_block_list_proc (task);
}

static void
on_fs_uploaded (CcnetProcessor *processor, gboolean success, void *data)
{
    TransferTask *task = data;

    /* if the user stopped or canceled this task, stop processing. */
    /* state #6, #10 */
    if (task->state == TASK_STATE_CANCELED) {
        transition_state (task, task->state, TASK_RT_STATE_FINISHED);
        goto out;
    }

    if (success) {
        start_load_block_list_thread (task, start_block_upload);
    } else if (task->state != TASK_STATE_ERROR
               && task->runtime_state == TASK_RT_STATE_FS) {
        transfer_task_with_proc_failure (
            task, processor, TASK_ERR_UPLOAD_FS);
    }

out:
    g_signal_handlers_disconnect_by_func (processor, on_fs_uploaded, data);
}

static void
start_fs_upload (TransferTask *task, const char *peer_id)
{
    int ret;
    ObjectList *ol;

    if (task->protocol_version == 1) {
        ol = object_list_new ();
        ret = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                        task->repo_id,
                                                        task->repo_version,
                                                        task->head,
                                                        fs_root_collector,
                                                        ol, FALSE);
        if (ret == FALSE) {
            object_list_free (ol);
            transition_state_to_error (task, TASK_ERR_LOAD_FS);
            return;
        }
        task->fs_roots = ol;
    }

    if (task->protocol_version <= 6 &&
        object_list_length(task->fs_roots) == 0) {
        update_remote_branch (task);
        return;
    }

    if (start_sendfs_proc (task, peer_id, (GCallback)on_fs_uploaded) < 0)
        transition_state_to_error (task, TASK_ERR_UPLOAD_FS_START);
    else
        transition_state (task, task->state, TASK_RT_STATE_FS);
}

static void
on_commit_uploaded (CcnetProcessor *processor, gboolean success, void *data)
{
    TransferTask *task = data;

    /* if the user stopped or canceled this task, stop processing. */
    /* state #5, #9 */
    if (task->state == TASK_STATE_CANCELED) {
        transition_state (task, task->state, TASK_RT_STATE_FINISHED);
        goto out;
    }

    if (success) {
        start_fs_upload (task, processor->peer_id);
    } else if (task->state != TASK_STATE_ERROR
               && task->runtime_state == TASK_RT_STATE_COMMIT) {
        transfer_task_with_proc_failure (
            task, processor, TASK_ERR_UPLOAD_COMMIT);
    }

out:
    g_signal_handlers_disconnect_by_func (processor, on_commit_uploaded, data);
}

static int
start_commit_upload (TransferTask *task)
{
    task->rsize = -1;
    task->dsize = 0;

    if (start_sendcommit_proc (task, task->dest_id, (GCallback)on_commit_uploaded) < 0) {
        transition_state_to_error (task, TASK_ERR_UPLOAD_COMMIT_START);
        return -1;
    }
    transition_state (task, task->state, TASK_RT_STATE_COMMIT);

    return 0;
}

static void
check_upload_cb (CcnetProcessor *processor, gboolean success, void *data)
{
    TransferTask *task = data;

    /* if the user stopped or canceled this task, stop processing. */
    /* state #5, #9 */
    if (task->state == TASK_STATE_CANCELED) {
        transition_state (task, task->state, TASK_RT_STATE_FINISHED);
        goto out;
    }

    if (success) {
        start_commit_upload (task);
    } else if (task->state != TASK_STATE_ERROR
               && task->runtime_state == TASK_RT_STATE_CHECK) {
        transfer_task_with_proc_failure (
            task, processor, TASK_ERR_UNKNOWN);
    }
    /* Errors have been processed in the processor. */

out:
    g_signal_handlers_disconnect_by_func (processor, check_upload_cb, data);
}

static int
start_upload (TransferTask *task)
{
    const char *dest_id = task->dest_id;
    CcnetProcessor *processor;
    SeafBranch *branch;

    if (!dest_id)
        return -1;

    if (!ccnet_peer_is_ready (seaf->ccnetrpc_client, dest_id))
        return -1;

    branch = seaf_branch_manager_get_branch (seaf->branch_mgr, 
                                             task->repo_id, 
                                             task->from_branch);
    if (!branch) {
        seaf_warning ("[Upload] Bad source branch %s.\n", task->from_branch);
        transition_state_to_error (task, TASK_ERR_BAD_LOCAL_BRANCH);
        return -1;
    }
    memcpy (task->head, branch->commit_id, 41);
    seaf_branch_unref (branch);

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-check-tx-v3", dest_id);
    if (!processor) {
        seaf_warning ("failed to create check-tx-v3 proc for upload.\n");
        transition_state_to_error (task, TASK_ERR_CHECK_UPLOAD_START);
        return -1;
    }

    g_signal_connect (processor, "done", (GCallback)check_upload_cb, task);

    ((SeafileCheckTxV3Proc *)processor)->task = task;
    if (ccnet_processor_startl (processor, "upload", NULL) < 0)
    {
        seaf_warning ("failed to start check-tx-v3 proc for upload.\n");
        return -1;
    }

    transition_state (task, task->state, TASK_RT_STATE_CHECK);
    return 0;
}

static void
schedule_upload_task (TransferTask *task)
{
    switch (task->runtime_state) {
    case TASK_RT_STATE_INIT:
        start_upload (task);
        break;
    case TASK_RT_STATE_DATA:
        break;
    default:
        break;
    }
}


/* -------- schedule -------- */

static void resume_task_from_netdown(TransferTask *task, const char *dest_id)
{
    if (!task || !dest_id)
        return;

    if (task->runtime_state == TASK_RT_STATE_NETDOWN) {
        switch (task->last_runtime_state) {
        case TASK_RT_STATE_CHECK:
            if (task->type == TASK_TYPE_DOWNLOAD)
                start_download(task);
            else
                start_upload(task);
            break;
        case TASK_RT_STATE_COMMIT:
            if (task->type == TASK_TYPE_DOWNLOAD)
                start_commit_download(task);
            else
                start_commit_upload(task);
            break;
        case TASK_RT_STATE_FS:
            if (task->type == TASK_TYPE_DOWNLOAD)
                start_fs_download(task, dest_id);
            else
                start_fs_upload(task, dest_id);
            break;
        case TASK_RT_STATE_CHECK_BLOCKS:
            g_return_if_fail (task->type == TASK_TYPE_UPLOAD);
            start_check_block_list_proc (task);
            break;
        case TASK_RT_STATE_CHUNK_SERVER:
            get_chunk_server_address (task);
            break;
        default:
            break ;
        }
    }
}


static void
state_machine_tick (TransferTask *task)
{
    switch (task->state) {
    case TASK_STATE_NORMAL:
        /* If repo was deleted, cancel any transfer task for it.
         * Also note that the repo doesn't exist if we're cloning it.
         */
        if (!task->is_clone &&
            !seaf_repo_manager_repo_exists (seaf->repo_mgr, task->repo_id)) {
            cancel_task (task);
            break;
        }

        /* state #1, #2, #3, #4 */
        if (task->runtime_state == TASK_RT_STATE_NETDOWN) {
            const char *dest_id = task->dest_id;
            if (dest_id && ccnet_peer_is_ready (seaf->ccnetrpc_client, dest_id))
            {
                seaf_debug ("[tr-mgr] Resume transfer repo %.8s when "
                            "peer %.10s is reconnected\n",
                            task->repo_id, dest_id);
                g_return_if_fail (task->last_runtime_state != TASK_RT_STATE_NETDOWN
                          && task->last_runtime_state != TASK_RT_STATE_FINISHED);
                resume_task_from_netdown(task, dest_id);
            }
        } else if (task->runtime_state != TASK_RT_STATE_FINISHED) {
            if (task->type == TASK_TYPE_DOWNLOAD)
                schedule_download_task (task);
            else
                schedule_upload_task (task);
        } else {
            /* normal && finish, can't happen */
            g_return_if_reached ();
        }
        break;
    case TASK_STATE_FINISHED:
        /* state #13 */
        g_return_if_fail (task->runtime_state == TASK_RT_STATE_FINISHED);
        break;
    case TASK_STATE_CANCELED:
        /* state #11 */
        break;
    case TASK_STATE_ERROR:
        /* state #14 */
        g_return_if_fail (task->runtime_state == TASK_RT_STATE_FINISHED);
        break;
    default:
        g_return_if_reached ();
    }
}

static int
schedule_task_pulse (void *vmanager)
{
    SeafTransferManager *mgr = vmanager;
    GHashTableIter iter;
    gpointer key, value;
    TransferTask *task;

    g_hash_table_iter_init (&iter, mgr->download_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        state_machine_tick (task);
    }

    g_hash_table_iter_init (&iter, mgr->upload_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        state_machine_tick (task);
    }

    return TRUE;
}
