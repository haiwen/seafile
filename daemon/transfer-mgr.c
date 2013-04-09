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

#include "seafile-session.h"
#include "transfer-mgr.h"
#include "commit-mgr.h"
#include "fs-mgr.h"
#include "block-mgr.h"
#include "bitfield.h"
#include "seafile-error.h"
#include "vc-common.h"
#include "merge.h"
#include "sync-mgr.h"
#include "clone-mgr.h"
#include "vc-utils.h"
#include "gc.h"
#include "mq-mgr.h"

#include "processors/check-tx-v2-proc.h"
#include "processors/check-tx-v3-proc.h"
#include "processors/getcommit-proc.h"
#include "processors/sendcommit-proc.h"
#include "processors/sendfs-proc.h"
#include "processors/getfs-proc.h"
#include "processors/getblock-proc.h"
#include "processors/getblock-v2-proc.h"
#include "processors/sendblock-proc.h"
#include "processors/sendblock-v2-proc.h"
#include "processors/getcs-proc.h"
#include "processors/sendbranch-proc.h"
#include "processors/getcommit-v2-proc.h"
#include "processors/sendcommit-v2-proc.h"
#include "processors/sendcommit-v3-proc.h"

#define TRANSFER_DB "transfer.db"

#define SCHEDULE_INTERVAL   1   /* 1s */
#define MAX_QUEUED_BLOCKS   50

#define DEFAULT_BLOCK_SIZE  (1 << 20)

static int schedule_task_pulse (void *vmanager);
static void free_task_resources (TransferTask *task);
static void state_machine_tick (TransferTask *task);

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
    "Transfer protocol outdated. You need to upgrade seafile."
    "Incomplete revision information in the local library"
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
    task->processors = g_hash_table_new_full (g_str_hash, g_str_equal,
                                              g_free, NULL);
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

    g_hash_table_destroy (task->processors);

    g_free (task);
}

int
transfer_task_get_rate (TransferTask *task)
{
    return task->last_tx_bytes;
}

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
        commit = seaf_commit_manager_get_commit (seaf->commit_mgr, commit_id);
        if (!commit) {
            seaf_warning ("Failed to get commit %s.\n", commit_id);
            block_list_free (bl1);
            return NULL;
        }

        if (seaf_fs_manager_populate_blocklist (seaf->fs_mgr,
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
                                                 parent_id);
        if (!parent) {
            block_list_free (bl1);
            return NULL;
        }

        bl2 = block_list_new ();
        if (seaf_fs_manager_populate_blocklist (seaf->fs_mgr, 
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
                                                    remote->root_id,
                                                    bl) < 0) {
                seaf_warning ("[tr-mgr] Failed to get blocks of commit %s.\n",
                           remote->commit_id);
                seaf_commit_unref (remote);
                return -1;
            }
        }
        seaf_commit_unref (remote);

        /* bl cannot be NULL since we shouldn't have started download
         * if we're already up to date.
         */
        g_assert (bl != NULL);
    }

    block_list_generate_bitmap (bl);

    task->block_list = bl;
    BitfieldConstruct (&task->active, bl->n_blocks);

    if (task->type == TASK_TYPE_UPLOAD)
        BitfieldConstruct (&task->uploaded, bl->n_blocks);

    return 0;
}

static int remove_task_state (TransferTask *task)
{
    char sql[256];

    snprintf (sql, 256, "DELETE FROM CloneHeads WHERE repo_id = '%s';",
              task->repo_id);
    if (sqlite_query_exec (task->manager->db, sql) < 0)
        return -1;

    return 0;
}

static void
save_clone_head (TransferTask *task, const char *head_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql), "REPLACE INTO CloneHeads VALUES ('%s', '%s');",
              task->repo_id, head_id);
    sqlite_query_exec (task->manager->db, sql);
}

static gboolean
get_heads (sqlite3_stmt *stmt, void *vheads)
{
    GList **pheads = vheads;
    const char *head_id;

    head_id = (const char *)sqlite3_column_text (stmt, 0);
    *pheads = g_list_prepend (*pheads, g_strdup(head_id));

    return TRUE;
}

GList *
seaf_transfer_manager_get_clone_heads (SeafTransferManager *mgr)
{
    GList *heads = NULL;

    char *sql = "SELECT head FROM CloneHeads";
    if (sqlite_foreach_selected_row (mgr->db, sql, get_heads, &heads) < 0) {
        string_list_free (heads);
        return NULL;
    }

    return heads;
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
        remove_task_state (task);
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
    seaf_message ("Transfer repo '%.8s': ('%s', '%s') --> ('%s', '%s'): %s\n",
                  task->repo_id,
                  task_state_to_str(task->state),
                  task_rt_state_to_str(task->runtime_state),
                  task_state_to_str(TASK_STATE_ERROR),
                  task_rt_state_to_str(TASK_RT_STATE_FINISHED),
                  task_error_str(task_errno));

    task->last_runtime_state = task->runtime_state;

    remove_task_state (task);

    g_assert (task_errno != 0);
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
    g_assert (task->state == TASK_STATE_NORMAL);
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
        g_assert(0);
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
                                           "seafile-getcommit",
                                           SEAFILE_TYPE_GETCOMMIT_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-sendcommit",
                                           SEAFILE_TYPE_SENDCOMMIT_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-getblock",
                                           SEAFILE_TYPE_GETBLOCK_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-getblock-v2",
                                           SEAFILE_TYPE_GETBLOCK_V2_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-sendblock",
                                           SEAFILE_TYPE_SENDBLOCK_PROC);

    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-sendblock-v2",
                                           SEAFILE_TYPE_SENDBLOCK_V2_PROC);

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
                                           "seafile-sendcommit-v2",
                                           SEAFILE_TYPE_SENDCOMMIT_V2_PROC);
    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-sendcommit-v3",
                                           SEAFILE_TYPE_SENDCOMMIT_V3_PROC);
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

    g_assert (task->state != TASK_STATE_NORMAL);

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
                                    const char *peer_id,
                                    const char *from_branch,
                                    const char *to_branch,
                                    const char *token,
                                    GError **error)
{
    TransferTask *task;

    if (!repo_id || !from_branch || !to_branch || !token) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Empty argument(s)");
        return NULL;
    }

    g_assert(strlen(repo_id) == 36);

    if (is_duplicate_task (manager, repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Task is already in progress");
        return NULL;
    }
    clean_tasks_for_repo (manager, repo_id);

    task = seaf_transfer_task_new (manager, NULL, repo_id, peer_id,
                                   from_branch, to_branch, token,
                                   TASK_TYPE_DOWNLOAD);
    task->state = TASK_STATE_NORMAL;

    /* Mark task "clone" if it's a new repo. */
    if (!seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id))
        task->is_clone = TRUE;

    g_hash_table_insert (manager->download_tasks,
                         g_strdup(task->tx_id),
                         task);

    return g_strdup(task->tx_id);
}

char *
seaf_transfer_manager_add_upload (SeafTransferManager *manager,
                                  const char *repo_id,
                                  const char *peer_id,
                                  const char *from_branch,
                                  const char *to_branch,
                                  const char *token,
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
                                   TASK_TYPE_UPLOAD);
    task->state = TASK_STATE_NORMAL;

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
    if (task->runtime_state == TASK_RT_STATE_NETDOWN) {
        transition_state (task, TASK_STATE_CANCELED, TASK_RT_STATE_FINISHED);
    } else {
        /*
         * Only transition state, not runtime state.
         * Runtime state transition is handled asynchronously.
         */
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


static int
start_getcs_proc (TransferTask *task, const char *peer_id)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-getcs", peer_id);
    if (!processor) {
        seaf_warning ("failed to create get chunk server proc.\n");
        return -1;
    }
    ((SeafileGetcsProc *)processor)->task = task;

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("failed to start get chunk server proc.\n");
        return -1;
    }

    return 0;
}

static int
get_chunk_server_list (TransferTask *task)
{
    const char *dest_id = task->dest_id;

    if (!dest_id)
        return -1;

    if (!ccnet_peer_is_ready (seaf->ccnetrpc_client, dest_id))
        return -1;

    if (start_getcs_proc (task, dest_id) < 0)
        return -1;

    return 0;
}


static void
tx_done_cb (CcnetProcessor *processor, gboolean success, void *data)
{
    TransferTask *task = data;

    if (!success && task->state == TASK_STATE_ERROR) {
        /* block tx processor encountered non-recoverable error,
         * such as access denied.
         */
        /* TODO: This is BUG */
        free_task_resources (task);
    } else {
        /* Otherwise processs exits successfully, or the error is
         * recoverable, restart processor later. 
         */
        g_hash_table_remove (task->processors, processor->peer_id);
    }
}

static CcnetProcessor *
start_sendblock_proc (TransferTask *task, const char *peer_id)
{
    CcnetProcessor *processor;

    if (!ccnet_peer_is_ready (seaf->ccnetrpc_client, peer_id))
        return NULL;

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-sendblock-v2", peer_id);
    if (!processor) {
        seaf_warning ("failed to create sendblock proc.\n");
        return NULL;
    }

    ((SeafileSendblockV2Proc *)processor)->tx_task = task;
    if (ccnet_processor_start (processor, 0, NULL) < 0) {
        seaf_warning ("failed to start sendblock proc.\n");
        return NULL;
    }

    g_signal_connect (processor, "done", (GCallback)tx_done_cb, task);

    return processor;
}

static CcnetProcessor *
start_getblock_proc (TransferTask *task, const char *peer_id)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-getblock-v2", peer_id);
    if (!processor) {
        seaf_warning ("failed to create getblock proc.\n");
        return NULL;
    }

    ((SeafileGetblockV2Proc *)processor)->tx_task = task;
    if (ccnet_processor_start (processor, 0, NULL) < 0) {
        seaf_warning ("failed to start getblock proc.\n");
        return NULL;
    }

    g_signal_connect (processor, "done", (GCallback)tx_done_cb, task);

    return processor;
}

static gboolean
fs_root_collector (SeafCommit *commit, void *data, gboolean *stop)
{
    ObjectList *ol = data;

    if (strcmp(commit->root_id, EMPTY_SHA1) != 0)
        object_list_insert (ol, commit->root_id);

    return TRUE;
}

/* -------- download -------- */

static int
start_getcommit_proc (TransferTask *task, const char *peer_id, GCallback done_cb)
{
    CcnetProcessor *processor;

    if (task->protocol_version == 1)
        processor = ccnet_proc_factory_create_remote_master_processor (
                    seaf->session->proc_factory, "seafile-getcommit", peer_id);
    else
        processor = ccnet_proc_factory_create_remote_master_processor (
                    seaf->session->proc_factory, "seafile-getcommit-v2", peer_id);
    if (!processor) {
        seaf_warning ("failed to create getcommit proc.\n");
        return -1;
    }

    ((SeafileSendcommitProc *)processor)->tx_task = task;
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

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-getfs", peer_id);
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


/**
 * Error handling:
 *
 * When a task is running in RT_STATE_INIT, COMMIT or FS, if we fail to
 * start a processor we'll set task state to TASK_STATE_ERROR.
 * The user can manually resume this task if needed.
 * If in these stages the relay suddenly goes off-line, we'll set runtime
 * state to RT_STATE_INIT and retry in the next schedule interval.
 *
 * When a task is running in RT_STATE_DATA, any processor error is
 * tolerated. We'll continuously retry.
 */

static void
download_dispatch_blocks_to_processor (TransferTask *task,
                                       SeafileGetblockV2Proc *proc,
                                       guint n_procs)
{
    CcnetProcessor *processor = (CcnetProcessor *)proc;
    int expected, n_blocks, n_scheduled = 0;
    int i;

    if (!seafile_getblock_v2_proc_is_ready (proc))
        return;

    expected = MIN (proc->block_bitmap.bitCount/n_procs, MAX_QUEUED_BLOCKS);
    n_blocks = expected - proc->pending_blocks;
    if (n_blocks <= 0)
        return;

    seaf_debug ("expected: %d, pending: %d.\n", expected, proc->pending_blocks);

    for (i = 0; i < proc->block_bitmap.bitCount; ++i) {
        if (n_scheduled == n_blocks)
            break;

        if (BitfieldHasFast (&proc->block_bitmap, i) &&
            !BitfieldHasFast (&task->block_list->block_map, i) &&
            !BitfieldHasFast (&task->active, i))
        {
            const char *block_id;
            block_id = g_ptr_array_index (task->block_list->block_ids, i);
            seaf_debug ("Transfer repo %.8s: schedule block %.8s to %.8s.\n",
                        task->repo_id, block_id, processor->peer_id);
            seafile_getblock_v2_proc_get_block (proc, i);
            BitfieldAdd (&task->active, i);
            ++n_scheduled;
        }
    }
}

static void
download_dispatch_blocks (TransferTask *task)
{
    GHashTableIter iter;
    gpointer key, value;
    SeafileGetblockV2Proc *proc;
    guint n_procs = g_hash_table_size (task->processors);

    g_hash_table_iter_init (&iter, task->processors);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        proc = value;
        download_dispatch_blocks_to_processor (task, proc, n_procs);
    }
}

static void
start_chunk_server_download (TransferTask *task)
{
    GList *ptr = task->chunk_servers;
    const char *cs_id;
    CcnetProcessor *processor;

    while (ptr) {
        cs_id = ptr->data;
        if (!g_hash_table_lookup (task->processors, cs_id)) {
            processor = start_getblock_proc (task, cs_id);
            if (processor != NULL) {
                g_hash_table_insert (task->processors, g_strdup(cs_id), processor);
            }
        }
        ptr = ptr->next;
    }
}

static void
start_block_download (TransferTask *task)
{
    if (seaf_transfer_task_load_blocklist (task) < 0) {
        transition_state_to_error (task, TASK_ERR_LOAD_BLOCK_LIST);
    } else {
        transition_state (task, task->state, TASK_RT_STATE_DATA);
    }
    state_machine_tick (task);
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
        start_block_download (task);
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
                                                        task->head,
                                                        fs_root_collector,
                                                        ol);
        if (ret == FALSE) {
            object_list_free (ol);
            transition_state_to_error (task, TASK_ERR_LOAD_FS);
            return;
        }
        task->fs_roots = ol;
    }

    if (object_list_length(task->fs_roots) == 0) {
        start_block_download (task);
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
        /* Save remote head id for use in GC.
         * GC can then mark the blocks refered by these head ids as alive.
         */
        save_clone_head (task, task->head);

        start_commit_download (task);
    } else if (processor->failure == PROC_NO_SERVICE) {
        /* Talking to an old server. */
        CcnetProcessor *v2_proc;

        v2_proc = ccnet_proc_factory_create_remote_master_processor (
            seaf->session->proc_factory, "seafile-check-tx-v2", task->dest_id);
        if (!v2_proc) {
            seaf_warning ("failed to create check-tx-v2 proc for download.\n");
            transition_state_to_error (task, TASK_ERR_CHECK_DOWNLOAD_START);
        }

        g_signal_connect (v2_proc, "done", (GCallback)check_download_cb, task);

        ((SeafileCheckTxV2Proc *)v2_proc)->task = task;
        if (ccnet_processor_startl (v2_proc, "download", NULL) < 0)
            seaf_warning ("failed to start check-tx-v2 proc for download.\n");

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

    new_head = seaf_commit_manager_get_commit (seaf->commit_mgr, task->head);

    /* If repo doesn't exist, create it.
     * Note that branch doesn't exist either in this case.
     */
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, new_head->repo_id);
    if (!repo && task->is_clone) {
        repo = seaf_repo_new (new_head->repo_id, NULL, NULL);
        if (repo == NULL) {
            /* create repo failed */
            return -1;
        }

        seaf_repo_from_commit (repo, new_head);

        seaf_repo_manager_add_repo (seaf->repo_mgr, repo);

        /* If it's a new repo, create 'local' branch */
        branch = seaf_branch_new ("local", task->repo_id, task->head);
        seaf_branch_manager_add_branch (seaf->branch_mgr, branch);
        seaf_branch_unref (branch);

        /* Set relay to where this repo from. */
        if (is_peer_relay (task->dest_id)) {
            seaf_repo_manager_set_repo_relay_id (seaf->repo_mgr, repo,
                                                 task->dest_id);
        }
    } else if (!repo) {
        /* The repo was deleted when we're downloading it. */
        return 0;
    }

    branch = seaf_branch_manager_get_branch (seaf->branch_mgr, 
                                             task->repo_id,
                                             task->to_branch);
    if (!branch) {
        branch = seaf_branch_new (task->to_branch, task->repo_id, task->head);
        seaf_branch_manager_add_branch (seaf->branch_mgr, branch);
    } else {
        /* If branch exists, make sure it's not the current branch of repo.
         * We don't allow fetching to the current branch.
         */
        if (repo->head && strcmp (branch->name, repo->head->name) == 0) {
            seaf_warning ("Refuse fetching to current branch %s.\n", repo->head->name);
            /* This should not happen in our restricted user model,
             * just set to unknown error.
             */
            transition_state_to_error (task, TASK_ERR_UNKNOWN);
            seaf_commit_unref (new_head);
            seaf_branch_unref (branch);
            return -1;
        }

        /* Update branch */
        seaf_branch_set_commit (branch, new_head->commit_id);
        seaf_branch_manager_update_branch (seaf->branch_mgr, branch);
    }

    seaf_branch_unref (branch);
    seaf_commit_unref (new_head);
    return 0;
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

    char *dest_id = task->dest_id;

    switch (task->runtime_state) {
    case TASK_RT_STATE_INIT:
        start_download (task);
        break;
    case TASK_RT_STATE_DATA:
        if (task->block_list->n_valid_blocks == task->block_list->n_blocks) {
            update_local_repo (task);
            free_task_resources (task);
            transition_state (task, TASK_STATE_FINISHED, TASK_RT_STATE_FINISHED);
            break;
        }

        if (task->chunk_servers == NULL) {
            if (is_peer_relay (dest_id))
                get_chunk_server_list (task);
            else
                task->chunk_servers = g_list_prepend (task->chunk_servers, 
                                                      g_strdup(dest_id));
        }

        start_chunk_server_download (task);
        download_dispatch_blocks (task);
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

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-sendfs", peer_id);
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

    switch (task->protocol_version) {
    case 1:
        processor = ccnet_proc_factory_create_remote_master_processor (
                    seaf->session->proc_factory, "seafile-sendcommit", peer_id);
        break;
    case 2:
        processor = ccnet_proc_factory_create_remote_master_processor (
                    seaf->session->proc_factory, "seafile-sendcommit-v2", peer_id);
        break;
    default:
        processor = ccnet_proc_factory_create_remote_master_processor (
                    seaf->session->proc_factory, "seafile-sendcommit-v3", peer_id);
        break;
    }
    if (!processor) {
        seaf_warning ("failed to create sendcommit proc.\n");
        return -1;
    }

    ((SeafileSendcommitProc *)processor)->tx_task = task;
    g_signal_connect (processor, "done", done_cb, task);

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("failed to start sendcommit proc.\n");
        return -1;
    }

    return 0;
}

static void
start_block_upload (TransferTask *task)
{
    if (seaf_transfer_task_load_blocklist (task) < 0) {
        transition_state_to_error (task, TASK_ERR_LOAD_BLOCK_LIST);
    } else if (task->block_list->n_valid_blocks != task->block_list->n_blocks) {
        seaf_warning ("Some blocks are missing locally, stop upload.\n");
        transition_state_to_error (task, TASK_ERR_LOAD_BLOCK_LIST);
    } else {
        transition_state (task, task->state, TASK_RT_STATE_DATA);
    }
    state_machine_tick (task);
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
        start_block_upload (task);
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
                                                        task->head,
                                                        fs_root_collector,
                                                        ol);
        if (ret == FALSE) {
            object_list_free (ol);
            transition_state_to_error (task, TASK_ERR_LOAD_FS);
            return;
        }
        task->fs_roots = ol;
    }

    if (object_list_length(task->fs_roots) == 0) {
        start_block_upload (task);
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
    } else if (processor->failure == PROC_NO_SERVICE) {
        /* Talking to an old server. */
        CcnetProcessor *v2_proc;

        v2_proc = ccnet_proc_factory_create_remote_master_processor (
            seaf->session->proc_factory, "seafile-check-tx-v2", task->dest_id);
        if (!v2_proc) {
            seaf_warning ("failed to create check-tx-v2 proc for upload.\n");
            transition_state_to_error (task, TASK_ERR_CHECK_UPLOAD_START);
        }

        g_signal_connect (v2_proc, "done", (GCallback)check_upload_cb, task);

        ((SeafileCheckTxV2Proc *)v2_proc)->task = task;
        if (ccnet_processor_startl (v2_proc, "upload", NULL) < 0)
            seaf_warning ("failed to start check-tx-v2 proc for upload.\n");

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
start_chunk_server_upload (TransferTask *task)
{
    GList *ptr = task->chunk_servers;
    const char *cs_id;
    CcnetProcessor *processor;

    while (ptr) {
        cs_id = ptr->data;
        if (!g_hash_table_lookup (task->processors, cs_id)) {
            processor = start_sendblock_proc (task, cs_id);
            if (processor != NULL) {
                g_hash_table_insert (task->processors, g_strdup(cs_id), processor);
            }
        }
        ptr = ptr->next;
    }
}

static void
upload_dispatch_blocks_to_processor (TransferTask *task,
                                     SeafileSendblockV2Proc *proc,
                                     guint n_procs)
{
    CcnetProcessor *processor = (CcnetProcessor *)proc;
    int expected, n_blocks, n_scheduled = 0;
    int i;

    if (!seafile_sendblock_v2_proc_is_ready (proc))
        return;

    expected = MIN (task->uploaded.bitCount/n_procs, MAX_QUEUED_BLOCKS);
    n_blocks = expected - proc->pending_blocks;
    if (n_blocks <= 0)
        return;

    seaf_debug ("expected: %d, pending: %d.\n", expected, proc->pending_blocks);

    for (i = 0; i < task->uploaded.bitCount; ++i) {
        if (n_scheduled == n_blocks)
            break;

        if (!BitfieldHasFast (&task->uploaded, i) &&
            BitfieldHasFast (&task->block_list->block_map, i) &&
            !BitfieldHasFast (&task->active, i))
        {
            const char *block_id;
            block_id = g_ptr_array_index (task->block_list->block_ids, i);
            seaf_debug ("Transfer repo %.8s: schedule block %.8s to %.8s.\n",
                     task->repo_id, block_id, processor->peer_id);
            seafile_sendblock_v2_proc_send_block (proc, i);
            BitfieldAdd (&task->active, i);
            ++n_scheduled;
        }
    }
}

static void
upload_dispatch_blocks (TransferTask *task)
{
    GHashTableIter iter;
    gpointer key, value;
    SeafileSendblockV2Proc *proc;
    guint n_procs = g_hash_table_size (task->processors);

    g_hash_table_iter_init (&iter, task->processors);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        proc = value;
        upload_dispatch_blocks_to_processor (task, proc, n_procs);
    }
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
schedule_upload_task (TransferTask *task)
{
    switch (task->runtime_state) {
    case TASK_RT_STATE_INIT:
        start_upload (task);
        break;
    case TASK_RT_STATE_DATA:
        if (task->n_uploaded == task->block_list->n_blocks) {
            free_task_resources (task);
            update_remote_branch (task);
            break;
        }

        if (task->chunk_servers == NULL)
            get_chunk_server_list (task);
        start_chunk_server_upload (task);
        upload_dispatch_blocks (task);

        break;
    default:
        break;
    }
}


/* -------- schedule -------- */

static gboolean
collect_block_processor (gpointer key, gpointer value, gpointer data)
{
    CcnetProcessor *processor = value;
    GList **pproc_list = data;

    *pproc_list = g_list_prepend (*pproc_list, processor);

    return TRUE;
}

static void
free_task_resources (TransferTask *task)
{
    GList *proc_list = NULL;
    GList *ptr;

    /* We must first move processors from the hash table into
     * a list, because tx_done_cb() tries to remove the proc
     * from the hash table too. We can't remove an element
     * from the hash table while traversing it.
     */
    g_hash_table_foreach_remove (task->processors,
                                 collect_block_processor,
                                 &proc_list);
    ptr = proc_list;
    while (ptr != NULL) {
        CcnetProcessor *processor = ptr->data;
        ccnet_processor_done (processor, TRUE);
        ptr = g_list_delete_link (ptr, ptr);
    }

    block_list_free (task->block_list);
    task->block_list = NULL;
    BitfieldDestruct (&task->active);

    for (ptr = task->chunk_servers; ptr; ptr = ptr->next) 
        g_free (ptr->data);
    g_list_free (task->chunk_servers);
    task->chunk_servers = NULL;

    if (task->type == TASK_TYPE_UPLOAD)
        BitfieldDestruct (&task->uploaded);
}

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
                g_assert (task->last_runtime_state != TASK_RT_STATE_NETDOWN
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
            g_assert (0);
        }
        break;
    case TASK_STATE_FINISHED:
        /* state #13 */
        g_assert (task->runtime_state == TASK_RT_STATE_FINISHED);
        break;
    case TASK_STATE_CANCELED:
        /* state #11 */
        if (task->runtime_state == TASK_RT_STATE_DATA) {
            free_task_resources (task);
            /* transition to state #12 */
            transition_state (task, TASK_STATE_CANCELED, TASK_RT_STATE_FINISHED);
        }
        break;
    case TASK_STATE_ERROR:
        /* state #14 */
        g_assert (task->runtime_state == TASK_RT_STATE_FINISHED);
        break;
    default:
        fprintf (stderr, "state %d\n", task->state);
        g_assert (0);
    }
}


static inline void 
format_transfer_task_detail (TransferTask *task, GString *buf)
{
    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr,
                                                 task->repo_id);
    char *repo_name;
    char *type;
    
    if (repo) {
        repo_name = repo->name;
        type = (task->type == TASK_TYPE_UPLOAD) ? "upload" : "download";
        
    } else if (task->is_clone) {
        CloneTask *ctask;
        ctask = seaf_clone_manager_get_task (seaf->clone_mgr, task->repo_id);
        repo_name = ctask->repo_name;
        type = "download";
        
    } else {
        return;
    }
    int rate = transfer_task_get_rate(task);

    g_string_append_printf (buf, "%s\t%d %s\n", type, rate, repo_name);
}

/*
 * Publish a notification message to report :
 *
 *      [uploading/downloading]\t[transfer-rate] [repo-name]\n
 */
static void
send_transfer_message (GList *tasks)
{
    GList *ptr;
    TransferTask *task;
    GString *buf = g_string_new (NULL);

    for (ptr = tasks; ptr; ptr = ptr->next) {
        task = ptr->data;
        format_transfer_task_detail(task, buf);
    }
        
    seaf_mq_manager_publish_notification (seaf->mq_mgr, "transfer",
                                          buf->str);

    g_string_free (buf, TRUE);
}

static int
schedule_task_pulse (void *vmanager)
{
    SeafTransferManager *mgr = vmanager;
    GHashTableIter iter;
    gpointer key, value;
    TransferTask *task;

    GList *tasks_in_transfer = NULL;

    g_hash_table_iter_init (&iter, mgr->download_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        state_machine_tick (task);
        if ((task->state == TASK_STATE_NORMAL)
            && (task->runtime_state == TASK_RT_STATE_COMMIT ||
                task->runtime_state == TASK_RT_STATE_FS ||
                task->runtime_state == TASK_RT_STATE_DATA)) {
            tasks_in_transfer = g_list_prepend (tasks_in_transfer, task);
        }
    }

    g_hash_table_iter_init (&iter, mgr->upload_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        state_machine_tick (task);
        if ((task->state == TASK_STATE_NORMAL)
            && (task->runtime_state == TASK_RT_STATE_COMMIT ||
                task->runtime_state == TASK_RT_STATE_FS ||
                task->runtime_state == TASK_RT_STATE_DATA)) {
            tasks_in_transfer = g_list_prepend (tasks_in_transfer, task);
        }
    }

    if (tasks_in_transfer) {
        send_transfer_message (tasks_in_transfer);
        g_list_free (tasks_in_transfer);
    }

    /* Save tx_bytes to last_tx_bytes and reset tx_bytes to 0 every second */
    g_hash_table_iter_init (&iter, mgr->download_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        task->last_tx_bytes = g_atomic_int_get (&task->tx_bytes);
        g_atomic_int_set (&task->tx_bytes, 0);
    }

    g_hash_table_iter_init (&iter, mgr->upload_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        task->last_tx_bytes = g_atomic_int_get (&task->tx_bytes);
        g_atomic_int_set (&task->tx_bytes, 0);
    }

    return TRUE;
}
