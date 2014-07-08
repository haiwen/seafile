/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */


#include "common.h"

#include <ccnet.h>

#include "db.h"
#include "seafile-session.h"
#include "seafile-config.h"
#include "sync-mgr.h"
#include "transfer-mgr.h"
#include "processors/sync-repo-proc.h"
#include "processors/getca-proc.h"
#include "processors/check-protocol-proc.h"
#include "vc-common.h"
#include "seafile-error.h"
#include "status.h"
#include "mq-mgr.h"
#include "utils.h"

#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
#include "log.h"

#define DEFAULT_SYNC_INTERVAL 30 /* 30s */
#define CHECK_SYNC_INTERVAL  1000 /* 1s */
#define MAX_RUNNING_SYNC_TASKS 5

struct _SeafSyncManagerPriv {
    struct CcnetTimer *check_sync_timer;
    int    pulse_count;

    /* When FALSE, auto sync is globally disabled */
    gboolean   auto_sync_enabled;
};

static void
start_sync (SeafSyncManager *manager, SeafRepo *repo,
            gboolean need_commit, gboolean is_manual_sync,
            gboolean is_initial_commit);

static int auto_sync_pulse (void *vmanager);
static void on_repo_fetched (SeafileSession *seaf,
                             TransferTask *tx_task,
                             SeafSyncManager *manager);
static void on_repo_uploaded (SeafileSession *seaf,
                              TransferTask *tx_task,
                              SeafSyncManager *manager);
static inline void
transition_sync_state (SyncTask *task, int new_state);

static void sync_task_free (SyncTask *task);

SeafSyncManager*
seaf_sync_manager_new (SeafileSession *seaf)
{
    SeafSyncManager *mgr = g_new0 (SeafSyncManager, 1);
    mgr->priv = g_new0 (SeafSyncManagerPriv, 1);    
    mgr->priv->auto_sync_enabled = TRUE;
    mgr->seaf = seaf;

    mgr->sync_interval = DEFAULT_SYNC_INTERVAL;
    mgr->sync_infos = g_hash_table_new (g_str_hash, g_str_equal);

    mgr->server_states = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, g_free);

    return mgr;
}

static SyncInfo*
get_sync_info (SeafSyncManager *manager, const char *repo_id)
{
    SyncInfo *info = g_hash_table_lookup (manager->sync_infos, repo_id);
    if (info) return info;

    info = g_new0 (SyncInfo, 1);
    memcpy (info->repo_id, repo_id, 41);
    g_hash_table_insert (manager->sync_infos, info->repo_id, info);
    return info;
}

SyncInfo *
seaf_sync_manager_get_sync_info (SeafSyncManager *mgr,
                                 const char *repo_id)
{
    return g_hash_table_lookup (mgr->sync_infos, repo_id);
}

int
seaf_sync_manager_init (SeafSyncManager *mgr)
{
    return 0;
}

/* In case ccnet relay info is lost(e.g. ~/ccnet is removed), we need to
 * re-add the relay by supplying addr:port
 */
static void
add_relay_if_needed (SeafRepo *repo)
{
    CcnetPeer *relay = NULL;
    char *relay_port = NULL, *relay_addr = NULL;
    GString *buf = NULL; 

    seaf_repo_manager_get_repo_relay_info (seaf->repo_mgr, repo->id,
                                           &relay_addr, &relay_port);

    relay = ccnet_get_peer (seaf->ccnetrpc_client, repo->relay_id);
    if (relay) {
        /* no relay addr/port info in seafile db. This means we are
         * updating from an old version. */
        if (!relay_addr || !relay_port) {
            if (relay->public_addr && relay->public_port) {
                char port[16];
                snprintf (port, sizeof(port), "%d", relay->public_port);
                seaf_repo_manager_set_repo_relay_info (seaf->repo_mgr, repo->id,
                                                       relay->public_addr, port);
            }
        }
        goto out;
    }

    /* relay info is lost in ccnet, but we have its addr:port in seafile.db */
    if (relay_addr && relay_port) {
        buf = g_string_new(NULL);
        g_string_append_printf (buf, "add-relay --id %s --addr %s:%s",
                                repo->relay_id, relay_addr, relay_port);
                                               
    } else {
        seaf_warning ("[sync mgr] relay addr/port info"
                      " of repo %.10s is unknown\n", repo->id);
    }

    if (buf) {
        ccnet_send_command (seaf->session, buf->str, NULL, NULL);
    }

out:
    g_free (relay_addr);
    g_free (relay_port);
    if (relay)
        g_object_unref (relay);
    if (buf)
        g_string_free (buf, TRUE);
}

static void
add_repo_relays ()
{
    GList *ptr, *repo_list;

    repo_list = seaf_repo_manager_get_repo_list (seaf->repo_mgr, 0, -1);

    for (ptr = repo_list; ptr; ptr = ptr->next) {
        SeafRepo *repo = ptr->data;
        if (repo->relay_id) {
            add_relay_if_needed (repo);
        }
    }

    g_list_free (repo_list);
}

int
seaf_sync_manager_start (SeafSyncManager *mgr)
{
    add_repo_relays ();
    mgr->priv->check_sync_timer = ccnet_timer_new (
        auto_sync_pulse, mgr, CHECK_SYNC_INTERVAL);

    ccnet_proc_factory_register_processor (mgr->seaf->session->proc_factory,
                                           "seafile-sync-repo",
                                           SEAFILE_TYPE_SYNC_REPO_PROC);
    ccnet_proc_factory_register_processor (mgr->seaf->session->proc_factory,
                                           "seafile-getca",
                                           SEAFILE_TYPE_GETCA_PROC);
    ccnet_proc_factory_register_processor (mgr->seaf->session->proc_factory,
                                           "seafile-check-protocol",
                                           SEAFILE_TYPE_CHECK_PROTOCOL_PROC);
    g_signal_connect (seaf, "repo-fetched",
                      (GCallback)on_repo_fetched, mgr);
    g_signal_connect (seaf, "repo-uploaded",
                      (GCallback)on_repo_uploaded, mgr);

    return 0;
}

int
seaf_sync_manager_add_sync_task (SeafSyncManager *mgr,
                                 const char *repo_id,
                                 GError **error)
{
    if (!seaf->started) {
        seaf_message ("sync manager is not started, skip sync request.\n");
        return -1;
    }

    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("[sync mgr] cannot find repo %s.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "Invalid repo");
        return -1;
    }

    if (seaf_repo_check_worktree (repo) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_NO_WORKTREE,
                     "Worktree doesn't exist");
        return -1;
    }

    SyncInfo *info = get_sync_info (mgr, repo_id);

    if (info->in_sync)
        return 0;

    start_sync (mgr, repo, TRUE, TRUE, FALSE);

    return 0;
}

void
seaf_sync_manager_cancel_sync_task (SeafSyncManager *mgr,
                                    const char *repo_id)
{
    SyncInfo *info;
    SyncTask *task;

    if (!seaf->started) {
        seaf_message ("sync manager is not started, skip cancel request.\n");
        return;
    }

    /* Cancel running task. */
    info = g_hash_table_lookup (mgr->sync_infos, repo_id);
    if (!info || !info->in_sync)
        return;

    g_return_if_fail (info->current_task != NULL);
    task = info->current_task;

    switch (task->state) {
    case SYNC_STATE_FETCH:
        seaf_transfer_manager_cancel_task (seaf->transfer_mgr,
                                           task->tx_id,
                                           TASK_TYPE_DOWNLOAD);
        transition_sync_state (task, SYNC_STATE_CANCEL_PENDING);
        break;
    case SYNC_STATE_UPLOAD:
        seaf_transfer_manager_cancel_task (seaf->transfer_mgr,
                                           task->tx_id,
                                           TASK_TYPE_UPLOAD);
        transition_sync_state (task, SYNC_STATE_CANCEL_PENDING);
        break;
    case SYNC_STATE_COMMIT:
    case SYNC_STATE_INIT:
    case SYNC_STATE_MERGE:
        transition_sync_state (task, SYNC_STATE_CANCEL_PENDING);
        break;
    case SYNC_STATE_CANCEL_PENDING:
        break;
    default:
        g_return_if_reached ();
    }
}

/* Check the notify setting by user.  */
static gboolean
need_notify_sync (SeafRepo *repo)
{
    char *notify_setting = seafile_session_config_get_string(seaf, "notify_sync");
    if (notify_setting == NULL) {
        seafile_session_config_set_string(seaf, "notify_sync", "on");
        return TRUE;
    }

    gboolean result = (g_strcmp0(notify_setting, "on") == 0);
    g_free (notify_setting);
    return result;
}

static const char *sync_state_str[] = {
    "synchronized",
    "committing",
    "initializing",
    "downloading",
    "merging",
    "uploading",
    "error",
    "canceled",
    "cancel pending"
};

static gboolean
find_meaningful_commit (SeafCommit *commit, void *data, gboolean *stop)
{
    SeafCommit **p_head = data;

    if (commit->second_parent_id && commit->new_merge && !commit->conflict)
        return TRUE;

    *stop = TRUE;
    seaf_commit_ref (commit);
    *p_head = commit;
    return TRUE;
}

static void
notify_sync (SeafRepo *repo)
{
    SeafCommit *head = NULL;

    if (!seaf_commit_manager_traverse_commit_tree_truncated (seaf->commit_mgr,
                                                   repo->id, repo->version,
                                                   repo->head->commit_id,
                                                   find_meaningful_commit,
                                                   &head, FALSE)) {
        seaf_warning ("Failed to traverse commit tree of %.8s.\n", repo->id);
        return;
    }
    if (!head)
        return;

    GString *buf = g_string_new (NULL);
    g_string_append_printf (buf, "%s\t%s\t%s",
                            repo->name,
                            repo->id,
                            head->desc);
    seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                          "sync.done",
                                          buf->str);
    g_string_free (buf, TRUE);
    seaf_commit_unref (head);
}

static inline void
transition_sync_state (SyncTask *task, int new_state)
{
    g_return_if_fail (new_state >= 0 && new_state < SYNC_STATE_NUM);

    if (task->state != new_state) {
        if (!(task->state == SYNC_STATE_DONE && new_state == SYNC_STATE_INIT) &&
            !(task->state == SYNC_STATE_INIT && new_state == SYNC_STATE_DONE)) {
            seaf_message ("Repo '%s' sync state transition from '%s' to '%s'.\n",
                          task->repo->name,
                          sync_state_str[task->state],
                          sync_state_str[new_state]);
        }

        if ((task->state == SYNC_STATE_MERGE || task->state == SYNC_STATE_UPLOAD) &&
            new_state == SYNC_STATE_DONE &&
            need_notify_sync(task->repo))
        {
            notify_sync (task->repo);
        }

        task->state = new_state;
        if (new_state == SYNC_STATE_DONE || 
            new_state == SYNC_STATE_CANCELED ||
            new_state == SYNC_STATE_ERROR) {
            task->info->in_sync = FALSE;
            --(task->mgr->n_running_tasks);
            if (new_state == SYNC_STATE_ERROR)
                task->info->err_cnt++;
            else
                task->info->err_cnt = 0;
        }
    }
}

static const char *sync_error_str[] = {
    "Success",
    "relay not connected",
    "failed to upgrade old repo",
    "Server has been removed",
    "You have not login to the server",
    "Remote service is not available",
    "You do not have permission to access this library",
    "The storage space of the repo owner has been used up",
    "Access denied to service. Please check your registration on relay.",
    "Internal data corrupted.",
    "Failed to start upload.",
    "Error occured in upload.",
    "Failed to start download.",
    "Error occured in download.",
    "No such repo on relay.",
    "Repo is damaged on relay.",
    "Failed to index files.",
    "Conflict in merge.",
    "Files changed in local folder, skip merge.",
    "Server version is too old.",
    "Unknown error.",
};

void
seaf_sync_manager_set_task_error (SyncTask *task, int error)
{
    g_return_if_fail (error >= 0 && error < SYNC_ERROR_NUM);

    if (task->state != SYNC_STATE_ERROR) {
        seaf_message ("Repo '%s' sync state transition from %s to '%s': '%s'.\n",
                      task->repo->name,
                      sync_state_str[task->state],
                      sync_state_str[SYNC_STATE_ERROR],
                      sync_error_str[error]);
        task->state = SYNC_STATE_ERROR;
        task->error = error;
        task->info->in_sync = FALSE;
        task->info->err_cnt++;
        --(task->mgr->n_running_tasks);

#if 0
        if (task->repo && error != SYNC_ERROR_RELAY_OFFLINE
            && error != SYNC_ERROR_NOREPO) {
            GString *buf = g_string_new (NULL);
            g_string_append_printf (buf, "%s\t%s", task->repo->name,
                                    task->repo->id);
            seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                                  "sync.error",
                                                  buf->str);
            g_string_free (buf, TRUE);
        }
#endif                                         
    }
}

static void
sync_task_free (SyncTask *task)
{
    g_free (task->tx_id);
    g_free (task->dest_id);
    g_free (task->token);
    g_free (task);
}

static void
start_upload_if_necessary (SyncTask *task)
{
    GError *error = NULL;
    const char *repo_id = task->repo->id;

    char *tx_id = seaf_transfer_manager_add_upload (seaf->transfer_mgr,
                                                    repo_id,
                                                    task->repo->version,
                                                    task->dest_id,
                                                    "local",
                                                    "master",
                                                    task->token,
                                                    task->server_side_merge,
                                                    &error);
    if (error != NULL) {
        seaf_warning ("Failed to start upload: %s\n", error->message);
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_START_UPLOAD);
        return;
    }
    task->tx_id = tx_id;
    transition_sync_state (task, SYNC_STATE_UPLOAD);
}

static void
start_fetch_if_necessary (SyncTask *task)
{
    GError *error = NULL;
    char *tx_id;
    const char *repo_id = task->repo->id;

    tx_id = seaf_transfer_manager_add_download (seaf->transfer_mgr,
                                                repo_id,
                                                task->repo->version,
                                                task->dest_id,
                                                "fetch_head",
                                                "master",
                                                task->token,
                                                task->server_side_merge,
                                                NULL,
                                                NULL,
                                                &error);

    if (error != NULL) {
        seaf_warning ("[sync-mgr] Failed to start download: %s\n",
                         error->message);
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_START_FETCH);
        return;
    }
    task->tx_id = tx_id;
    transition_sync_state (task, SYNC_STATE_FETCH);
}

struct MergeResult {
    SyncTask *task;
    gboolean success;
    int merge_status;
    gboolean worktree_dirty;
};

static void *
merge_job (void *vtask)
{
    SyncTask *task = vtask;
    SeafRepo *repo = task->repo;
    char *err_msg = NULL;
    struct MergeResult *res = g_new0 (struct MergeResult, 1);

    res->task = task;

    if (repo->delete_pending) {
        seaf_message ("Repo %s was deleted, don't need to merge.\n", repo->id);
        return res;
    }

    /*
     * 4 types of errors may occur:
     * 1. merge conflicts;
     * 2. fail to checkout a file because the worktree file has been changed;
     * 3. Files are locked on Windows;
     * 4. other I/O errors.
     *
     * For 1, the next commit operation will make worktree clean.
     * For 2 and 4, the errors are ignored by the merge routine (return 0).
     * For 3, just wait another merge retry.
     * */
    if (seaf_repo_merge (repo, "master", &err_msg, &res->merge_status) < 0) {
        seaf_message ("[Sync mgr] Merge of repo %s(%.8s) is not clean.\n",
                   repo->name, repo->id);
        res->success = FALSE;
        g_free (err_msg);
        return res;
    }

    res->success = TRUE;
    g_free (err_msg);
    seaf_message ("[Sync mgr] Merged repo %s(%.8s).\n", repo->name, repo->id);
    return res;
}

static void
merge_job_done (void *vresult)
{
    struct MergeResult *res = vresult;
    SeafRepo *repo = res->task->repo;

    if (repo->delete_pending) {
        transition_sync_state (res->task, SYNC_STATE_CANCELED);
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
        g_free (res);
        return;
    }

    if (res->task->state == SYNC_STATE_CANCEL_PENDING) {
        transition_sync_state (res->task, SYNC_STATE_CANCELED);
        g_free (res);
        return;
    }

    if (res->success) {
        SeafBranch *local;
        SeafBranch *master = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                             repo->id,
                                                             "master");
        if (!master) {
            seaf_warning ("[sync mgr] master branch doesn't exist.\n");
            seaf_sync_manager_set_task_error (res->task, SYNC_ERROR_DATA_CORRUPT);
            goto out;
        }
        /* Save head commit id of master branch for GC, since we've
         * checked out the blocks on the master branch.
         */
        seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                             repo->id,
                                             REPO_REMOTE_HEAD,
                                             master->commit_id);
        seaf_branch_unref (master);

        /* If it's a ff merge, also update REPO_LOCAL_HEAD. */
        switch (res->merge_status) {
        case MERGE_STATUS_FAST_FORWARD:
            local = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                    repo->id,
                                                    "local");
            if (!local) {
                seaf_warning ("[sync mgr] local branch doesn't exist.\n");
                seaf_sync_manager_set_task_error (res->task, SYNC_ERROR_DATA_CORRUPT);
                goto out;
            }

            seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                                 repo->id,
                                                 REPO_LOCAL_HEAD,
                                                 local->commit_id);
            seaf_branch_unref (local);

            transition_sync_state (res->task, SYNC_STATE_DONE);
            break;
        case MERGE_STATUS_REAL_MERGE:
            start_upload_if_necessary (res->task);
            break;
        case MERGE_STATUS_UPTODATE:
            transition_sync_state (res->task, SYNC_STATE_DONE);
            break;
        }
    } else if (res->worktree_dirty)
        seaf_sync_manager_set_task_error (res->task, SYNC_ERROR_WORKTREE_DIRTY);
    else
        seaf_sync_manager_set_task_error (res->task, SYNC_ERROR_MERGE);

out:
    g_free (res);
}

static void
merge_branches_if_necessary (SyncTask *task)
{
    SeafRepo *repo = task->repo;

    /* Repo is not checked out yet. */
    if (!repo->head) {
        transition_sync_state (task, SYNC_STATE_DONE);
        return;
    }
    transition_sync_state (task, SYNC_STATE_MERGE);

    ccnet_job_manager_schedule_job (seaf->job_mgr, 
                                    merge_job, 
                                    merge_job_done,
                                    task);
}

typedef struct {
    char remote_id[41];
    char last_uploaded[41];
    char last_checkout[41];
    gboolean result;
} CheckFFData;

static gboolean
check_fast_forward (SeafCommit *commit, void *vdata, gboolean *stop)
{
    CheckFFData *data = vdata;

    if (strcmp (commit->commit_id, data->remote_id) == 0) {
        *stop = TRUE;
        data->result = TRUE;
        return TRUE;
    }

    if (strcmp (commit->commit_id, data->last_uploaded) == 0 ||
        strcmp (commit->commit_id, data->last_checkout) == 0) {
        *stop = TRUE;
        return TRUE;
    }

    return TRUE;
}

static gboolean
check_fast_forward_with_limit (SeafRepo *repo,
                               const char *local_id,
                               const char *remote_id,
                               const char *last_uploaded,
                               const char *last_checkout,
                               gboolean *error)
{
    CheckFFData data;

    memset (&data, 0, sizeof(data));
    memcpy (data.remote_id, remote_id, 40);
    memcpy (data.last_uploaded, last_uploaded, 40);
    memcpy (data.last_checkout, last_checkout, 40);
    *error = FALSE;

    if (!seaf_commit_manager_traverse_commit_tree_truncated (seaf->commit_mgr,
                                                             repo->id,
                                                             repo->version,
                                                             local_id,
                                                             check_fast_forward,
                                                             &data, FALSE)) {
        seaf_warning ("Failed to traverse commit tree from %s.\n", local_id);
        *error = TRUE;
        return FALSE;
    }

    return data.result;
}

static void
getca_done_cb (CcnetProcessor *processor, gboolean success, void *data)
{
    SyncTask *task = data;
    SyncInfo *info = task->info;
    SeafRepo *repo = task->repo;
    SeafileGetcaProc *proc = (SeafileGetcaProc *)processor;
    SeafBranch *master;

    if (repo->delete_pending) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
        return;
    }

    if (task->state == SYNC_STATE_CANCEL_PENDING) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
        return;
    }

    if (!success) {
        switch (processor->failure) {
        case PROC_NO_SERVICE:
            seaf_warning ("Server doesn't support putca-proc.\n");
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_DEPRECATED_SERVER);
            break;
        case GETCA_PROC_ACCESS_DENIED:
            seaf_warning ("No permission to access repo %.8s.\n", repo->id);
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_ACCESS_DENIED);
            break;
        case GETCA_PROC_NO_CA:
            seaf_warning ("Compute common ancestor failed for %.8s.\n", repo->id);
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_UNKNOWN);
            break;
        case PROC_REMOTE_DEAD:
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_SERVICE_DOWN);
            break;
        case PROC_PERM_ERR:
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_PROC_PERM_ERR);
            break;
        case PROC_DONE:
            /* It can never happen */
            g_return_if_reached ();
        case PROC_BAD_RESP:
        case PROC_NOTSET:
        default:
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_UNKNOWN);
        }
        return;
    }

    seaf_repo_manager_set_common_ancestor (seaf->repo_mgr,
                                           repo->id,
                                           proc->ca_id,
                                           repo->head->commit_id);

    master = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                             info->repo_id,
                                             "master");

    if (!master || strcmp (info->head_commit, master->commit_id) != 0) {
        start_fetch_if_necessary (task);
    } else if (strcmp (repo->head->commit_id, master->commit_id) != 0) {
        /* Try to merge even if we don't need to fetch. */
        merge_branches_if_necessary (task);
    }

    seaf_branch_unref (master);
}

static int
start_get_ca_proc (SyncTask *task, const char *repo_id)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-getca", task->dest_id);
    if (!processor) {
        seaf_warning ("[sync-mgr] failed to create getca proc.\n");
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_UNKNOWN);
        return -1;
    }

    if (ccnet_processor_startl (processor, repo_id, task->token, NULL) < 0) {
        seaf_warning ("[sync-mgr] failed to start getca proc.\n");
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_UNKNOWN);
        return -1;
    }

    g_signal_connect (processor, "done", (GCallback)getca_done_cb, task);
    return 0;
}

/* Return TURE if we started a processor, otherwise return FALSE. */
static gboolean
update_common_ancestor (SyncTask *task,
                        const char *last_uploaded,
                        const char *last_checkout)
{
    SeafRepo *repo = task->repo;
    char *local_head = repo->head->commit_id;
    char ca_id[41], cached_head_id[41];

    /* If common ancestor result is not cached, we need to compute it. */
    if (seaf_repo_manager_get_common_ancestor (seaf->repo_mgr, repo->id,
                                               ca_id, cached_head_id) < 0)
        goto update_common_ancestor;

    /* If the head id is unchanged, use the cached common ancestor id directly.
     * Common ancestor won't change if the local head is not updated.
     */
    if (strcmp (cached_head_id, local_head) == 0) {
        seaf_debug ("Use cached common ancestor.\n");
        return FALSE;
    }

update_common_ancestor:
    if (strcmp (last_uploaded, local_head) == 0 ||
        strcmp (last_checkout, local_head) == 0) {
        seaf_debug ("Use local head as common ancestor.\n");
        seaf_repo_manager_set_common_ancestor (seaf->repo_mgr, repo->id,
                                               local_head, local_head);
        return FALSE;
    }

    start_get_ca_proc (task, repo->id);
    return TRUE;
}

static gboolean
repo_block_store_exists (SeafRepo *repo)
{
    gboolean ret;
    char *store_path = g_build_filename (seaf->seaf_dir, "storage", "blocks",
                                         repo->id, NULL);
    if (g_file_test (store_path, G_FILE_TEST_IS_DIR))
        ret = TRUE;
    else
        ret = FALSE;
    g_free (store_path);
    return ret;
}

static void *
remove_repo_blocks (void *vtask)
{
    SyncTask *task = vtask;

    seaf_block_manager_remove_store (seaf->block_mgr, task->repo->id);

    return vtask;
}

static void
remove_blocks_done (void *vtask)
{
    SyncTask *task = vtask;

    transition_sync_state (task, SYNC_STATE_DONE);
}

static void
update_sync_status (SyncTask *task)
{
    SyncInfo *info = task->info;
    SeafRepo *repo = task->repo;
    SeafBranch *master, *local;
    char *last_uploaded = NULL, *last_checkout = NULL;

    local = seaf_branch_manager_get_branch (
        seaf->branch_mgr, info->repo_id, "local");
    if (!local) {
        seaf_warning ("[sync-mgr] Branch local not found for repo %s(%.8s).\n",
                   repo->name, repo->id);
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_DATA_CORRUPT);
        return;
    }
    master = seaf_branch_manager_get_branch (
        seaf->branch_mgr, info->repo_id, "master");

    last_uploaded = seaf_repo_manager_get_repo_property (seaf->repo_mgr,
                                                         repo->id,
                                                         REPO_LOCAL_HEAD);
    if (!last_uploaded) {
        seaf_warning ("Last uploaded commit id is not found in db.\n");
        seaf_branch_unref (local);
        seaf_branch_unref (master);
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_DATA_CORRUPT);
        return;
    }

    last_checkout = seaf_repo_manager_get_repo_property (seaf->repo_mgr,
                                                         repo->id,
                                                         REPO_REMOTE_HEAD);
    if (!last_checkout) {
        seaf_warning ("Last checked out commit id is not found in db.\n");
        seaf_branch_unref (local);
        seaf_branch_unref (master);
        g_free (last_uploaded);
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_DATA_CORRUPT);
        return;
    }

    if (info->repo_corrupted) {
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_REPO_CORRUPT);
    } else if (info->deleted_on_relay) {
        /* First upload. */
        if (!master)
            start_upload_if_necessary (task);
        /* If repo doesn't exist on relay and we have "master",
         * it was deleted on relay. In this case we remove this repo.
         */
        else {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_NOREPO);
            seaf_debug ("remove repo %s(%.8s) since it's deleted on relay\n",
                        repo->name, repo->id);
            seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                                  "repo.deleted_on_relay",
                                                  repo->name);
            seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
        }
    } else {
        /* branch deleted on relay */
        if (info->branch_deleted_on_relay) {
            start_upload_if_necessary (task);
            goto out;
        }

        /* If local head is the same as remote head, already in sync. */
        if (strcmp (local->commit_id, info->head_commit) == 0) {
            /* As long as the repo is synced with the server. All the local
             * blocks are not useful any more.
             */
            if (repo_block_store_exists (repo)) {
                seaf_message ("Removing blocks for repo %s(%.8s).\n",
                              repo->name, repo->id);
                ccnet_job_manager_schedule_job (seaf->job_mgr,
                                                remove_repo_blocks,
                                                remove_blocks_done,
                                                task);
            } else
                transition_sync_state (task, SYNC_STATE_DONE);
            goto out;
        }

        /* This checking is done in the main thread. But it usually doesn't take
         * much time, because the traversing is limited by last_uploaded and
         * last_checkout commits.
         */
        gboolean error = FALSE;
        gboolean is_ff = check_fast_forward_with_limit (repo,
                                                        local->commit_id,
                                                        info->head_commit,
                                                        last_uploaded,
                                                        last_checkout,
                                                        &error);
        if (error) {
            seaf_warning ("Failed to check fast forward.\n");
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_DATA_CORRUPT);
            goto out;
        }

        /* fast-forward upload */
        if (is_ff) {
            start_upload_if_necessary (task);
            goto out;
        }

        /*
         * We have to compute the common ancestor before doing merge.
         * The last result of computation is cached in local db.
         * Check if we need to re-compute the common ancestor.
         * If so we'll start a processor to do that on the server.
         * For repo version == 0, we download all commits so there is no
         * need to check.
         */
        if (repo->version > 0 &&
            update_common_ancestor (task, last_uploaded, last_checkout))
            goto out;

        if (!master || strcmp (info->head_commit, master->commit_id) != 0) {
            start_fetch_if_necessary (task);
        } else if (strcmp (local->commit_id, master->commit_id) != 0) {
            /* Try to merge even if we don't need to fetch. */
            merge_branches_if_necessary (task);
        }
    }

out:
    seaf_branch_unref (local);
    if (master)
        seaf_branch_unref (master);
    g_free (last_uploaded);
    g_free (last_checkout);
}

static void
update_sync_status_v2 (SyncTask *task)
{
    SyncInfo *info = task->info;
    SeafRepo *repo = task->repo;
    SeafBranch *master = NULL, *local = NULL;

    local = seaf_branch_manager_get_branch (
        seaf->branch_mgr, info->repo_id, "local");
    if (!local) {
        seaf_warning ("[sync-mgr] Branch local not found for repo %s(%.8s).\n",
                   repo->name, repo->id);
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_DATA_CORRUPT);
        return;
    }

    master = seaf_branch_manager_get_branch (
        seaf->branch_mgr, info->repo_id, "master");
    if (!master) {
        seaf_warning ("[sync-mgr] Branch master not found for repo %s(%.8s).\n",
                   repo->name, repo->id);
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_DATA_CORRUPT);
        return;
    }

    if (info->repo_corrupted) {
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_REPO_CORRUPT);
    } else if (info->deleted_on_relay) {
        /* If repo doesn't exist on relay and we have "master",
         * it was deleted on relay. In this case we remove this repo.
         */
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_NOREPO);
        seaf_debug ("remove repo %s(%.8s) since it's deleted on relay\n",
                    repo->name, repo->id);
        seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                              "repo.deleted_on_relay",
                                              repo->name);
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
    } else {
        /* If local head is the same as remote head, already in sync. */
        if (strcmp (local->commit_id, info->head_commit) == 0) {
            /* As long as the repo is synced with the server. All the local
             * blocks are not useful any more.
             */
            if (repo_block_store_exists (repo)) {
                seaf_message ("Removing blocks for repo %s(%.8s).\n",
                              repo->name, repo->id);
                ccnet_job_manager_schedule_job (seaf->job_mgr,
                                                remove_repo_blocks,
                                                remove_blocks_done,
                                                task);
            } else
                transition_sync_state (task, SYNC_STATE_DONE);
        } else
            start_fetch_if_necessary (task);
    }

    seaf_branch_unref (local);
    seaf_branch_unref (master);
}

static void
sync_done_cb (CcnetProcessor *processor, gboolean success, void *data)
{
    SyncTask *task = data;
    SeafRepo *repo = task->repo;

    if (repo->delete_pending) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
        return;
    }

    if (task->state == SYNC_STATE_CANCEL_PENDING) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
        return;
    }

    if (!success) {
        switch (processor->failure) {
        case PROC_DONE:
            /* It can never happen */
            g_return_if_reached ();
        case PROC_REMOTE_DEAD:
        case PROC_NO_SERVICE:
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_SERVICE_DOWN);
            break;
        case PROC_PERM_ERR:
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_PROC_PERM_ERR);
            break;
        case PROC_BAD_RESP:
        case PROC_NOTSET:
        default:
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_UNKNOWN);
        }
        return;
    }

    if (!task->server_side_merge)
        update_sync_status (task);
    else
        update_sync_status_v2 (task);
}

static int
start_sync_repo_proc (SeafSyncManager *manager, SyncTask *task)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-sync-repo", task->dest_id);
    if (!processor) {
        seaf_warning ("[sync-mgr] failed to create get seafile-sync-repo proc.\n");
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_UNKNOWN);
        return -1;
    }
    ((SeafileSyncRepoProc *)processor)->task = task;

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("[sync-mgr] failed to start get seafile-sync-repo proc.\n");
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_UNKNOWN);
        return -1;
    }

    g_signal_connect (processor, "done", (GCallback)sync_done_cb, task);

    transition_sync_state (task, SYNC_STATE_INIT);

    return 0;
}

struct CommitResult {
    SyncTask *task;
    gboolean changed;
    gboolean success;
};

static void *
commit_job (void *vtask)
{
    SyncTask *task = vtask;
    SeafRepo *repo = task->repo;
    struct CommitResult *res = g_new0 (struct CommitResult, 1);
    GError *error = NULL;

    res->task = task;

    if (repo->delete_pending)
        return res;

    res->changed = TRUE;
    res->success = TRUE;

    char *commit_id = seaf_repo_index_commit (repo, "", task->is_initial_commit,
                                              &error);
    if (commit_id == NULL && error != NULL) {
        seaf_warning ("[Sync mgr] Failed to commit to repo %s(%.8s).\n",
                      repo->name, repo->id);
        res->success = FALSE;
    } else if (commit_id == NULL) {
        res->changed = FALSE;
    }
    g_free (commit_id);

    return res;
}

static void
commit_job_done (void *vres)
{
    struct CommitResult *res = vres;
    SeafRepo *repo = res->task->repo;
    SyncTask *task = res->task;

    res->task->mgr->commit_job_running = FALSE;

    if (repo->delete_pending) {
        transition_sync_state (res->task, SYNC_STATE_CANCELED);
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
        g_free (res);
        return;
    }

    if (res->task->state == SYNC_STATE_CANCEL_PENDING) {
        transition_sync_state (res->task, SYNC_STATE_CANCELED);
        g_free (res);
        return;
    }

    if (!res->success) {
        seaf_sync_manager_set_task_error (res->task, SYNC_ERROR_COMMIT);
        g_free (res);
        return;
    }

    if (!res->task->server_side_merge) {
        /* If nothing committed and is not manual sync, no need to sync. */
        if (!res->changed &&
            !res->task->is_manual_sync && !res->task->is_initial_commit) {
            transition_sync_state (res->task, SYNC_STATE_DONE);
            g_free (res);
            return;
        }
        start_sync_repo_proc (res->task->mgr, res->task);
    } else {
        if (res->changed)
            start_upload_if_necessary (res->task);
        else if (task->is_manual_sync || task->is_initial_commit)
            start_sync_repo_proc (task->mgr, task);
        else
            transition_sync_state (task, SYNC_STATE_DONE);
    }

    g_free (res);
}

static int check_commit_state (void *data);

static void
commit_repo (SyncTask *task)
{
    /* In order not to eat too much CPU power, only one commit job can be run
     * at the same time. Other sync tasks have to check every 1 second.
     */
    if (task->mgr->commit_job_running) {
        task->commit_timer = ccnet_timer_new (check_commit_state, task, 1000);
        return;
    }

    task->mgr->commit_job_running = TRUE;

    transition_sync_state (task, SYNC_STATE_COMMIT);

    ccnet_job_manager_schedule_job (seaf->job_mgr, 
                                    commit_job, 
                                    commit_job_done,
                                    task);
}

static int
check_commit_state (void *data)
{
    SyncTask *task = data;

    if (!task->mgr->commit_job_running) {
        ccnet_timer_free (&task->commit_timer);
        commit_repo (task);
        return 0;
    }

    return 1;
}

static void
start_sync (SeafSyncManager *manager, SeafRepo *repo,
            gboolean need_commit, gboolean is_manual_sync,
            gboolean is_initial_commit)
{
    SyncTask *task = g_new0 (SyncTask, 1);
    SyncInfo *info;

    info = get_sync_info (manager, repo->id);

    task->info = info;
    task->mgr = manager;

    task->dest_id = g_strdup(repo->relay_id);
    task->token = g_strdup(repo->token);
    task->is_manual_sync = is_manual_sync;
    task->is_initial_commit = is_initial_commit;

    repo->last_sync_time = time(NULL);
    ++(manager->n_running_tasks);

    /* Free the last task when a new task is started.
     * This way we can always get the state of the last task even
     * after it's done.
     */
    if (task->info->current_task)
        sync_task_free (task->info->current_task);
    task->info->current_task = task;
    task->info->in_sync = TRUE;
    task->repo = repo;

    if (need_commit) {
        repo->create_partial_commit = FALSE;
        commit_repo (task);
    } else
        start_sync_repo_proc (manager, task);
}

static int
sync_repo (SeafSyncManager *manager, SeafRepo *repo)
{
    WTStatus *status;
    gint now = (gint)time(NULL);
    gint last_changed;

    status = seaf_wt_monitor_get_worktree_status (manager->seaf->wt_monitor,
                                                  repo->id);
    if (status) {
        last_changed = g_atomic_int_get (&status->last_changed);
        if (status->last_check == 0) {
            /* Force commit and sync after a new repo is added. */
            start_sync (manager, repo, TRUE, FALSE, TRUE);
            status->last_check = now;
            wt_status_unref (status);
            return 0;
        } else if (last_changed != 0 && status->last_check <= last_changed) {
            /* Commit and sync if the repo has been updated after the
             * last check and is not updated for the last 2 seconds.
             */
            if (now - last_changed >= 2) {
                start_sync (manager, repo, TRUE, FALSE, FALSE);
                status->last_check = now;
                wt_status_unref (status);
                return 0;
            }
        }
        wt_status_unref (status);
    }

    if (manager->n_running_tasks >= MAX_RUNNING_SYNC_TASKS)
        return -1;

    if (repo->last_sync_time > now - manager->sync_interval)
        return -1;

    start_sync (manager, repo, FALSE, FALSE, FALSE);

    return 0;
}

static SyncTask *
create_sync_task_v2 (SeafSyncManager *manager, SeafRepo *repo,
                     gboolean is_manual_sync, gboolean is_initial_commit)
{
    SyncTask *task = g_new0 (SyncTask, 1);
    SyncInfo *info;

    info = get_sync_info (manager, repo->id);

    task->info = info;
    task->mgr = manager;

    task->dest_id = g_strdup (repo->relay_id);
    task->token = g_strdup(repo->token);
    task->is_manual_sync = is_manual_sync;
    task->is_initial_commit = is_initial_commit;
    task->server_side_merge = TRUE;

    repo->last_sync_time = time(NULL);
    ++(manager->n_running_tasks);

    /* Free the last task when a new task is started.
     * This way we can always get the state of the last task even
     * after it's done.
     */
    if (task->info->current_task)
        sync_task_free (task->info->current_task);
    task->info->current_task = task;
    task->info->in_sync = TRUE;
    task->repo = repo;

    return task;
}

static gboolean
create_commit_from_event_queue (SeafSyncManager *manager, SeafRepo *repo,
                                gboolean is_manual_sync)
{
    WTStatus *status;
    SyncTask *task;
    gboolean ret = FALSE;
    gint now = (gint)time(NULL);
    gint last_changed;

    status = seaf_wt_monitor_get_worktree_status (manager->seaf->wt_monitor,
                                                  repo->id);
    if (status) {
        last_changed = g_atomic_int_get (&status->last_changed);
        if (status->last_check == 0) {
            /* Force commit and sync after a new repo is added. */
            task = create_sync_task_v2 (manager, repo, is_manual_sync, TRUE);
            repo->create_partial_commit = TRUE;
            commit_repo (task);
            status->last_check = now;
            ret = TRUE;
        } else if (last_changed != 0 && status->last_check <= last_changed) {
            /* Commit and sync if the repo has been updated after the
             * last check and is not updated for the last 2 seconds.
             */
            if (now - last_changed >= 2) {
                task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
                repo->create_partial_commit = TRUE;
                commit_repo (task);
                status->last_check = now;
                ret = TRUE;
            }
        } else if (status->last_event != NULL) {
            task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
            repo->create_partial_commit = TRUE;
            commit_repo (task);
            ret = TRUE;
        }
        wt_status_unref (status);
    }

    return ret;
}

static int
sync_repo_v2 (SeafSyncManager *manager, SeafRepo *repo, gboolean is_manual_sync)
{
    SeafBranch *master, *local;
    int now = (int)time(NULL);
    SyncTask *task;
    int ret = 0;
    char *last_download = NULL;

    master = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "master");
    if (!master) {
        seaf_warning ("No master branch found for repo %s(%.8s).\n",
                      repo->name, repo->id);
        return -1;
    }
    local = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "local");
    if (!local) {
        seaf_warning ("No local branch found for repo %s(%.8s).\n",
                      repo->name, repo->id);
        return -1;
    }

    /* If last download was interrupted in the fetch and download stage,
     * need to resume it at exactly the same remote commit.
     */
    last_download = seaf_repo_manager_get_repo_property (seaf->repo_mgr,
                                                         repo->id,
                                                         REPO_PROP_DOWNLOAD_HEAD);
    if (last_download && strcmp (last_download, EMPTY_SHA1) != 0) {
        task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
        start_fetch_if_necessary (task);
        goto out;
    }

    if (strcmp (master->commit_id, local->commit_id) != 0) {
        if ((repo->last_sync_time == 0 ||
             repo->last_sync_time < now - manager->sync_interval) &&
            manager->n_running_tasks < MAX_RUNNING_SYNC_TASKS) {
            task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
            start_upload_if_necessary (task);
        }
        /* Do nothing if the client still has something to upload
         * but it's before 30-second schedule.
         */
        goto out;
    } else if (create_commit_from_event_queue (manager, repo, is_manual_sync))
        goto out;

    if ((repo->last_sync_time == 0 ||
         repo->last_sync_time < now - manager->sync_interval) &&
        manager->n_running_tasks < MAX_RUNNING_SYNC_TASKS) {
        task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
        start_sync_repo_proc (manager, task);
    }

out:
    g_free (last_download);
    seaf_branch_unref (master);
    seaf_branch_unref (local);
    return ret;
}

static void
auto_delete_repo (SeafSyncManager *manager, SeafRepo *repo)
{
    SyncInfo *info = seaf_sync_manager_get_sync_info (manager, repo->id);
    char *name = g_strdup (repo->name);

    seaf_message ("Auto deleted repo '%s'.\n", repo->name);

    if (info != NULL && info->in_sync) {
        seaf_repo_manager_mark_repo_deleted (seaf->repo_mgr, repo);
    } else {
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
    }

    /* Publish a message, for applet to notify in the system tray */
    seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                          "repo.removed",
                                          name);
    g_free (name);
}

static void
check_protocol_done_cb (CcnetProcessor *processor, gboolean success, void *data)
{
    ServerState *state = data;

    state->checking = FALSE;
    if (success)
        state->server_side_merge = SERVER_SIDE_MERGE_SUPPORTED;
    else if (processor->failure == PROC_NO_SERVICE)
        /* Talking to an old server. */
        state->server_side_merge = SERVER_SIDE_MERGE_UNSUPPORTED;
}

static int
start_check_protocol_proc (SeafSyncManager *manager,
                           const char *peer_id, ServerState *state)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-check-protocol", peer_id);
    if (!processor) {
        seaf_warning ("[sync-mgr] failed to create get seafile-check-protocol proc.\n");
        return -1;
    }

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("[sync-mgr] failed to start seafile-check-protocol proc.\n");
        return -1;
    }

    g_signal_connect (processor, "done", (GCallback)check_protocol_done_cb, state);

    return 0;
}

static gboolean
check_relay_status (SeafSyncManager *mgr, SeafRepo *repo)
{
    gboolean is_ready = ccnet_peer_is_ready (seaf->ccnetrpc_client, repo->relay_id);

    ServerState *state = g_hash_table_lookup (mgr->server_states, repo->relay_id);
    if (!state) {
        state = g_new0 (ServerState, 1);
        g_hash_table_insert (mgr->server_states, g_strdup(repo->relay_id), state);
    }

    if (is_ready) {
        if (state->server_side_merge == SERVER_SIDE_MERGE_UNKNOWN) {
            if (!state->checking) {
                start_check_protocol_proc (mgr, repo->relay_id, state);
                state->checking = TRUE;
            }
            return FALSE;
        } else
            return TRUE;
    } else {
        if (state->server_side_merge == SERVER_SIDE_MERGE_UNKNOWN)
            return FALSE;
        else {
            /* Reset protocol_version to unknown so that we'll check it
             * after the server is up again. */
            state->server_side_merge = SERVER_SIDE_MERGE_UNKNOWN;
            return FALSE;
        }
    }
}

/*
 * If the user upgarde from 3.0.x, there may be more than one commit to upload
 * on the local branch. The new syncing protocol can't handle more than one
 * commit. So if we detect this case, fall back to old protocol.
 * After the repo is synced this time, we can use new protocol in the future.
 */
static gboolean
has_old_commits_to_upload (SeafRepo *repo)
{
    SeafBranch *master = NULL, *local = NULL;
    SeafCommit *head = NULL;
    gboolean ret = TRUE;

    master = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "master");
    if (!master) {
        seaf_warning ("No master branch found for repo %s(%.8s).\n",
                      repo->name, repo->id);
        goto out;
    }
    local = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "local");
    if (!local) {
        seaf_warning ("No local branch found for repo %s(%.8s).\n",
                      repo->name, repo->id);
        goto out;
    }

    if (strcmp (local->commit_id, master->commit_id) == 0) {
        ret = FALSE;
        goto out;
    }

    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id, repo->version,
                                           local->commit_id);
    if (!head) {
        seaf_warning ("Failed to get head commit of repo %s(%.8s).\n",
                      repo->name, repo->id);
        goto out;
    }

    if (head->second_parent_id == NULL &&
        g_strcmp0 (head->parent_id, master->commit_id) == 0)
        ret = FALSE;

out:
    seaf_branch_unref (master);
    seaf_branch_unref (local);
    seaf_commit_unref (head);
    return ret;
}

gint
cmp_repos_by_sync_time (gconstpointer a, gconstpointer b, gpointer user_data)
{
    const SeafRepo *repo_a = a;
    const SeafRepo *repo_b = b;

    return (repo_a->last_sync_time - repo_b->last_sync_time);
}

static int
auto_sync_pulse (void *vmanager)
{
    SeafSyncManager *manager = vmanager;
    GList *repos, *ptr;
    SeafRepo *repo;

    repos = seaf_repo_manager_get_repo_list (manager->seaf->repo_mgr, -1, -1);

    /* Sort repos by last_sync_time, so that we don't "starve" any repo. */
    repos = g_list_sort_with_data (repos, cmp_repos_by_sync_time, NULL);

    for (ptr = repos; ptr != NULL; ptr = ptr->next) {
        repo = ptr->data;

        /* Every second, we'll check the worktree to see if it still exists.
         * We'll invalidate worktree if it gets moved or deleted.
         * But there is a hole here: If the user delete the worktree dir and
         * recreate a dir with the same name within a second, we'll falsely
         * see the worktree as valid. What's worse, the new worktree dir won't
         * be monitored.
         * This problem can only be solved by restart.
         */
        /* If repo has been checked out and the worktree doesn't exist,
         * we'll delete the repo automatically.
         */

        if (repo->head != NULL) {
            if (seaf_repo_check_worktree (repo) < 0) {
                if (!repo->worktree_invalid) {
                    // The repo worktree was valid, but now it's invalid
                    seaf_repo_manager_invalidate_repo_worktree (seaf->repo_mgr, repo);
                    if (!seafile_session_config_get_allow_invalid_worktree(seaf)) {
                        auto_delete_repo (manager, repo);
                    }
                }
                continue;
            } else {
                if (repo->worktree_invalid) {
                    // The repo worktree was invalid, but now it's valid again,
                    // so we start watch it
                    seaf_repo_manager_validate_repo_worktree (seaf->repo_mgr, repo);
                    continue;
                }
            }
        }

        repo->worktree_invalid = FALSE;

        if (repo->delete_pending) {
            seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
            continue;
        }

        if (!manager->priv->auto_sync_enabled || !repo->auto_sync)
            continue;

        /* If relay is not ready or protocol version is not determined,
         * need to wait.
         */
        if (!check_relay_status (manager, repo))
            continue;

        SyncInfo *info = get_sync_info (manager, repo->id);

        if (info->in_sync)
            continue;

        ServerState *state = g_hash_table_lookup (manager->server_states,
                                                  repo->relay_id);

        if (repo->version == 0 ||
            state->server_side_merge == SERVER_SIDE_MERGE_UNSUPPORTED ||
            has_old_commits_to_upload (repo))
            sync_repo (manager, repo);
        else if (state->server_side_merge == SERVER_SIDE_MERGE_SUPPORTED)
            sync_repo_v2 (manager, repo, FALSE);
    }

    g_list_free (repos);
    return TRUE;
}

inline static void
send_sync_error_notification (SeafRepo *repo, const char *type)
{
    GString *buf = g_string_new (NULL);
    g_string_append_printf (buf, "%s\t%s", repo->name, repo->id);
    seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                          type,
                                          buf->str);
    g_string_free (buf, TRUE);
}

static void
on_repo_fetched (SeafileSession *seaf,
                 TransferTask *tx_task,
                 SeafSyncManager *manager)
{
    SyncInfo *info = get_sync_info (manager, tx_task->repo_id);
    SyncTask *task = info->current_task;

    /* Clone tasks are handled by clone manager. */
    if (tx_task->is_clone)
        return;

    if (task->repo->delete_pending) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
        seaf_repo_manager_del_repo (seaf->repo_mgr, task->repo);
        return;
    }

    if (tx_task->state == TASK_STATE_FINISHED) {
        memcpy (info->head_commit, tx_task->head, 41);

        if (!task->server_side_merge)
            merge_branches_if_necessary (task);
        else
            transition_sync_state (task, SYNC_STATE_DONE);
    } else if (tx_task->state == TASK_STATE_CANCELED) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
    } else if (tx_task->state == TASK_STATE_ERROR) {
        if (tx_task->error == TASK_ERR_ACCESS_DENIED) {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_ACCESS_DENIED);
            if (!task->repo->access_denied_notified) {
                send_sync_error_notification (task->repo, "sync.access_denied");
                task->repo->access_denied_notified = 1;
            }
        } else
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_FETCH);
    }
}

static void
on_repo_uploaded (SeafileSession *seaf,
                  TransferTask *tx_task,
                  SeafSyncManager *manager)
{
    SyncInfo *info = get_sync_info (manager, tx_task->repo_id);
    SyncTask *task = info->current_task;

    g_return_if_fail (task != NULL && info->in_sync);

    if (task->repo->delete_pending) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
        seaf_repo_manager_del_repo (seaf->repo_mgr, task->repo);
        return;
    }

    if (tx_task->state == TASK_STATE_FINISHED) {
        memcpy (info->head_commit, tx_task->head, 41);

        /* Save current head commit id for GC. */
        seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                             task->repo->id,
                                             REPO_LOCAL_HEAD,
                                             task->repo->head->commit_id);
        if (!task->server_side_merge)
            transition_sync_state (task, SYNC_STATE_DONE);
        else
            start_sync_repo_proc (manager, task);
    } else if (tx_task->state == TASK_STATE_CANCELED) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
    } else if (tx_task->state == TASK_STATE_ERROR) {
        if (tx_task->error == TASK_ERR_ACCESS_DENIED) {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_ACCESS_DENIED);
            if (!task->repo->access_denied_notified) {
                send_sync_error_notification (task->repo, "sync.access_denied");
                task->repo->access_denied_notified = 1;
            }
        } else if (tx_task->error == TASK_ERR_QUOTA_FULL) {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_QUOTA_FULL);
            /* Only notify "quota full" once. */
            if (!task->repo->quota_full_notified) {
                send_sync_error_notification (task->repo, "sync.quota_full");
                task->repo->quota_full_notified = 1;
            }
        } else
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_UPLOAD);
    }
}


const char *
sync_error_to_str (int error)
{
    if (error < 0 || error >= SYNC_ERROR_NUM) {
        seaf_warning ("illegal sync error: %d\n", error); 
        return NULL;
    }

    return sync_error_str[error];
}

const char *
sync_state_to_str (int state)
{
    if (state < 0 || state >= SYNC_STATE_NUM) {
        seaf_warning ("illegal sync state: %d\n", state); 
        return NULL;
    }

    return sync_state_str[state];
}

static void
cancel_all_sync_tasks (SeafSyncManager *mgr)
{
    GList *repos;
    GList *ptr;
    SeafRepo *repo;

    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    for (ptr = repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        seaf_sync_manager_cancel_sync_task (mgr, repo->id);
    }

    g_list_free (repos);
}

int
seaf_sync_manager_disable_auto_sync (SeafSyncManager *mgr)
{
    if (!seaf->started) {
        seaf_message ("sync manager is not started, skip disable auto sync.\n");
        return -1;
    }

    cancel_all_sync_tasks (mgr);
    mgr->priv->auto_sync_enabled = FALSE;
    g_debug ("[sync mgr] auto sync is disabled\n");
    return 0;
}

#if 0
static void
add_sync_tasks_for_all (SeafSyncManager *mgr)
{
    GList *repos, *ptr;
    SeafRepo *repo;

    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    for (ptr = repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        if (!repo->auto_sync)
            continue;

        if (repo->worktree_invalid)
            continue;
        
        start_sync (mgr, repo, TRUE, FALSE, TRUE);
    }

    g_list_free (repos);
}
#endif

int
seaf_sync_manager_enable_auto_sync (SeafSyncManager *mgr)
{
    if (!seaf->started) {
        seaf_message ("sync manager is not started, skip enable auto sync.\n");
        return -1;
    }

    /* add_sync_tasks_for_all (mgr); */
    mgr->priv->auto_sync_enabled = TRUE;
    g_debug ("[sync mgr] auto sync is enabled\n");
    return 0;
}

int
seaf_sync_manager_is_auto_sync_enabled (SeafSyncManager *mgr)
{
    if (mgr->priv->auto_sync_enabled)
        return 1;
    else
        return 0;
}
