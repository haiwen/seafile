/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */


#include "common.h"

#include <ccnet.h>

#include "db.h"
#include "seafile-session.h"
#include "seafile-config.h"
#include "sync-mgr.h"
#include "transfer-mgr.h"
#include "processors/sync-repo-proc.h"
#include "processors/notifysync-proc.h"
#include "processors/getrepoemailtoken-proc.h"
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

#define DEFAULT_WORKTREE_INTERVAL 600 /* 10 minutes */

#define CHECK_COMMIT_INTERVAL   1000 /* 1s */

struct _SeafSyncManagerPriv {
    struct CcnetTimer *check_sync_timer;
    int    pulse_count;

    /* When FALSE, auto sync is globally disabled */
    gboolean   auto_sync_enabled;

    struct CcnetTimer *check_commit_timer;
    GHashTable *get_email_token_hash; /* repo_id -> failed */
};

static int
try_get_repo_email_token (SeafSyncManager *mgr,
                          SyncTask *task);

static int
perform_sync_task (SeafSyncManager *manager, SyncTask *task);
static int check_sync_pulse (void *vmanager);
static int auto_commit_pulse (void *vmanager);
static void on_repo_fetched (SeafileSession *seaf,
                             TransferTask *tx_task,
                             SeafSyncManager *manager);
static void on_repo_uploaded (SeafileSession *seaf,
                              TransferTask *tx_task,
                              SeafSyncManager *manager);
static inline void
transition_sync_state (SyncTask *task, int new_state);

static gint compare_sync_task (gconstpointer a, gconstpointer b);
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
    mgr->sync_tasks = g_queue_new ();

    mgr->wt_interval = DEFAULT_WORKTREE_INTERVAL;

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
    mgr->priv->get_email_token_hash = g_hash_table_new_full (
        g_str_hash, g_str_equal, NULL, NULL);

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
        check_sync_pulse, mgr, CHECK_SYNC_INTERVAL);

    mgr->priv->check_commit_timer = ccnet_timer_new (
        auto_commit_pulse, mgr, CHECK_COMMIT_INTERVAL);

    ccnet_proc_factory_register_processor (mgr->seaf->session->proc_factory,
                                           "seafile-sync-repo",
                                           SEAFILE_TYPE_SYNC_REPO_PROC);
    ccnet_proc_factory_register_processor (mgr->seaf->session->proc_factory,
                                           "seafile-notifysync",
                                           SEAFILE_TYPE_NOTIFYSYNC_PROC);
    ccnet_proc_factory_register_processor (mgr->seaf->session->proc_factory,
                                           "seafile-get-repo-email-token",
                                           SEAFILE_TYPE_GETREPOEMAILTOKEN_PROC);
    g_signal_connect (seaf, "repo-fetched",
                      (GCallback)on_repo_fetched, mgr);
    g_signal_connect (seaf, "repo-uploaded",
                      (GCallback)on_repo_uploaded, mgr);

    return 0;
}

int
seaf_sync_manager_add_sync_task (SeafSyncManager *mgr,
                                 const char *repo_id,
                                 const char *dest_id,
                                 const char *token,
                                 gboolean is_sync_lan,
                                 GError **error)
{
    if (!seaf->started) {
        seaf_message ("sync manager is not started, skip sync request.\n");
        return -1;
    }

    SyncInfo *info = get_sync_info (mgr, repo_id);
    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("[sync mgr] cannot find repo %s.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "Invalid repo");
        return -1;
    }

    if (!peer_id_valid(dest_id)) {
        if (is_sync_lan) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_PEER_ID,
                         "Dest ID is missing");
            return -1;
        } else {
            if (repo->relay_id)
                dest_id = repo->relay_id;
            /* else if (seaf->session->base.relay_id) */
            /*     dest_id = seaf->session->base.relay_id; */
            else {
                g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                             "Unknown Destination");
                return -1;
            }
        }
    }

    if (strlen(dest_id) != 40) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_PEER_ID,
                     "Dest ID is invalid");
        return -1;
    }

    if (seaf_repo_check_worktree (repo) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_NO_WORKTREE,
                     "Worktree doesn't exist");
        return -1;
    }

    if (info->in_sync)
        return 0;

    /* Run the sync task immediately, without adding to the queue. */
    SyncTask *task = g_new0 (SyncTask, 1);

    task->info = info;
    task->mgr = mgr;

    task->dest_id = g_strdup (dest_id);
    task->force_upload = TRUE;
    task->is_sync_lan = is_sync_lan;
    task->need_commit = TRUE;

    if (task->is_sync_lan) {
        if (token)
            task->token = g_strdup (token);
        else
            task->token = g_strdup (DEFAULT_REPO_TOKEN);
    } else {
        if (token)
            task->token = g_strdup (token);
        else {
            task->token = g_strdup(repo->token);
        }
    }

    perform_sync_task (mgr, task);

    return 0;
}

void
seaf_sync_manager_cancel_sync_task (SeafSyncManager *mgr,
                                    const char *repo_id)
{
    SyncInfo *info;
    SyncTask *task;
    GList *link;

    if (!seaf->started) {
        seaf_message ("sync manager is not started, skip cancel request.\n");
        return;
    }

    /* Cancel any pending tasks for this repo on the queue. */
    link = g_queue_find_custom (mgr->sync_tasks,
                                repo_id, compare_sync_task);
    if (link) {
        task = link->data;
        sync_task_free (task);
        g_queue_delete_link (mgr->sync_tasks, link);
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

#if 0
int
seaf_sync_manager_notify_peer_sync (SeafSyncManager *mgr,
                                    const char *repo_id,
                                    const char *peer_id,
                                    GError **error)
{
    CcnetProcessor *processor;
    char *token;

    if (!repo_id || !peer_id) {
        return -1;
    }

    token = seaf_repo_manager_generate_tmp_token (seaf->repo_mgr,
                                                  repo_id, peer_id);
    if (!token) {
        seaf_warning ("[sync-mgr] failed to generate tmp token for repo %s.\n",
                      repo_id);
        return -1;
    }
    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-notifysync", peer_id);
    if (!processor) {
        seaf_warning ("[sync-mgr] failed to create get seafile-notifysync proc.\n");
        return -1;
    }

    if (ccnet_processor_startl (processor, repo_id, token, NULL) < 0) {
        seaf_warning ("[sync-mgr] failed to start get seafile-notifysync proc.\n");
        g_free (token);
        return -1;
    }

    seaf_debug ("[sync-mgr] Notify peer %s sync repo %s in lan\n",
                peer_id, repo_id);
    g_free (token);
    return 0;
}
#endif

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

static inline void
transition_sync_state (SyncTask *task, int new_state)
{
    g_return_if_fail (new_state >= 0 && new_state < SYNC_STATE_NUM);

    if (task->state != new_state) {
        if (!task->quiet &&
            !(task->state == SYNC_STATE_DONE && new_state == SYNC_STATE_INIT) &&
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
            SeafCommit *head;
            head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                   task->repo->head->commit_id);
            if (head) {
                GString *buf = g_string_new (NULL);
                g_string_append_printf (buf, "%s\t%s\t%s",
                                        task->repo->name,
                                        task->repo->id,
                                        head->desc);
                seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                                      "sync.done",
                                                      buf->str);
                g_string_free (buf, TRUE);
                seaf_commit_unref (head);
            }
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
    "You do not have permission to access this repo",
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
                                                    task->dest_id,
                                                    "local",
                                                    "master",
                                                    task->token,
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
                                                task->dest_id,
                                                "fetch_head",
                                                "master",
                                                task->token,
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
    gboolean real_merge;
    gboolean worktree_dirty;
};

static int
fix_dirty_worktree (SeafRepo *repo)
{
    char *commit_id;
    GError *error = NULL;

    commit_id = seaf_repo_index_commit (repo, "", &error);
    if (error != NULL) {
        seaf_warning ("Failed to commit unclean worktree.\n");
        g_error_free (error);
        return -1;
    }
    g_free (commit_id);

    /* After commit, the worktree should be clean. */
    if (seaf_repo_is_worktree_changed (repo)) {
        seaf_warning ("Worktree is still dirty after commit.\n");
        return -1;
    }

    return 0;
}

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

    pthread_mutex_lock (&repo->lock);

    /* Try to commit if worktree is not clean. */
    if (seaf_repo_is_worktree_changed (repo) && fix_dirty_worktree (repo) < 0) {
        seaf_message ("[sync mgr] Worktree is not clean. Skip merging repo %s(%.8s).\n",
                   repo->name, repo->id);
        res->success = FALSE;
        res->worktree_dirty = TRUE;
        pthread_mutex_unlock (&repo->lock);
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
    if (seaf_repo_merge (repo, "master", &err_msg, &res->real_merge) < 0) {
        seaf_message ("[Sync mgr] Merge of repo %s(%.8s) is not clean.\n",
                   repo->name, repo->id);
        res->success = FALSE;
        g_free (err_msg);
        pthread_mutex_unlock (&repo->lock);
        return res;
    }

    res->success = TRUE;
    g_free (err_msg);
    pthread_mutex_unlock (&repo->lock);
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

    if (repo->auto_sync && res->task->force_upload) {
        if (seaf_wt_monitor_refresh_repo (seaf->wt_monitor, 
                                          repo->id) < 0) {
            seaf_warning ("[sync mgr] failed to refresh worktree "
                          "watch for repo %s(%.8s).\n",
                          repo->name, repo->id);
        }
    }

    if (res->success) {
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
    }

    if (res->success && res->real_merge)
        start_upload_if_necessary (res->task);
    else if (res->success)
        transition_sync_state (res->task, SYNC_STATE_DONE);
    else if (res->worktree_dirty)
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

static void
update_sync_status (SyncTask *task)
{
    SyncInfo *info = task->info;
    SeafRepo *repo = task->repo;
    SeafBranch *master, *local;

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
    } else if (info->branch_deleted_on_relay || /* branch deleted on relay */
               is_fast_forward (local->commit_id, info->head_commit)) {
        /* fast-forward upload */
        start_upload_if_necessary (task);
    } else {
        if (!master || !is_up_to_date (info->head_commit, master->commit_id)) {
            start_fetch_if_necessary (task);
        } else if (strcmp (local->commit_id, master->commit_id) != 0) {
            /* Try to merge even if we don't need to fetch. */
            merge_branches_if_necessary (task);
        } else {
            /* seaf_debug ("[sync-mgr] The repo %s is already uptodate\n", */
            /*             info->repo_id); */
            transition_sync_state (task, SYNC_STATE_DONE);
        }
    }

    seaf_branch_unref (local);
    if (master)
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

    update_sync_status (task);
}

static const char *
get_dest_id (SeafRepo *repo)
{
    const char *dest_id;
    if (repo->relay_id)
        dest_id = repo->relay_id;
    else
        return NULL;

    if (!ccnet_peer_is_ready(seaf->ccnetrpc_client, dest_id))
        return NULL;

    return dest_id;
}

static int
check_net_state (void *data);

static int
start_sync_repo_proc (SeafSyncManager *manager, SyncTask *task)
{
    CcnetProcessor *processor;

    /* Set dest id before we talk to the dest.
     * If it's a manual sync, it should have been set.
     */
    if (!task->dest_id) {
        if (!task->repo->relay_id) {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_RELAY_OFFLINE);
            return -1;
        }
        task->dest_id = g_strdup(task->repo->relay_id);
    }

    /* If relay is not ready, wait until it is. */
    if (!ccnet_peer_is_ready (seaf->ccnetrpc_client, task->dest_id)) {
        seaf_message ("[sync-mgr] Relay for %s is not ready, wait.\n",
                      task->repo->name);
        task->conn_timer = ccnet_timer_new (check_net_state, task, 1000);
        return 0;
    }

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

static int
check_net_state (void *data)
{
    SyncTask *task = data;

    if (ccnet_peer_is_ready (seaf->ccnetrpc_client, task->dest_id)) {
        ccnet_timer_free (&task->conn_timer);
        start_sync_repo_proc (task->mgr, task);
        return 0;
    }

    return 1;
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

    pthread_mutex_lock (&repo->lock);

    res->changed = TRUE;
    res->success = TRUE;

    char *commit_id = seaf_repo_index_commit (repo, "", &error);
    if (commit_id == NULL && error != NULL) {
        seaf_warning ("[Sync mgr] Failed to commit to repo %s(%.8s).\n",
                      repo->name, repo->id);
        res->success = FALSE;
    } else if (commit_id == NULL) {
        res->changed = FALSE;
    }
    g_free (commit_id);

    pthread_mutex_unlock (&repo->lock);
    return res;
}

static void
commit_job_done (void *vres)
{
    struct CommitResult *res = vres;
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

    if (repo->auto_sync && res->task->force_upload) {
        if (seaf_wt_monitor_refresh_repo (seaf->wt_monitor, 
                                          repo->id) < 0) {
            seaf_warning ("[sync mgr] failed to refresh worktree "
                          "watch for repo %s(%.8s).\n",
                          repo->name, repo->id);
        }
    }

    if (!res->success) {
        seaf_sync_manager_set_task_error (res->task, SYNC_ERROR_COMMIT);
        g_free (res);
        return;
    }

    /* If this repo is downloaded by syncing with an existing folder, and
     * the folder's contents are different from the server, clone manager
     * will create a "index" branch. This branch is of no use after the
     * first commit operation succeeds.
     */
    if (seaf_branch_manager_branch_exists (seaf->branch_mgr, repo->id, "index"))
        seaf_branch_manager_del_branch (seaf->branch_mgr, repo->id, "index");

    /* If nothing committed and is not manual sync, no need to sync. */
    if (!res->changed && !res->task->force_upload) {
        transition_sync_state (res->task, SYNC_STATE_DONE);
        g_free (res);
        return;
    }

    SyncTask *task = res->task;
    
    if (!task->token) {
        try_get_repo_email_token (task->mgr, task);
    } else 
        start_sync_repo_proc (res->task->mgr, res->task);

    g_free (res);
}

static void
commit_repo (SyncTask *task)
{
    transition_sync_state (task, SYNC_STATE_COMMIT);

    ccnet_job_manager_schedule_job (seaf->job_mgr, 
                                    commit_job, 
                                    commit_job_done,
                                    task);
}

#define GET_EMAIL_TOKEN_IN_PROGRESS 1
#define GET_EMAIL_TOKEN_FAILED      2

static void
get_email_token_done (CcnetProcessor *processor, gboolean success, void *data)
{
    GHashTable *htbl = seaf->sync_mgr->priv->get_email_token_hash;
    SyncTask *task = data;
    char *repo_id = task->info->repo_id;

    if (task->repo->delete_pending) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
        seaf_repo_manager_del_repo (seaf->repo_mgr, task->repo);
        return;
    }

    if (!success) {
        seaf_warning ("[sync mgr] failed to get email and token "
                      "for repo %s\n", repo_id);
        g_hash_table_replace (htbl, repo_id, (gpointer)GET_EMAIL_TOKEN_FAILED);
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_UPGRADE_REPO);
    } else {
        task->token = g_strdup(task->repo->token);
        start_sync_repo_proc (task->mgr, task);

        g_hash_table_remove (htbl, repo_id);
    }
}

/* If we update from old seafile version, and keep old seafile-data, then
 * repo->email and repo->token is not set, and we need to get it from the
 * repo->server before continue.
 */
static int
try_get_repo_email_token (SeafSyncManager *mgr,
                          SyncTask *task)
{
    /* Set dest id before we talk to the dest.
     * If it's a manual sync, it should have been set.
     */
    if (!task->dest_id) {
        const char *dest_id = get_dest_id (task->repo);
        if (!dest_id) {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_RELAY_OFFLINE);
            return -1;
        }
        task->dest_id = g_strdup(dest_id);
    } else {
        /* We also check relay net status in manual sync. */
        if (!ccnet_peer_is_ready (seaf->ccnetrpc_client, task->dest_id)) {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_RELAY_OFFLINE);
            return -1;
        }
    }
    
    GHashTable *htbl = mgr->priv->get_email_token_hash;
    char *repo_id = task->info->repo_id;
    long status = (long)g_hash_table_lookup (htbl, repo_id);

    if (status == GET_EMAIL_TOKEN_FAILED) {
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_UPGRADE_REPO);
        return -1;
        
    } else if (status == GET_EMAIL_TOKEN_IN_PROGRESS) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
        return 0;
    }

    CcnetProcessor *processor;
    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-get-repo-email-token",
        task->dest_id);

    if (!processor) {
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_UPGRADE_REPO);
        seaf_warning ("[sync-mgr] failed to create "
                      "get seafile-get-repo-email-token proc.\n");
        return -1;
    }

    if (ccnet_processor_startl (processor, repo_id, NULL) < 0) {
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_UPGRADE_REPO);
        seaf_warning ("[sync-mgr] failed to start "
                      "get seafile-get-repo-email-token proc.\n");
    }

    g_hash_table_insert (htbl, repo_id, (gpointer)GET_EMAIL_TOKEN_IN_PROGRESS);

    g_signal_connect (processor, "done",
                      (GCallback)get_email_token_done,
                      task);

    return 0;
}


static void
start_sync (SeafSyncManager *manager, SeafRepo *repo, SyncTask *task)
{
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

    if (task->need_commit)
        commit_repo (task);
    else if (!task->token) {
        try_get_repo_email_token (task->mgr, task);
    } else {
        start_sync_repo_proc (manager, task);
    }
}

static int
perform_sync_task (SeafSyncManager *manager, SyncTask *task)
{
    /* Repo may have been marked as deleted or actually deleted
     * after this task was added.
     * But once start_sync() is called, the repo should always
     * exists since it can only be deleted in the sync loop.
     */
    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr,
                                                 task->info->repo_id);
    if (!repo) {
        seaf_message ("repo %s was deleted, don't need to sync.\n", 
                      task->info->repo_id);
        sync_task_free (task);
        return 0;
    }
    if (repo->delete_pending) {
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
        sync_task_free (task);
        return 0;
    }

    /* Only one task can be run. If the task cannot be run, return -1.*/
    if (!task->info->in_sync) {
        start_sync (manager, repo, task);
        return 0;
    }

    seaf_debug ("Sync task for repo '%s' is running, reschedule.\n",
                repo->name);

    return -1;
}

static SyncTask *
create_sync_task (SeafSyncManager *manager,
                  SyncInfo *info,
                  SeafRepo *repo,
                  gboolean is_sync_lan,
                  gboolean force_upload,
                  gboolean need_commit)
{
    SyncTask *task = g_new0 (SyncTask, 1);

    task->info = info;
    task->mgr = manager;

    /* dest_id will be set later. */
    task->force_upload = force_upload;
    task->is_sync_lan = is_sync_lan;
    task->need_commit = need_commit;
    task->token = g_strdup(repo->token);

    return task;
}

gint
cmp_repos_by_sync_time (gconstpointer a, gconstpointer b, gpointer user_data)
{
    const SeafRepo *repo_a = a;
    const SeafRepo *repo_b = b;

    return (repo_a->last_sync_time - repo_b->last_sync_time);
}

static int
add_auto_sync_tasks (SeafSyncManager *manager)
{
    int timeline;
    GList *repos, *ptr;
    SeafRepo *repo;
    SyncInfo *info;

    timeline = (int) (time(NULL) - manager->sync_interval);

    repos = seaf_repo_manager_get_repo_list (manager->seaf->repo_mgr, -1, -1);

    /* Sort repos by last_sync_time, so that we don't "starve" any repo. */
    repos = g_list_sort_with_data (repos, cmp_repos_by_sync_time, NULL);

    for (ptr = repos; ptr; ptr = ptr->next) {
        repo = ptr->data;

        if (manager->n_running_tasks >= MAX_RUNNING_SYNC_TASKS)
            break;

        if (repo->last_sync_time > timeline)
            continue;

        if (repo->delete_pending)
            continue;

        if (!repo->auto_sync)
            continue;

        /* Don't sync if worktree doesn't exist. */
        if (!repo->head || seaf_repo_check_worktree (repo) < 0)
            continue;

        /* Don't sync repos without a relay-id */
        if (!repo->relay_id) 
            continue;

        info = get_sync_info (manager, repo->id);

        if (info->in_sync)
            continue;

        const char *dest_id = get_dest_id (repo);
        if (!dest_id)
            continue;

        CcnetPeer *peer = ccnet_get_peer (seaf->ccnetrpc_client, dest_id);
        if (!peer->session_key) {
            g_object_unref (peer);
            continue;
        }
        g_object_unref (peer);
        
        SyncTask *task = create_sync_task (manager, info, repo, FALSE, FALSE, FALSE);
        perform_sync_task (manager, task);
    }

    g_list_free (repos);

    return 0;
}

static int
check_sync_pulse (void *vmanager)
{
    SeafSyncManager *manager = vmanager;

    if (!manager->priv->auto_sync_enabled) {
        return TRUE;
    }

    add_auto_sync_tasks (manager);
    
    /* Here we perform tasks queued by auto-commit.
     * These tasks should be performed as soon as possible.
     */
    while (1) {
        SyncTask *task;

        task = (SyncTask *)g_queue_pop_head (manager->sync_tasks);
        if (!task)
            break;

        if (perform_sync_task (manager, task) < 0) {
            g_queue_push_tail (manager->sync_tasks, task);
            break;
        }
    }


    return TRUE;
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

static gint
compare_sync_task (gconstpointer a, gconstpointer b)
{
    const SyncTask *task = a;
    const char *repo_id = b;

    return strcmp (task->info->repo_id, repo_id);
}

static void
enqueue_sync_task (SeafSyncManager *manager, SeafRepo *repo, gboolean quiet)
{
    SyncInfo *info;
    SyncTask *task;

    seaf_debug ("Enqueue sync task for repo '%s'.\n", repo->name);

    if (g_queue_find_custom (manager->sync_tasks,
                             repo->id,
                             compare_sync_task) != NULL) {
        seaf_debug ("[sync-mgr] Task for '%s' is in queue, don't add again.\n",
                    repo->name);
        return;
    }

    info = get_sync_info (manager, repo->id);
    task = create_sync_task (manager, info, repo,
                             FALSE, FALSE, TRUE);
    task->quiet = quiet;
    g_queue_push_tail (manager->sync_tasks, task);
}

static int
auto_commit_pulse (void *vmanager)
{
    SeafSyncManager *manager = vmanager;
    GList *repos, *ptr;
    SeafRepo *repo;
    WTStatus *status;
    gint now = (gint)time(NULL);
    gint last_changed;

    repos = seaf_repo_manager_get_repo_list (manager->seaf->repo_mgr, -1, -1);

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
        if (repo->head != NULL && seaf_repo_check_worktree (repo) < 0) {
            seaf_repo_manager_invalidate_repo_worktree (seaf->repo_mgr, repo);
            auto_delete_repo (manager, repo);
            continue;
        }
        repo->worktree_invalid = FALSE;

        if (manager->priv->auto_sync_enabled && repo->auto_sync) {
            status = seaf_wt_monitor_get_worktree_status (manager->seaf->wt_monitor,
                                                          repo->id);
            if (status) {
                last_changed = g_atomic_int_get (&status->last_changed);
                if (last_changed != 0 && status->last_check <= last_changed) {
                    /* Do not set the wt_changed variable since we will
                       commit it soon. */
                    /* repo->wt_changed = TRUE; */
                    if (now - last_changed >= 2) {
                        enqueue_sync_task (manager, repo, FALSE);
                        status->last_check = now;
                    }
                } else if (now - status->last_check >= manager->wt_interval) {
                    /* Try to commit if no change has been detected in 10 mins. */
                    enqueue_sync_task (manager, repo, TRUE);
                    status->last_check = now;
                }
            }
        }
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
        merge_branches_if_necessary (task);
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
        
        enqueue_sync_task (mgr, repo, FALSE);
    }

    g_list_free (repos);
}

int
seaf_sync_manager_enable_auto_sync (SeafSyncManager *mgr)
{
    if (!seaf->started) {
        seaf_message ("sync manager is not started, skip enable auto sync.\n");
        return -1;
    }

    add_sync_tasks_for_all (mgr);
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
