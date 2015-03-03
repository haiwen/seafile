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
#define UPDATE_TX_STATE_INTERVAL 1000 /* 1s */
#define MAX_RUNNING_SYNC_TASKS 5
#define CHECK_LOCKED_FILES_INTERVAL 10 /* 10s */
#define CHECK_FOLDER_PERMS_INTERVAL 30 /* 30s */

enum {
    SERVER_SIDE_MERGE_UNKNOWN = 0,
    SERVER_SIDE_MERGE_SUPPORTED,
    SERVER_SIDE_MERGE_UNSUPPORTED,
};

struct _ServerState {
    int server_side_merge;
    gboolean checking;
};
typedef struct _ServerState ServerState;

struct _HttpServerState {
    gboolean http_not_supported;
    int http_version;
    gboolean checking;

    gboolean folder_perms_not_supported;
    gint64 last_check_perms_time;
    gboolean checking_folder_perms;
};
typedef struct _HttpServerState HttpServerState;

struct _SeafSyncManagerPriv {
    struct CcnetTimer *check_sync_timer;
    struct CcnetTimer *update_tx_state_timer;
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
static void on_repo_http_fetched (SeafileSession *seaf,
                                  HttpTxTask *tx_task,
                                  SeafSyncManager *manager);
static void on_repo_http_uploaded (SeafileSession *seaf,
                                   HttpTxTask *tx_task,
                                   SeafSyncManager *manager);

static inline void
transition_sync_state (SyncTask *task, int new_state);

static void sync_task_free (SyncTask *task);

static gboolean
check_relay_status (SeafSyncManager *mgr, SeafRepo *repo);

static gboolean
has_old_commits_to_upload (SeafRepo *repo);

static int
sync_repo_v2 (SeafSyncManager *manager, SeafRepo *repo, gboolean is_manual_sync);

static gboolean
check_http_protocol (SeafSyncManager *mgr, SeafRepo *repo, gboolean *is_checking);

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

    mgr->http_server_states = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                     g_free, g_free);

    gboolean exists;
    int download_limit = seafile_session_config_get_int (seaf,
                                                         KEY_DOWNLOAD_LIMIT,
                                                         &exists);
    if (exists)
        mgr->download_limit = download_limit;

    int upload_limit = seafile_session_config_get_int (seaf,
                                                       KEY_UPLOAD_LIMIT,
                                                       &exists);
    if (exists)
        mgr->upload_limit = upload_limit;

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

static void 
format_transfer_task_detail (TransferTask *task, GString *buf)
{
    if (task->state != TASK_STATE_NORMAL ||
        task->runtime_state == TASK_RT_STATE_INIT ||
        task->runtime_state == TASK_RT_STATE_FINISHED ||
        task->runtime_state == TASK_RT_STATE_NETDOWN)
        return;

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

static void 
format_http_task_detail (HttpTxTask *task, GString *buf)
{
    if (task->state != HTTP_TASK_STATE_NORMAL ||
        task->runtime_state == HTTP_TASK_RT_STATE_INIT ||
        task->runtime_state == HTTP_TASK_RT_STATE_FINISHED)
        return;

    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr,
                                                 task->repo_id);
    char *repo_name;
    char *type;
    
    if (repo) {
        repo_name = repo->name;
        type = (task->type == HTTP_TASK_TYPE_UPLOAD) ? "upload" : "download";
        
    } else if (task->is_clone) {
        CloneTask *ctask;
        ctask = seaf_clone_manager_get_task (seaf->clone_mgr, task->repo_id);
        repo_name = ctask->repo_name;
        type = "download";
        
    } else {
        return;
    }
    int rate = http_tx_task_get_rate(task);

    g_string_append_printf (buf, "%s\t%d %s\n", type, rate, repo_name);
}

/*
 * Publish a notification message to report :
 *
 *      [uploading/downloading]\t[transfer-rate] [repo-name]\n
 */
static int
update_tx_state (void *vmanager)
{
    SeafSyncManager *mgr = vmanager;
    GString *buf = g_string_new (NULL);
    GList *tasks, *ptr;
    TransferTask *task;
    HttpTxTask *http_task;

    mgr->last_sent_bytes = g_atomic_int_get (&mgr->sent_bytes);
    g_atomic_int_set (&mgr->sent_bytes, 0);
    mgr->last_recv_bytes = g_atomic_int_get (&mgr->recv_bytes);
    g_atomic_int_set (&mgr->recv_bytes, 0);

    tasks = seaf_transfer_manager_get_upload_tasks (seaf->transfer_mgr);
    for (ptr = tasks; ptr; ptr = ptr->next) {
        task = ptr->data;
        format_transfer_task_detail (task, buf);
    }
    g_list_free (tasks);

    tasks = seaf_transfer_manager_get_download_tasks (seaf->transfer_mgr);
    for (ptr = tasks; ptr; ptr = ptr->next) {
        task = ptr->data;
        format_transfer_task_detail (task, buf);
    }
    g_list_free (tasks);

    tasks = http_tx_manager_get_upload_tasks (seaf->http_tx_mgr);
    for (ptr = tasks; ptr; ptr = ptr->next) {
        http_task = ptr->data;
        format_http_task_detail (http_task, buf);
    }
    g_list_free (tasks);

    tasks = http_tx_manager_get_download_tasks (seaf->http_tx_mgr);
    for (ptr = tasks; ptr; ptr = ptr->next) {
        http_task = ptr->data;
        format_http_task_detail (http_task, buf);
    }
    g_list_free (tasks);

    if (buf->len != 0)
        seaf_mq_manager_publish_notification (seaf->mq_mgr, "transfer",
                                              buf->str);

    g_string_free (buf, TRUE);

    return TRUE;
}

int
seaf_sync_manager_start (SeafSyncManager *mgr)
{
    add_repo_relays ();

    mgr->priv->check_sync_timer = ccnet_timer_new (
        auto_sync_pulse, mgr, CHECK_SYNC_INTERVAL);

    mgr->priv->update_tx_state_timer = ccnet_timer_new (
        update_tx_state, mgr, UPDATE_TX_STATE_INTERVAL);

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
    g_signal_connect (seaf, "repo-http-fetched",
                      (GCallback)on_repo_http_fetched, mgr);
    g_signal_connect (seaf, "repo-http-uploaded",
                      (GCallback)on_repo_http_uploaded, mgr);

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

    SyncInfo *info = get_sync_info (mgr, repo->id);

    if (info->in_sync)
        return 0;

    gboolean is_checking_http = FALSE;
    if (seaf->enable_http_sync && repo->version > 0) {
        if (check_http_protocol (mgr, repo, &is_checking_http)) {
            sync_repo_v2 (mgr, repo, TRUE);
            return 0;
        }
    }

    /* If relay is not ready or protocol version is not determined,
     * need to wait.
     */
    if (!check_relay_status (mgr, repo)) {
        seaf_warning ("Relay for repo %s(%.8s) is not ready or protocol version"
                      "is not detected.\n", repo->name, repo->id);
        return 0;
    }

    ServerState *state = g_hash_table_lookup (mgr->server_states,
                                              repo->relay_id);

    if (repo->version == 0 ||
        state->server_side_merge == SERVER_SIDE_MERGE_UNSUPPORTED ||
        has_old_commits_to_upload (repo))
        start_sync (mgr, repo, TRUE, TRUE, FALSE);
    else if (state->server_side_merge == SERVER_SIDE_MERGE_SUPPORTED)
        sync_repo_v2 (mgr, repo, TRUE);

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
        if (!task->http_sync)
            seaf_transfer_manager_cancel_task (seaf->transfer_mgr,
                                               task->tx_id,
                                               TASK_TYPE_DOWNLOAD);
        else
            http_tx_manager_cancel_task (seaf->http_tx_mgr,
                                         repo_id,
                                         HTTP_TASK_TYPE_DOWNLOAD);
        transition_sync_state (task, SYNC_STATE_CANCEL_PENDING);
        break;
    case SYNC_STATE_UPLOAD:
        if (!task->http_sync)
            seaf_transfer_manager_cancel_task (seaf->transfer_mgr,
                                               task->tx_id,
                                               TASK_TYPE_UPLOAD);
        else
            http_tx_manager_cancel_task (seaf->http_tx_mgr,
                                         repo_id,
                                         HTTP_TASK_TYPE_UPLOAD);
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

        if (!task->server_side_merge) {
            if ((task->state == SYNC_STATE_MERGE ||
                 task->state == SYNC_STATE_UPLOAD) &&
                new_state == SYNC_STATE_DONE &&
                need_notify_sync(task->repo))
                notify_sync (task->repo);
        } else {
            if (((task->state == SYNC_STATE_INIT && task->uploaded) ||
                 task->state == SYNC_STATE_FETCH) &&
                new_state == SYNC_STATE_DONE &&
                need_notify_sync(task->repo))
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
    "Failed to get sync info from server.",
    "Files are locked by other application",
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
    SeafRepo *repo = task->repo;
    const char *repo_id = task->repo->id;

    if (!task->http_sync) {
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
    } else {
        if (http_tx_manager_add_upload (seaf->http_tx_mgr,
                                        repo->id,
                                        repo->version,
                                        repo->server_url,
                                        repo->token,
                                        task->http_version,
                                        &error) < 0) {
            seaf_warning ("Failed to start http upload: %s\n", error->message);
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_START_UPLOAD);
            return;
        }
        task->tx_id = g_strdup(repo->id);
    }

    transition_sync_state (task, SYNC_STATE_UPLOAD);
}

static void
start_fetch_if_necessary (SyncTask *task, const char *remote_head)
{
    GError *error = NULL;
    char *tx_id;
    SeafRepo *repo = task->repo;
    const char *repo_id = task->repo->id;

    if (!task->http_sync) {
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
    } else {
        if (http_tx_manager_add_download (seaf->http_tx_mgr,
                                          repo->id,
                                          repo->version,
                                          repo->server_url,
                                          repo->token,
                                          remote_head,
                                          FALSE,
                                          NULL, NULL,
                                          task->http_version,
                                          &error) < 0) {
            seaf_warning ("Failed to start http download: %s.\n", error->message);
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_START_FETCH);
            return;
        }
        task->tx_id = g_strdup(repo->id);
    }

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
        start_fetch_if_necessary (task, NULL);
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

#ifdef WIN32

static GHashTable *
load_locked_files_blocks (const char *repo_id)
{
    LockedFileSet *fset;
    GHashTable *block_id_hash;
    GHashTableIter iter;
    gpointer key, value;
    LockedFile *locked;
    Seafile *file;
    int i;
    char *blk_id;

    fset = seaf_repo_manager_get_locked_file_set (seaf->repo_mgr, repo_id);

    block_id_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    g_hash_table_iter_init (&iter, fset->locked_files);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        locked = value;

        if (strcmp (locked->operation, LOCKED_OP_UPDATE) == 0) {
            file = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                                fset->repo_id, 1,
                                                locked->file_id);
            if (!file) {
                seaf_warning ("Failed to find file %s in repo %.8s.\n",
                              locked->file_id, fset->repo_id);
                continue;
            }

            for (i = 0; i < file->n_blocks; ++i) {
                blk_id = g_strdup (file->blk_sha1s[i]);
                g_hash_table_replace (block_id_hash, blk_id, blk_id);
            }

            seafile_unref (file);
        }
    }

    locked_file_set_free (fset);

    return block_id_hash;
}

static gboolean
remove_block_cb (const char *store_id,
                 int version,
                 const char *block_id,
                 void *user_data)
{
    GHashTable *block_hash = user_data;

    if (!g_hash_table_lookup (block_hash, block_id))
        seaf_block_manager_remove_block (seaf->block_mgr, store_id, version, block_id);

    return TRUE;
}

#endif

static void *
remove_repo_blocks (void *vtask)
{
    SyncTask *task = vtask;

#ifndef WIN32
    seaf_block_manager_remove_store (seaf->block_mgr, task->repo->id);
#else
    GHashTable *block_hash;

    block_hash = load_locked_files_blocks (task->repo->id);
    if (g_hash_table_size (block_hash) == 0) {
        g_hash_table_destroy (block_hash);
        seaf_block_manager_remove_store (seaf->block_mgr, task->repo->id);
        return vtask;
    }

    seaf_block_manager_foreach_block (seaf->block_mgr,
                                      task->repo->id,
                                      task->repo->version,
                                      remove_block_cb,
                                      block_hash);

    g_hash_table_destroy (block_hash);
#endif

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

            seaf_warning ("repo %s(%.8s) not found on server\n",
                        repo->name, repo->id);

            if (!seafile_session_config_get_allow_repo_not_found_on_server(seaf)) {
                seaf_debug ("remove repo %s(%.8s) since it's deleted on relay\n",
                            repo->name, repo->id);
                seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                                      "repo.deleted_on_relay",
                                                      repo->name);
                seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
            }
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
                /* seaf_message ("Removing blocks for repo %s(%.8s).\n", */
                /*               repo->name, repo->id); */
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
            start_fetch_if_necessary (task, NULL);
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
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_NOREPO);

        seaf_warning ("repo %s(%.8s) not found on server\n",
                      repo->name, repo->id);

        if (!seafile_session_config_get_allow_repo_not_found_on_server(seaf)) {
            seaf_message ("remove repo %s(%.8s) since it's deleted on relay\n",
                        repo->name, repo->id);
            seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                                  "repo.deleted_on_relay",
                                                  repo->name);
            seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
        }
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
            start_fetch_if_necessary (task, task->info->head_commit);
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

/*
  The sync-repo processor is used to check the head commit at the server side.
*/
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

static void
check_head_commit_done (HttpHeadCommit *result, void *user_data)
{
    SyncTask *task = user_data;
    SyncInfo *info = task->info;

    if (!result->check_success) {
        seaf_sync_manager_set_task_error (task, SYNC_ERROR_GET_SYNC_INFO);
        return;
    }

    info->deleted_on_relay = result->is_deleted;
    info->repo_corrupted = result->is_corrupt;
    memcpy (info->head_commit, result->head_commit, 40);

    update_sync_status_v2 (task);
}

static int
check_head_commit_http (SyncTask *task)
{
    SeafRepo *repo = task->repo;

    int ret = http_tx_manager_check_head_commit (seaf->http_tx_mgr,
                                                 repo->id, repo->version,
                                                 repo->server_url,
                                                 repo->token,
                                                 check_head_commit_done,
                                                 task);
    if (ret == 0)
        transition_sync_state (task, SYNC_STATE_INIT);
    return ret;
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

    char *commit_id = seaf_repo_index_commit (repo, "", task->is_manual_sync,
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
        else if (task->is_manual_sync || task->is_initial_commit) {
            if (task->http_sync)
                check_head_commit_http (task);
            else
                start_sync_repo_proc (task->mgr, task);
        } else
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

    if (repo->server_url) {
        HttpServerState *state = g_hash_table_lookup (manager->http_server_states,
                                                      repo->server_url);
        if (state) {
            if (!state->http_not_supported) {
                task->http_sync = TRUE;
                task->http_version = state->http_version;
            }
        }
    }

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
        } else if (status->partial_commit) {
            task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
            repo->create_partial_commit = TRUE;
            commit_repo (task);
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
        }
        wt_status_unref (status);
    }

    return ret;
}

static gboolean
can_schedule_repo (SeafSyncManager *manager, SeafRepo *repo)
{
    int now = (int)time(NULL);

    return ((repo->last_sync_time == 0 ||
             repo->last_sync_time < now - manager->sync_interval) &&
            manager->n_running_tasks < MAX_RUNNING_SYNC_TASKS);
}

static int
sync_repo_v2 (SeafSyncManager *manager, SeafRepo *repo, gboolean is_manual_sync)
{
    SeafBranch *master, *local;
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
        if (is_manual_sync || can_schedule_repo (manager, repo)) {
            task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
            start_fetch_if_necessary (task, last_download);
        }
        goto out;
    }

    if (strcmp (master->commit_id, local->commit_id) != 0) {
        if (is_manual_sync || can_schedule_repo (manager, repo)) {
            task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
            start_upload_if_necessary (task);
        }
        /* Do nothing if the client still has something to upload
         * but it's before 30-second schedule.
         */
        goto out;
    } else if (is_manual_sync) {
        task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
        commit_repo (task);
        goto out;
    } else if (create_commit_from_event_queue (manager, repo, is_manual_sync))
        goto out;

    if (is_manual_sync || can_schedule_repo (manager, repo)) {
        task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
        if (task->http_sync)
            check_head_commit_http (task);
        else
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

static void
check_http_protocol_done (HttpProtocolVersion *result, void *user_data)
{
    HttpServerState *state = user_data;

    state->checking = FALSE;

    if (result->check_success) {
        state->http_not_supported = result->not_supported;
        if (!result->not_supported)
            state->http_version = result->version;
    } else
        state->http_not_supported = TRUE;
}

#define CHECK_HTTP_INTERVAL 10

/*
 * Returns TRUE if we can use http-sync; otherwise FALSE.
 * If FALSE is returned, the caller should also check @is_checking value.
 * If @is_checking is set to TRUE, we're still determining whether the
 * server supports http-sync.
 */
static gboolean
check_http_protocol (SeafSyncManager *mgr, SeafRepo *repo, gboolean *is_checking)
{
    *is_checking = FALSE;

    /* If a repo was cloned before 4.0, server-url is not set. */
    if (!repo->server_url)
        return FALSE;

    HttpServerState *state = g_hash_table_lookup (mgr->http_server_states,
                                                  repo->server_url);
    if (!state) {
        state = g_new0 (HttpServerState, 1);
        g_hash_table_insert (mgr->http_server_states,
                             g_strdup(repo->server_url), state);
    }

    if (state->checking) {
        *is_checking = TRUE;
        return FALSE;
    }

    if (state->http_not_supported)
        return FALSE;
    if (state->http_version > 0)
        return TRUE;

    http_tx_manager_check_protocol_version (seaf->http_tx_mgr,
                                            repo->server_url,
                                            check_http_protocol_done,
                                            state);
    state->checking = TRUE;
    *is_checking = TRUE;

    return FALSE;
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

#ifdef WIN32

static void
cleanup_file_blocks (const char *repo_id, int version, const char *file_id)
{
    Seafile *file;
    int i;

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                        repo_id, version,
                                        file_id);
    for (i = 0; i < file->n_blocks; ++i)
        seaf_block_manager_remove_block (seaf->block_mgr,
                                         repo_id, version,
                                         file->blk_sha1s[i]);

    seafile_unref (file);
}

static gboolean
handle_locked_file_update (SeafRepo *repo, struct index_state *istate,
                           LockedFileSet *fset, const char *path, LockedFile *locked)
{
    struct cache_entry *ce;
    char file_id[41];
    char *fullpath = NULL;
    SeafStat st;
    gboolean file_exists = TRUE;
    SeafileCrypt *crypt = NULL;
    SeafBranch *master = NULL;
    gboolean ret = TRUE;

    /* File is still locked, do nothing. */
    if (do_check_file_locked (path, repo->worktree))
        return FALSE;

    seaf_debug ("Update previously locked file %s in repo %.8s.\n",
                path, repo->id);

    /* If the file was locked on the last checkout, the worktree file was not
     * updated, but the index has been updated. So the ce in the index should
     * contain the information for the file to be updated.
     */
    ce = index_name_exists (istate, path, strlen(path), 0);
    if (!ce) {
        seaf_warning ("Cache entry for %s in repo %s(%.8s) is not found "
                      "when update locked file.",
                      path, repo->name, repo->id);
        goto remove_from_db;
    }

    rawdata_to_hex (ce->sha1, file_id, 20);

    fullpath = g_build_filename (repo->worktree, path, NULL);

    file_exists = seaf_util_exists (fullpath);

    if (file_exists && seaf_stat (fullpath, &st) < 0) {
        seaf_warning ("Failed to stat %s: %s.\n", fullpath, strerror(errno));
        goto out;
    }

    if (repo->encrypted)
        crypt = seafile_crypt_new (repo->enc_version,
                                   repo->enc_key,
                                   repo->enc_iv);

    master = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "master");
    if (!master) {
        seaf_warning ("No master branch found for repo %s(%.8s).\n",
                      repo->name, repo->id);
        goto out;
    }

    gboolean conflicted;
    gboolean force_conflict = (file_exists && st.st_mtime != locked->old_mtime);
    if (seaf_fs_manager_checkout_file (seaf->fs_mgr,
                                       repo->id, repo->version,
                                       file_id, fullpath,
                                       ce->ce_mode, ce->ce_mtime.sec,
                                       crypt,
                                       path,
                                       master->commit_id,
                                       force_conflict,
                                       &conflicted) < 0) {
        seaf_warning ("Failed to checkout previously locked file %s in repo "
                      "%s(%.8s).\n",
                      path, repo->name, repo->id);
    }

out:
    cleanup_file_blocks (repo->id, repo->version, file_id);

remove_from_db:
    /* Remove the locked file record from db. */
    locked_file_set_remove (fset, path, TRUE);

    g_free (fullpath);
    g_free (crypt);
    seaf_branch_unref (master);
    return ret;
}

static gboolean
handle_locked_file_delete (SeafRepo *repo, struct index_state *istate,
                           LockedFileSet *fset, const char *path, LockedFile *locked)
{
    char *fullpath = NULL;
    SeafStat st;
    gboolean file_exists = TRUE;
    gboolean ret = TRUE;

    /* File is still locked, do nothing. */
    if (do_check_file_locked (path, repo->worktree))
        return FALSE;

    seaf_debug ("Delete previously locked file %s in repo %.8s.\n",
                path, repo->id);

    fullpath = g_build_filename (repo->worktree, path, NULL);

    file_exists = seaf_util_exists (fullpath);

    if (file_exists && seaf_stat (fullpath, &st) < 0) {
        seaf_warning ("Failed to stat %s: %s.\n", fullpath, strerror(errno));
        goto out;
    }

    if (file_exists && st.st_mtime == locked->old_mtime)
        seaf_util_unlink (fullpath);

out:
    /* Remove the locked file record from db. */
    locked_file_set_remove (fset, path, TRUE);

    g_free (fullpath);
    return ret;
}

static void *
check_locked_files (void *vdata)
{
    SeafRepo *repo = vdata;
    LockedFileSet *fset;
    GHashTableIter iter;
    gpointer key, value;
    char *path;
    LockedFile *locked;
    char index_path[SEAF_PATH_MAX];
    struct index_state istate;

    fset = seaf_repo_manager_get_locked_file_set (seaf->repo_mgr, repo->id);

    if (g_hash_table_size (fset->locked_files) == 0) {
        locked_file_set_free (fset);
        return vdata;
    }

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", repo->manager->index_dir, repo->id);
    if (read_index_from (&istate, index_path, repo->version) < 0) {
        seaf_warning ("Failed to load index.\n");
        return vdata;
    }

    gboolean success;
    g_hash_table_iter_init (&iter, fset->locked_files);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        path = key;
        locked = value;

        success = FALSE;
        if (strcmp (locked->operation, LOCKED_OP_UPDATE) == 0)
            success = handle_locked_file_update (repo, &istate, fset, path, locked);
        else if (strcmp (locked->operation, LOCKED_OP_DELETE) == 0)
            success = handle_locked_file_delete (repo, &istate, fset, path, locked);

        if (success)
            g_hash_table_iter_remove (&iter);
    }

    discard_index (&istate);
    locked_file_set_free (fset);

    return vdata;
}

static void
check_locked_files_done (void *vdata)
{
    SeafRepo *repo = vdata;
    repo->checking_locked_files = FALSE;
}

#endif

static void
check_folder_perms_done (HttpFolderPerms *result, void *user_data)
{
    HttpServerState *server_state = user_data;
    GList *ptr;
    HttpFolderPermRes *res;
    gint64 now = (gint64)time(NULL);

    server_state->checking_folder_perms = FALSE;

    if (!result->success) {
        /* If on star-up we find that checking folder perms fails,
         * we assume the server doesn't support it.
         */
        if (server_state->last_check_perms_time == 0)
            server_state->folder_perms_not_supported = TRUE;
        server_state->last_check_perms_time = now;
        return;
    }

    for (ptr = result->results; ptr; ptr = ptr->next) {
        res = ptr->data;

        seaf_repo_manager_update_folder_perms (seaf->repo_mgr, res->repo_id,
                                               FOLDER_PERM_TYPE_USER,
                                               res->user_perms);
        seaf_repo_manager_update_folder_perms (seaf->repo_mgr, res->repo_id,
                                               FOLDER_PERM_TYPE_GROUP,
                                               res->group_perms);
        seaf_repo_manager_update_folder_perm_timestamp (seaf->repo_mgr,
                                                        res->repo_id,
                                                        res->timestamp);
    }
    server_state->last_check_perms_time = now;
}

static void
check_folder_permissions_one_server (SeafSyncManager *mgr,
                                     const char *host,
                                     HttpServerState *server_state,
                                     GList *repos)
{
    GList *ptr;
    SeafRepo *repo;
    char *token;
    gint64 timestamp;
    HttpFolderPermReq *req;
    GList *requests = NULL;

    gint64 now = (gint64)time(NULL);

    if (server_state->http_version == 0 ||
        server_state->folder_perms_not_supported ||
        server_state->checking_folder_perms)
        return;

    if (server_state->last_check_perms_time > 0 &&
        now - server_state->last_check_perms_time < CHECK_FOLDER_PERMS_INTERVAL)
        return;

    for (ptr = repos; ptr; ptr = ptr->next) {
        repo = ptr->data;

        if (!repo->head)
            continue;

        if (g_strcmp0 (host, repo->server_url) != 0)
            continue;

        token = seaf_repo_manager_get_repo_property (seaf->repo_mgr,
                                                     repo->id, REPO_PROP_TOKEN);
        if (!token)
            continue;

        timestamp = seaf_repo_manager_get_folder_perm_timestamp (seaf->repo_mgr,
                                                                 repo->id);
        if (timestamp < 0)
            timestamp = 0;

        req = g_new0 (HttpFolderPermReq, 1);
        memcpy (req->repo_id, repo->id, 36);
        req->token = g_strdup(token);
        req->timestamp = timestamp;

        requests = g_list_append (requests, req);
    }

    if (!requests)
        return;

    server_state->checking_folder_perms = TRUE;

    /* The requests list will be freed in http tx manager. */
    http_tx_manager_get_folder_perms (seaf->http_tx_mgr,
                                      host,
                                      requests,
                                      check_folder_perms_done,
                                      server_state);
}

static void
check_folder_permissions (SeafSyncManager *mgr, GList *repos)
{
    GHashTableIter iter;
    gpointer key, value;
    char *host;
    HttpServerState *state;

    g_hash_table_iter_init (&iter, mgr->http_server_states);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        host = key;
        state = value;
        check_folder_permissions_one_server (mgr, host, state, repos);
    }
}

static int
auto_sync_pulse (void *vmanager)
{
    SeafSyncManager *manager = vmanager;
    GList *repos, *ptr;
    SeafRepo *repo;
    gint64 now;

    repos = seaf_repo_manager_get_repo_list (manager->seaf->repo_mgr, -1, -1);

    check_folder_permissions (manager, repos);

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

        if (!repo->token) {
            /* If the user has logged out of the account, the repo token would
             * be null */
            seaf_debug ("repo token of %s (%.8s) is null, would not sync it\n", repo->name, repo->id);
            continue;
        }

        /* Don't sync repos not checked out yet. */
        if (!repo->head)
            continue;

        if (!manager->priv->auto_sync_enabled || !repo->auto_sync)
            continue;

#ifdef WIN32
        if (repo->version > 0) {
            if (repo->checking_locked_files)
                continue;

            now = (gint64)time(NULL);
            if (repo->last_check_locked_time == 0 ||
                now - repo->last_check_locked_time >= CHECK_LOCKED_FILES_INTERVAL)
            {
                repo->checking_locked_files = TRUE;
                ccnet_job_manager_schedule_job (seaf->job_mgr,
                                                check_locked_files,
                                                check_locked_files_done,
                                                repo);
                repo->last_check_locked_time = now;

            }
        }
#endif

        SyncInfo *info = get_sync_info (manager, repo->id);

        if (info->in_sync)
            continue;

        /* Try to use http sync first if enabled. */
        gboolean is_checking_http = FALSE;
        if (seaf->enable_http_sync && repo->version > 0) {
            if (check_http_protocol (manager, repo, &is_checking_http)) {
                sync_repo_v2 (manager, repo, FALSE);
                continue;
            } else if (is_checking_http)
                continue;
            /* Otherwise we've determined the server doesn't support http-sync. */
        }

        /* If relay is not ready or protocol version is not determined,
         * need to wait.
         */
        if (!check_relay_status (manager, repo))
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
        } else if (tx_task->error == TASK_ERR_FILES_LOCKED) {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_FILES_LOCKED);
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
        else {
            task->uploaded = TRUE;
            if (!task->http_sync)
                start_sync_repo_proc (manager, task);
            else
                check_head_commit_http (task);
        }
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

static void
on_repo_http_fetched (SeafileSession *seaf,
                      HttpTxTask *tx_task,
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

    if (tx_task->state == HTTP_TASK_STATE_FINISHED) {
        memcpy (info->head_commit, tx_task->head, 41);
        transition_sync_state (task, SYNC_STATE_DONE);
    } else if (tx_task->state == HTTP_TASK_STATE_CANCELED) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
    } else if (tx_task->state == HTTP_TASK_STATE_ERROR) {
        if (tx_task->error == HTTP_TASK_ERR_FORBIDDEN) {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_ACCESS_DENIED);
            if (!task->repo->access_denied_notified) {
                send_sync_error_notification (task->repo, "sync.access_denied");
                task->repo->access_denied_notified = 1;
            }
        } else if (tx_task->error == HTTP_TASK_ERR_FILES_LOCKED) {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_FILES_LOCKED);
        } else
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_FETCH);
    }
}

static void
on_repo_http_uploaded (SeafileSession *seaf,
                       HttpTxTask *tx_task,
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

    if (tx_task->state == HTTP_TASK_STATE_FINISHED) {
        memcpy (info->head_commit, tx_task->head, 41);

        /* Save current head commit id for GC. */
        seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                             task->repo->id,
                                             REPO_LOCAL_HEAD,
                                             task->repo->head->commit_id);
        task->uploaded = TRUE;
        check_head_commit_http (task);
    } else if (tx_task->state == HTTP_TASK_STATE_CANCELED) {
        transition_sync_state (task, SYNC_STATE_CANCELED);
    } else if (tx_task->state == HTTP_TASK_STATE_ERROR) {
        if (tx_task->error == HTTP_TASK_ERR_FORBIDDEN) {
            seaf_sync_manager_set_task_error (task, SYNC_ERROR_ACCESS_DENIED);
            if (!task->repo->access_denied_notified) {
                send_sync_error_notification (task->repo, "sync.access_denied");
                task->repo->access_denied_notified = 1;
            }
        } else if (tx_task->error == HTTP_TASK_ERR_NO_QUOTA) {
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
