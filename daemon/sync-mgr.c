/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */


#include "common.h"

#include <pthread.h>

#include "db.h"
#include "seafile-session.h"
#include "seafile-config.h"
#include "sync-mgr.h"
#include "seafile-error-impl.h"
#include "mq-mgr.h"
#include "utils.h"
#include "vc-utils.h"

#include "sync-status-tree.h"

#ifdef WIN32
#include <shlobj.h>
#endif

#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
#include "log.h"

#include "timer.h"

#define DEFAULT_SYNC_INTERVAL 30 /* 30s */
#define CHECK_SYNC_INTERVAL  1000 /* 1s */
#define UPDATE_TX_STATE_INTERVAL 1000 /* 1s */
#define MAX_RUNNING_SYNC_TASKS 5
#define CHECK_LOCKED_FILES_INTERVAL 10 /* 10s */
#define CHECK_FOLDER_PERMS_INTERVAL 30 /* 30s */

#define SYNC_PERM_ERROR_RETRY_TIME 2

struct _HttpServerState {
    int http_version;
    gboolean checking;
    gint64 last_http_check_time;
    char *testing_host;
    /* Can be server_url or server_url:8082, depends on which one works. */
    char *effective_host;
    gboolean use_fileserver_port;

    gboolean folder_perms_not_supported;
    gint64 last_check_perms_time;
    gboolean checking_folder_perms;

    gboolean locked_files_not_supported;
    gint64 last_check_locked_files_time;
    gboolean checking_locked_files;

    /*
     * repo_id -> head commit id mapping.
     * Caches the head commit ids of synced repos.
     */
    GHashTable *head_commit_map;
    pthread_mutex_t head_commit_map_lock;
    gboolean head_commit_map_init;
    gint64 last_update_head_commit_map_time;
};
typedef struct _HttpServerState HttpServerState;

struct _SeafSyncManagerPriv {
    struct SeafTimer *check_sync_timer;
    struct SeafTimer *update_tx_state_timer;
    int    pulse_count;

    /* When FALSE, auto sync is globally disabled */
    gboolean   auto_sync_enabled;

    GHashTable *active_paths;
    pthread_mutex_t paths_lock;

#ifdef WIN32
    GAsyncQueue *refresh_paths;
    struct SeafTimer *refresh_windows_timer;
#endif
};

struct _ActivePathsInfo {
    GHashTable *paths;
    struct SyncStatusTree *syncing_tree;
    struct SyncStatusTree *synced_tree;
};
typedef struct _ActivePathsInfo ActivePathsInfo;

static int auto_sync_pulse (void *vmanager);

static void on_repo_http_fetched (SeafileSession *seaf,
                                  HttpTxTask *tx_task,
                                  SeafSyncManager *manager);
static void on_repo_http_uploaded (SeafileSession *seaf,
                                   HttpTxTask *tx_task,
                                   SeafSyncManager *manager);

static inline void
transition_sync_state (SyncTask *task, int new_state);

static void sync_task_free (SyncTask *task);

static int
sync_repo_v2 (SeafSyncManager *manager, SeafRepo *repo, gboolean is_manual_sync);

static gboolean
check_http_protocol (SeafSyncManager *mgr, SeafRepo *repo);

static void
active_paths_info_free (ActivePathsInfo *info);

static HttpServerState *
http_server_state_new ()
{
    HttpServerState *state = g_new0 (HttpServerState, 1);
    state->head_commit_map = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
    pthread_mutex_init (&state->head_commit_map_lock, NULL);
    return state;
}

static void
http_server_state_free (HttpServerState *state)
{
    if (!state)
        return;
    g_hash_table_destroy (state->head_commit_map);
    pthread_mutex_destroy (&state->head_commit_map_lock);
    g_free (state);
}

SeafSyncManager*
seaf_sync_manager_new (SeafileSession *seaf)
{
    SeafSyncManager *mgr = g_new0 (SeafSyncManager, 1);
    mgr->priv = g_new0 (SeafSyncManagerPriv, 1);    
    mgr->priv->auto_sync_enabled = TRUE;
    mgr->seaf = seaf;

    mgr->sync_interval = DEFAULT_SYNC_INTERVAL;
    mgr->sync_infos = g_hash_table_new (g_str_hash, g_str_equal);

    mgr->http_server_states = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                     g_free,
                                                     (GDestroyNotify)http_server_state_free);

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

    mgr->priv->active_paths = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                     g_free,
                                                     (GDestroyNotify)active_paths_info_free);
    pthread_mutex_init (&mgr->priv->paths_lock, NULL);

#ifdef WIN32
    mgr->priv->refresh_paths = g_async_queue_new ();
#endif

    return mgr;
}

static SyncInfo*
get_sync_info (SeafSyncManager *manager, const char *repo_id)
{
    SyncInfo *info = g_hash_table_lookup (manager->sync_infos, repo_id);
    if (info) return info;

    info = g_new0 (SyncInfo, 1);
    memcpy (info->repo_id, repo_id, 36);
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
    HttpTxTask *http_task;

    mgr->last_sent_bytes = g_atomic_int_get (&mgr->sent_bytes);
    g_atomic_int_set (&mgr->sent_bytes, 0);
    mgr->last_recv_bytes = g_atomic_int_get (&mgr->recv_bytes);
    g_atomic_int_set (&mgr->recv_bytes, 0);

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

#ifdef WIN32
static void *
refresh_windows_explorer_thread (void *vdata);

#define STARTUP_REFRESH_WINDOWS_DELAY 10000

static int
refresh_all_windows_on_startup (void *vdata)
{
    /* This is a hack to tell Windows Explorer to refresh all open windows.
     * On startup, if there is one big library, its events may dominate the
     * explorer refresh queue. Other libraries don't get refreshed until
     * the big library's events are consumed. So we refresh the open windows
     * to reduce the delay.
     */
    SHChangeNotify (SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);

    /* One time */
    return 0;
}
#endif

static void *update_cached_head_commit_ids (void *arg);

int
seaf_sync_manager_start (SeafSyncManager *mgr)
{
    mgr->priv->check_sync_timer = seaf_timer_new (
        auto_sync_pulse, mgr, CHECK_SYNC_INTERVAL);

    mgr->priv->update_tx_state_timer = seaf_timer_new (
        update_tx_state, mgr, UPDATE_TX_STATE_INTERVAL);

    g_signal_connect (seaf, "repo-http-fetched",
                      (GCallback)on_repo_http_fetched, mgr);
    g_signal_connect (seaf, "repo-http-uploaded",
                      (GCallback)on_repo_http_uploaded, mgr);

#ifdef WIN32
    seaf_job_manager_schedule_job (seaf->job_mgr,
                                   refresh_windows_explorer_thread,
                                   NULL,
                                   mgr->priv->refresh_paths);

    mgr->priv->refresh_windows_timer = seaf_timer_new (
        refresh_all_windows_on_startup, mgr, STARTUP_REFRESH_WINDOWS_DELAY);
#endif

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create (&tid, &attr, update_cached_head_commit_ids, mgr) < 0) {
        seaf_warning ("Failed to create update cached head commit id thread.\n");
        return -1;
    }

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

#ifdef USE_GPL_CRYPTO
    if (repo->version == 0 || (repo->encrypted && repo->enc_version < 2)) {
        seaf_warning ("Don't support syncing old version libraries.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Don't support syncing old version libraries");
        return -1;
    }
#endif

    SyncInfo *info = get_sync_info (mgr, repo->id);

    if (info->in_sync)
        return 0;

    if (repo->version > 0) {
        if (check_http_protocol (mgr, repo)) {
            sync_repo_v2 (mgr, repo, TRUE);
            return 0;
        }
    } else {
        seaf_warning ("Repo %s(%s) is version 0 library. Syncing is no longer supported.\n",
                      repo->name, repo->id);
    }

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

    if (!info)
        return;
    else if (!info->in_sync) {
        if (info->current_task && info->current_task->state == SYNC_STATE_ERROR) {
            info->err_cnt = 0;
            info->in_error = FALSE;
            info->sync_perm_err_cnt = 0;
        }
        return;
    }

    g_return_if_fail (info->current_task != NULL);
    task = info->current_task;

    switch (task->state) {
    case SYNC_STATE_FETCH:
        http_tx_manager_cancel_task (seaf->http_tx_mgr,
                                     repo_id,
                                     HTTP_TASK_TYPE_DOWNLOAD);
        transition_sync_state (task, SYNC_STATE_CANCEL_PENDING);
        break;
    case SYNC_STATE_UPLOAD:
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
notify_sync (SeafRepo *repo, gboolean is_multipart_upload)
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
    g_string_append_printf (buf, "%s\t%s\t%s\t%s\t%s",
                            repo->name,
                            repo->id,
                            head->commit_id,
                            head->parent_id,
                            head->desc);
    if (!is_multipart_upload)
        seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                              "sync.done",
                                              buf->str);
    else
        seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                              "sync.multipart_upload",
                                              buf->str);
    g_string_free (buf, TRUE);
    seaf_commit_unref (head);
}

#define IN_ERROR_THRESHOLD 3

static gboolean
is_perm_error (int error)
{
    return (error == SYNC_ERROR_ID_ACCESS_DENIED ||
            error == SYNC_ERROR_ID_NO_WRITE_PERMISSION ||
            error == SYNC_ERROR_ID_PERM_NOT_SYNCABLE ||
            error == SYNC_ERROR_ID_FOLDER_PERM_DENIED);
}

static void
update_sync_info_error_state (SyncTask *task, int new_state)
{
    SyncInfo *info = task->info;

    if (new_state == SYNC_STATE_ERROR) {
        info->err_cnt++;
        if (info->err_cnt == IN_ERROR_THRESHOLD)
            info->in_error = TRUE;
        if (is_perm_error(task->error))
            info->sync_perm_err_cnt++;
    } else if (info->err_cnt > 0) {
        info->err_cnt = 0;
        info->in_error = FALSE;
        info->sync_perm_err_cnt = 0;
    }
}

static void commit_repo (SyncTask *task);

static void
transition_sync_state (SyncTask *task, int new_state)
{
    g_return_if_fail (new_state >= 0 && new_state < SYNC_STATE_NUM);

    SyncInfo *info = task->info;

    if (task->state != new_state) {
        if (((task->state == SYNC_STATE_INIT && task->uploaded) ||
             task->state == SYNC_STATE_FETCH) &&
            new_state == SYNC_STATE_DONE &&
            need_notify_sync(task->repo))
            notify_sync (task->repo, (info->multipart_upload && !info->end_multipart_upload));

        /* If we're in the process of uploading large set of files, they'll be splitted
         * into multiple batches for upload. We want to immediately start the next batch
         * after previous one is done.
         */
        if (new_state == SYNC_STATE_DONE &&
            info->multipart_upload &&
            !info->end_multipart_upload) {
            commit_repo (task);
            return;
        }

        /* If file error levels occured during sync, the whole sync process can still finish
         * with DONE state. But we need to notify the user about this error in the interface.
         * Such file level errors are set with seaf_sync_manager_set_task_error_code().
         */
        if (new_state != SYNC_STATE_ERROR && task->error != SYNC_ERROR_ID_NO_ERROR
            && task->error != SYNC_ERROR_ID_INVALID_PATH_ON_WINDOWS) {
            new_state = SYNC_STATE_ERROR;
            seaf_message ("Repo '%s' sync is finished but with error: %s\n",
                          task->repo->name,
                          sync_error_id_to_str(task->error));
        }

        if (!(task->state == SYNC_STATE_DONE && new_state == SYNC_STATE_INIT) &&
            !(task->state == SYNC_STATE_INIT && new_state == SYNC_STATE_DONE)) {
            seaf_message ("Repo '%s' sync state transition from '%s' to '%s'.\n",
                          task->repo->name,
                          sync_state_str[task->state],
                          sync_state_str[new_state]);
        }

        task->state = new_state;
        if (new_state == SYNC_STATE_DONE || 
            new_state == SYNC_STATE_CANCELED ||
            new_state == SYNC_STATE_ERROR) {
            info->in_sync = FALSE;
            --(task->mgr->n_running_tasks);
            update_sync_info_error_state (task, new_state);

            /* Keep previous upload progress if sync task is canceled or failed. */
            if (new_state == SYNC_STATE_DONE) {
                info->multipart_upload = FALSE;
                info->end_multipart_upload = FALSE;
                info->total_bytes = 0;
                info->uploaded_bytes = 0;
            }
        }

#ifdef WIN32
        seaf_sync_manager_add_refresh_path (seaf->sync_mgr, task->repo->worktree);
#endif
    }
}

static void
set_task_error (SyncTask *task, int error)
{
    g_return_if_fail (error >= 0 && error < N_SYNC_ERROR_ID);

    const char *err_str = sync_error_id_to_str(error);
    int err_level = sync_error_level(error);

    if (task->state != SYNC_STATE_ERROR) {
        seaf_message ("Repo '%s' sync state transition from %s to '%s': '%s'.\n",
                      task->repo->name,
                      sync_state_str[task->state],
                      sync_state_str[SYNC_STATE_ERROR],
                      err_str);
        task->state = SYNC_STATE_ERROR;
        task->error = error;
        task->info->in_sync = FALSE;
        --(task->mgr->n_running_tasks);
        update_sync_info_error_state (task, SYNC_STATE_ERROR);

        /* For repo-level errors, only need to record in database, but not send notifications.
         * File-level errors are recorded and notified in the location they happens, not here.
         */
        if (err_level == SYNC_ERROR_LEVEL_REPO)
            seaf_repo_manager_record_sync_error (task->repo->id, task->repo->name, NULL, error);

#ifdef WIN32
        seaf_sync_manager_add_refresh_path (seaf->sync_mgr, task->repo->worktree);
#endif

    }
}

void
seaf_sync_manager_set_task_error_code (SeafSyncManager *mgr,
                                       const char *repo_id,
                                       int error)
{
    SyncInfo *info = g_hash_table_lookup (mgr->sync_infos, repo_id);
    if (!info)
        return;

    info->current_task->error = error;
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

    if (http_tx_manager_add_upload (seaf->http_tx_mgr,
                                    repo->id,
                                    repo->version,
                                    repo->effective_host,
                                    repo->token,
                                    task->http_version,
                                    repo->use_fileserver_port,
                                    &error) < 0) {
        seaf_warning ("Failed to start http upload: %s\n", error->message);
        set_task_error (task, SYNC_ERROR_ID_NOT_ENOUGH_MEMORY);
        return;
    }
    task->tx_id = g_strdup(repo->id);

    transition_sync_state (task, SYNC_STATE_UPLOAD);
}

static void
start_fetch_if_necessary (SyncTask *task, const char *remote_head)
{
    GError *error = NULL;
    SeafRepo *repo = task->repo;

    if (http_tx_manager_add_download (seaf->http_tx_mgr,
                                      repo->id,
                                      repo->version,
                                      repo->effective_host,
                                      repo->token,
                                      remote_head,
                                      FALSE,
                                      NULL, NULL,
                                      task->http_version,
                                      repo->email,
                                      repo->use_fileserver_port,
                                      repo->name,
                                      &error) < 0) {
        seaf_warning ("Failed to start http download: %s.\n", error->message);
        set_task_error (task, SYNC_ERROR_ID_NOT_ENOUGH_MEMORY);
        return;
    }
    task->tx_id = g_strdup(repo->id);

    transition_sync_state (task, SYNC_STATE_FETCH);
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

#if defined WIN32 || defined __APPLE__

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

#if defined WIN32 || defined __APPLE__
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
#else
    seaf_block_manager_remove_store (seaf->block_mgr, task->repo->id);
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
on_repo_deleted_on_server (SyncTask *task, SeafRepo *repo)
{
    set_task_error (task, SYNC_ERROR_ID_SERVER_REPO_DELETED);

    seaf_warning ("repo %s(%.8s) not found on server\n",
                  repo->name, repo->id);

    if (!seafile_session_config_get_allow_repo_not_found_on_server(seaf)) {
        seaf_message ("remove repo %s(%.8s) since it's deleted on relay\n",
                      repo->name, repo->id);
        /* seaf_mq_manager_publish_notification (seaf->mq_mgr, */
        /*                                       "repo.deleted_on_relay", */
        /*                                       repo->name); */
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
    }
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
        set_task_error (task, SYNC_ERROR_ID_LOCAL_DATA_CORRUPT);
        return;
    }

    master = seaf_branch_manager_get_branch (
        seaf->branch_mgr, info->repo_id, "master");
    if (!master) {
        seaf_warning ("[sync-mgr] Branch master not found for repo %s(%.8s).\n",
                   repo->name, repo->id);
        set_task_error (task, SYNC_ERROR_ID_LOCAL_DATA_CORRUPT);
        return;
    }

    if (info->repo_corrupted) {
        set_task_error (task, SYNC_ERROR_ID_SERVER_REPO_CORRUPT);
    } else if (info->deleted_on_relay) {
        on_repo_deleted_on_server (task, repo);
    } else {
        /* If local head is the same as remote head, already in sync. */
        if (strcmp (local->commit_id, info->head_commit) == 0) {
            /* As long as the repo is synced with the server. All the local
             * blocks are not useful any more.
             */
            if (repo_block_store_exists (repo)) {
                seaf_message ("Removing blocks for repo %s(%.8s).\n",
                              repo->name, repo->id);
                seaf_job_manager_schedule_job (seaf->job_mgr,
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
check_head_commit_done (HttpHeadCommit *result, void *user_data)
{
    SyncTask *task = user_data;
    SyncInfo *info = task->info;

    if (!result->check_success) {
        set_task_error (task, result->error_code);
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
                                                 repo->effective_host,
                                                 repo->token,
                                                 repo->use_fileserver_port,
                                                 check_head_commit_done,
                                                 task);
    if (ret == 0)
        transition_sync_state (task, SYNC_STATE_INIT);
    else if (ret < 0)
        set_task_error (task, SYNC_ERROR_ID_NOT_ENOUGH_MEMORY);

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

    char *commit_id = seaf_repo_index_commit (repo,
                                              task->is_manual_sync,
                                              task->is_initial_commit,
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
        set_task_error (res->task, SYNC_ERROR_ID_INDEX_ERROR);
        g_free (res);
        return;
    }

    if (res->changed)
        start_upload_if_necessary (res->task);
    else if (task->is_manual_sync || task->is_initial_commit)
        check_head_commit_http (task);
    else
        transition_sync_state (task, SYNC_STATE_DONE);

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
        task->commit_timer = seaf_timer_new (check_commit_state, task, 1000);
        return;
    }

    task->mgr->commit_job_running = TRUE;

    transition_sync_state (task, SYNC_STATE_COMMIT);

    if (seaf_job_manager_schedule_job (seaf->job_mgr, 
                                       commit_job, 
                                       commit_job_done,
                                       task) < 0)
        set_task_error (task, SYNC_ERROR_ID_NOT_ENOUGH_MEMORY);
}

static int
check_commit_state (void *data)
{
    SyncTask *task = data;

    if (!task->mgr->commit_job_running) {
        seaf_timer_free (&task->commit_timer);
        commit_repo (task);
        return 0;
    }

    return 1;
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
    task->error = SYNC_ERROR_ID_NO_ERROR;

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
            task->http_version = state->http_version;
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

static gboolean
need_check_on_server (SeafSyncManager *manager, SeafRepo *repo, const char *master_head_id)
{
#define HEAD_COMMIT_MAP_TTL 90
    HttpServerState *state;
    gboolean ret = FALSE;
    SyncInfo *info;

    /* If sync state is in error, always retry. */
    info = get_sync_info (manager, repo->id);
    if (info && info->current_task && info->current_task->state == SYNC_STATE_ERROR)
        return TRUE;

    state = g_hash_table_lookup (manager->http_server_states, repo->server_url);
    if (!state)
        return TRUE;

    pthread_mutex_lock (&state->head_commit_map_lock);

    if (!state->head_commit_map_init) {
        ret = TRUE;
        goto out;
    }

    gint64 now = (gint64)time(NULL);
    if (now - state->last_update_head_commit_map_time >= HEAD_COMMIT_MAP_TTL) {
        ret = TRUE;
        goto out;
    }

    char *server_head = g_hash_table_lookup (state->head_commit_map, repo->id);
    if (!server_head) {
        /* Repo was removed on server. Just return "changed on server". */
        ret = TRUE;
        goto out;
    }
    if (g_strcmp0 (server_head, master_head_id) != 0)
        ret = TRUE;

out:
    pthread_mutex_unlock (&state->head_commit_map_lock);
    return ret;
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
        /* If file syncing protocol version is higher than 2, we check for all head commit ids
         * for synced repos regularly.
         */
        if (!is_manual_sync && !need_check_on_server (manager, repo, master->commit_id)) {
            seaf_debug ("Repo %s is not changed on server %s.\n", repo->name, repo->server_url);
            repo->last_sync_time = time(NULL);
            goto out;
        }

        task = create_sync_task_v2 (manager, repo, is_manual_sync, FALSE);
        check_head_commit_http (task);
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

    seaf_sync_manager_cancel_sync_task (seaf->sync_mgr, repo->id);

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

static char *
http_fileserver_url (const char *url)
{
    const char *host;
    char *colon;
    char *url_no_port;
    char *ret = NULL;

    /* Just return the url itself if it's invalid. */
    if (strlen(url) <= strlen("http://"))
        return g_strdup(url);

    /* Skip protocol schem. */
    host = url + strlen("http://");

    colon = strrchr (host, ':');
    if (colon) {
        url_no_port = g_strndup(url, colon - url);
        ret = g_strconcat(url_no_port, ":8082", NULL);
        g_free (url_no_port);
    } else {
        ret = g_strconcat(url, ":8082", NULL);
    }

    return ret;
}

static void
check_http_fileserver_protocol_done (HttpProtocolVersion *result, void *user_data)
{
    HttpServerState *state = user_data;

    state->checking = FALSE;

    if (result->check_success && !result->not_supported) {
        state->http_version = MIN(result->version, CURRENT_SYNC_PROTO_VERSION);
        state->effective_host = http_fileserver_url(state->testing_host);
        state->use_fileserver_port = TRUE;
        seaf_message ("File syncing protocol version on server %s is %d. "
                      "Client file syncing protocol version is %d. Use version %d.\n",
                      state->effective_host, result->version, CURRENT_SYNC_PROTO_VERSION,
                      state->http_version);
    }
}

static void
check_http_protocol_done (HttpProtocolVersion *result, void *user_data)
{
    HttpServerState *state = user_data;

    if (result->check_success && !result->not_supported) {
        state->http_version = MIN(result->version, CURRENT_SYNC_PROTO_VERSION);
        state->effective_host = g_strdup(state->testing_host);
        state->checking = FALSE;
        seaf_message ("File syncing protocol version on server %s is %d. "
                      "Client file syncing protocol version is %d. Use version %d.\n",
                      state->effective_host, result->version, CURRENT_SYNC_PROTO_VERSION,
                      state->http_version);
    } else if (strncmp(state->testing_host, "https", 5) != 0) {
        char *host_fileserver = http_fileserver_url(state->testing_host);
        if (http_tx_manager_check_protocol_version (seaf->http_tx_mgr,
                                                    host_fileserver,
                                                    TRUE,
                                                    check_http_fileserver_protocol_done,
                                                    state) < 0)
            state->checking = FALSE;
        g_free (host_fileserver);
    } else {
        state->checking = FALSE;
    }
}

#define CHECK_HTTP_INTERVAL 10

/*
 * Returns TRUE if we're ready to use http-sync; otherwise FALSE.
 */
static gboolean
check_http_protocol (SeafSyncManager *mgr, SeafRepo *repo)
{
    /* If a repo was cloned before 4.0, server-url is not set. */
    if (!repo->server_url)
        return FALSE;

    HttpServerState *state = g_hash_table_lookup (mgr->http_server_states,
                                                  repo->server_url);
    if (!state) {
        state = http_server_state_new ();
        g_hash_table_insert (mgr->http_server_states,
                             g_strdup(repo->server_url), state);
    }

    if (state->checking) {
        return FALSE;
    }

    if (state->http_version > 0) {
        if (!repo->effective_host) {
            repo->effective_host = g_strdup(state->effective_host);
            repo->use_fileserver_port = state->use_fileserver_port;
        }
        return TRUE;
    }

    /* If we haven't detected the server url successfully, retry every 10 seconds. */
    gint64 now = time(NULL);
    if (now - state->last_http_check_time < CHECK_HTTP_INTERVAL)
        return FALSE;

    /* First try repo->server_url.
     * If it fails and https is not used, try server_url:8082 instead.
     */
    g_free (state->testing_host);
    state->testing_host = g_strdup(repo->server_url);

    state->last_http_check_time = (gint64)time(NULL);

    if (http_tx_manager_check_protocol_version (seaf->http_tx_mgr,
                                                repo->server_url,
                                                FALSE,
                                                check_http_protocol_done,
                                                state) < 0)
        return FALSE;

    state->checking = TRUE;

    return FALSE;
}

gint
cmp_repos_by_sync_time (gconstpointer a, gconstpointer b, gpointer user_data)
{
    const SeafRepo *repo_a = a;
    const SeafRepo *repo_b = b;

    return (repo_a->last_sync_time - repo_b->last_sync_time);
}

#if defined WIN32 || defined __APPLE__

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
    gboolean locked_on_server = FALSE;
    struct cache_entry *ce;
    char file_id[41];
    char *fullpath = NULL;
    SeafStat st;
    gboolean file_exists = TRUE;
    SeafileCrypt *crypt = NULL;
    SeafBranch *master = NULL;
    gboolean ret = TRUE;

    locked_on_server = seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                             repo->id,
                                                             path);
    /* File is still locked, do nothing. */
    if (do_check_file_locked (path, repo->worktree, locked_on_server))
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
                                       &conflicted,
                                       repo->email) < 0) {
        seaf_warning ("Failed to checkout previously locked file %s in repo "
                      "%s(%.8s).\n",
                      path, repo->name, repo->id);
    }

    seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                          repo->id,
                                          path,
                                          S_IFREG,
                                          SYNC_STATUS_SYNCED,
                                          TRUE);

    /* In checkout, the file was overwritten by rename, so the file attributes
       are gone. We have to set read-only state again.
    */
    if (locked_on_server)
        seaf_filelock_manager_lock_wt_file (seaf->filelock_mgr,
                                            repo->id,
                                            path);

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
    gboolean locked_on_server = FALSE;
    char *fullpath = NULL;
    SeafStat st;
    gboolean file_exists = TRUE;
    gboolean ret = TRUE;

    locked_on_server = seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                             repo->id,
                                                             path);

    /* File is still locked, do nothing. */
    if (do_check_file_locked (path, repo->worktree, locked_on_server))
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

    SyncInfo *info;
    for (ptr = result->results; ptr; ptr = ptr->next) {
        res = ptr->data;

        info = get_sync_info (seaf->sync_mgr, res->repo_id);
        if (info->in_sync)
            continue;

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

    if (!seaf_repo_manager_server_is_pro (seaf->repo_mgr, host))
        return;

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

        g_free (token);
    }

    if (!requests)
        return;

    server_state->checking_folder_perms = TRUE;

    /* The requests list will be freed in http tx manager. */
    if (http_tx_manager_get_folder_perms (seaf->http_tx_mgr,
                                          server_state->effective_host,
                                          server_state->use_fileserver_port,
                                          requests,
                                          check_folder_perms_done,
                                          server_state) < 0) {
        seaf_warning ("Failed to schedule check folder permissions\n");
        server_state->checking_folder_perms = FALSE;
    }
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

static void
check_server_locked_files_done (HttpLockedFiles *result, void *user_data)
{
    HttpServerState *server_state = user_data;
    GList *ptr;
    HttpLockedFilesRes *locked_res;
    gint64 now = (gint64)time(NULL);

    server_state->checking_locked_files = FALSE;

    if (!result->success) {
        /* If on star-up we find that checking locked files fails,
         * we assume the server doesn't support it.
         */
        if (server_state->last_check_locked_files_time == 0)
            server_state->locked_files_not_supported = TRUE;
        server_state->last_check_locked_files_time = now;
        return;
    }

    SyncInfo *info;
    for (ptr = result->results; ptr; ptr = ptr->next) {
        locked_res = ptr->data;

        info = get_sync_info (seaf->sync_mgr, locked_res->repo_id);
        if (info->in_sync)
            continue;

        seaf_filelock_manager_update (seaf->filelock_mgr,
                                      locked_res->repo_id,
                                      locked_res->locked_files);

        seaf_filelock_manager_update_timestamp (seaf->filelock_mgr,
                                                locked_res->repo_id,
                                                locked_res->timestamp);
    }

    server_state->last_check_locked_files_time = now;
}

static void
check_locked_files_one_server (SeafSyncManager *mgr,
                               const char *host,
                               HttpServerState *server_state,
                               GList *repos)
{
    GList *ptr;
    SeafRepo *repo;
    char *token;
    gint64 timestamp;
    HttpLockedFilesReq *req;
    GList *requests = NULL;

    if (!seaf_repo_manager_server_is_pro (seaf->repo_mgr, host))
        return;

    gint64 now = (gint64)time(NULL);

    if (server_state->http_version == 0 ||
        server_state->locked_files_not_supported ||
        server_state->checking_locked_files)
        return;

    if (server_state->last_check_locked_files_time > 0 &&
        now - server_state->last_check_locked_files_time < CHECK_FOLDER_PERMS_INTERVAL)
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

        timestamp = seaf_filelock_manager_get_timestamp (seaf->filelock_mgr,
                                                         repo->id);
        if (timestamp < 0)
            timestamp = 0;

        req = g_new0 (HttpLockedFilesReq, 1);
        memcpy (req->repo_id, repo->id, 36);
        req->token = g_strdup(token);
        req->timestamp = timestamp;

        requests = g_list_append (requests, req);

        g_free (token);
    }

    if (!requests)
        return;

    server_state->checking_locked_files = TRUE;

    /* The requests list will be freed in http tx manager. */
    if (http_tx_manager_get_locked_files (seaf->http_tx_mgr,
                                          server_state->effective_host,
                                          server_state->use_fileserver_port,
                                          requests,
                                          check_server_locked_files_done,
                                          server_state) < 0) {
        seaf_warning ("Failed to schedule check server locked files\n");
        server_state->checking_locked_files = FALSE;
    }
}

static void
check_server_locked_files (SeafSyncManager *mgr, GList *repos)
{
    GHashTableIter iter;
    gpointer key, value;
    char *host;
    HttpServerState *state;

    g_hash_table_iter_init (&iter, mgr->http_server_states);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        host = key;
        state = value;
        check_locked_files_one_server (mgr, host, state, repos);
    }
}

#if 0
static void
print_active_paths (SeafSyncManager *mgr)
{
    int n = seaf_sync_manager_active_paths_number(mgr);
    seaf_message ("%d active paths\n\n", n);
    if (n < 10) {
        char *paths_json = seaf_sync_manager_list_active_paths_json (mgr);
        seaf_message ("%s\n", paths_json);
        g_free (paths_json);
    }
}
#endif

inline static gboolean
periodic_sync_due (SeafRepo *repo)
{
    int now = (int)time(NULL);
    return (now > (repo->last_sync_time + repo->sync_interval));
}

static int
auto_sync_pulse (void *vmanager)
{
    SeafSyncManager *manager = vmanager;
    GList *repos, *ptr;
    SeafRepo *repo;

    repos = seaf_repo_manager_get_repo_list (manager->seaf->repo_mgr, -1, -1);

    check_folder_permissions (manager, repos);

    check_server_locked_files (manager, repos);

    /* Sort repos by last_sync_time, so that we don't "starve" any repo. */
    repos = g_list_sort_with_data (repos, cmp_repos_by_sync_time, NULL);

    for (ptr = repos; ptr != NULL; ptr = ptr->next) {
        repo = ptr->data;

        if (!manager->priv->auto_sync_enabled || !repo->auto_sync)
            continue;

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

#ifdef USE_GPL_CRYPTO
        if (repo->version == 0 || (repo->encrypted && repo->enc_version < 2)) {
            continue;
        }
#endif

        if (!repo->token) {
            /* If the user has logged out of the account, the repo token would
             * be null */
            seaf_debug ("repo token of %s (%.8s) is null, would not sync it\n", repo->name, repo->id);
            continue;
        }

        /* Don't sync repos not checked out yet. */
        if (!repo->head)
            continue;

#if defined WIN32 || defined __APPLE__
        if (repo->version > 0) {
            if (repo->checking_locked_files)
                continue;

            gint64 now = (gint64)time(NULL);
            if (repo->last_check_locked_time == 0 ||
                now - repo->last_check_locked_time >= CHECK_LOCKED_FILES_INTERVAL)
            {
                repo->checking_locked_files = TRUE;
                if (seaf_job_manager_schedule_job (seaf->job_mgr,
                                                   check_locked_files,
                                                   check_locked_files_done,
                                                   repo) < 0) {
                    seaf_warning ("Failed to schedule check local locked files\n");
                    repo->checking_locked_files = FALSE;
                } else {
                    repo->last_check_locked_time = now;
                }

            }
        }
#endif

        SyncInfo *info = get_sync_info (manager, repo->id);

        if (info->in_sync)
            continue;

        if (info->sync_perm_err_cnt > SYNC_PERM_ERROR_RETRY_TIME)
            continue;

        if (repo->version > 0) {
            /* For repo version > 0, only use http sync. */
            if (check_http_protocol (manager, repo)) {
                if (repo->sync_interval == 0)
                    sync_repo_v2 (manager, repo, FALSE);
                else if (periodic_sync_due (repo))
                    sync_repo_v2 (manager, repo, TRUE);
            }
        } else {
            seaf_warning ("Repo %s(%s) is version 0 library. Syncing is no longer supported.\n",
                          repo->name, repo->id);
        }
    }

    g_list_free (repos);
    return TRUE;
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
        if (tx_task->error == SYNC_ERROR_ID_SERVER_REPO_DELETED) {
            on_repo_deleted_on_server (task, task->repo);
        } else {
            set_task_error (task, tx_task->error);
        }
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
        if (tx_task->error == SYNC_ERROR_ID_SERVER_REPO_DELETED) {
            on_repo_deleted_on_server (task, task->repo);
        } else {
            set_task_error (task, tx_task->error);
        }
    }
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
disable_auto_sync_for_repos (SeafSyncManager *mgr)
{
    GList *repos;
    GList *ptr;
    SeafRepo *repo;

    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    for (ptr = repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        if (repo->sync_interval == 0)
            seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo->id);
        seaf_sync_manager_cancel_sync_task (mgr, repo->id);
        seaf_sync_manager_remove_active_path_info (mgr, repo->id);
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

    disable_auto_sync_for_repos (mgr);

    mgr->priv->auto_sync_enabled = FALSE;
    g_debug ("[sync mgr] auto sync is disabled\n");
    return 0;
}

static void
enable_auto_sync_for_repos (SeafSyncManager *mgr)
{
    GList *repos;
    GList *ptr;
    SeafRepo *repo;

    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    for (ptr = repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        if (repo->sync_interval == 0)
            seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree);
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

    enable_auto_sync_for_repos (mgr);

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

static ActivePathsInfo *
active_paths_info_new (SeafRepo *repo)
{
    ActivePathsInfo *info = g_new0 (ActivePathsInfo, 1);

    info->paths = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    info->syncing_tree = sync_status_tree_new (repo->worktree);
    info->synced_tree = sync_status_tree_new (repo->worktree);

    return info;
}

static void
active_paths_info_free (ActivePathsInfo *info)
{
    if (!info)
        return;
    g_hash_table_destroy (info->paths);
    sync_status_tree_free (info->syncing_tree);
    sync_status_tree_free (info->synced_tree);
    g_free (info);
}

void
seaf_sync_manager_update_active_path (SeafSyncManager *mgr,
                                      const char *repo_id,
                                      const char *path,
                                      int mode,
                                      SyncStatus status,
                                      gboolean refresh)
{
    ActivePathsInfo *info;
    SeafRepo *repo;

    if (!repo_id || !path) {
        seaf_warning ("BUG: empty repo_id or path.\n");
        return;
    }

    if (status <= SYNC_STATUS_NONE || status >= N_SYNC_STATUS) {
        seaf_warning ("BUG: invalid sync status %d.\n", status);
        return;
    }

    pthread_mutex_lock (&mgr->priv->paths_lock);

    info = g_hash_table_lookup (mgr->priv->active_paths, repo_id);
    if (!info) {
        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!repo) {
            pthread_mutex_unlock (&mgr->priv->paths_lock);
            return;
        }
        info = active_paths_info_new (repo);
        g_hash_table_insert (mgr->priv->active_paths, g_strdup(repo_id), info);
    }

    SyncStatus existing = (SyncStatus) g_hash_table_lookup (info->paths, path);
    if (!existing) {
        g_hash_table_insert (info->paths, g_strdup(path), (void*)status);
        if (status == SYNC_STATUS_SYNCING)
            sync_status_tree_add (info->syncing_tree, path, mode, refresh);
        else if (status == SYNC_STATUS_SYNCED)
            sync_status_tree_add (info->synced_tree, path, mode, refresh);
#ifdef WIN32
        else if (refresh)
            seaf_sync_manager_add_refresh_path (mgr, path);
#endif
    } else if (existing != status) {
        g_hash_table_replace (info->paths, g_strdup(path), (void*)status);

        if (existing == SYNC_STATUS_SYNCING)
            sync_status_tree_del (info->syncing_tree, path);
        else if (existing == SYNC_STATUS_SYNCED)
            sync_status_tree_del (info->synced_tree, path);

        if (status == SYNC_STATUS_SYNCING)
            sync_status_tree_add (info->syncing_tree, path, mode, refresh);
        else if (status == SYNC_STATUS_SYNCED)
            sync_status_tree_add (info->synced_tree, path, mode, refresh);
#ifdef WIN32
        else if (refresh)
            seaf_sync_manager_add_refresh_path (mgr, path);
#endif
    }

    pthread_mutex_unlock (&mgr->priv->paths_lock);
}

void
seaf_sync_manager_delete_active_path (SeafSyncManager *mgr,
                                      const char *repo_id,
                                      const char *path)
{
    ActivePathsInfo *info;

    if (!repo_id || !path) {
        seaf_warning ("BUG: empty repo_id or path.\n");
        return;
    }

    pthread_mutex_lock (&mgr->priv->paths_lock);

    info = g_hash_table_lookup (mgr->priv->active_paths, repo_id);
    if (!info) {
        pthread_mutex_unlock (&mgr->priv->paths_lock);
        return;
    }

    g_hash_table_remove (info->paths, path);
    sync_status_tree_del (info->syncing_tree, path);
    sync_status_tree_del (info->synced_tree, path);

    pthread_mutex_unlock (&mgr->priv->paths_lock);
}

static char *path_status_tbl[] = {
    "none",
    "syncing",
    "error",
    "ignored",
    "synced",
    "paused",
    "readonly",
    "locked",
    "locked_by_me",
    NULL,
};

static char *
get_repo_sync_status (SeafSyncManager *mgr, const char *repo_id)
{
    SyncInfo *info = get_sync_info (mgr, repo_id);
    SeafRepo *repo;

    if (info->in_error)
        return g_strdup(path_status_tbl[SYNC_STATUS_ERROR]);

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo)
        return g_strdup(path_status_tbl[SYNC_STATUS_NONE]);

    if (!repo->auto_sync || !mgr->priv->auto_sync_enabled)
        return g_strdup(path_status_tbl[SYNC_STATUS_PAUSED]);

    char allzeros[41] = {0};
    if (!info->in_sync && memcmp(allzeros, info->head_commit, 41) == 0)
        return g_strdup(path_status_tbl[SYNC_STATUS_NONE]);

    if (info->in_sync &&
        (info->current_task->state == SYNC_STATE_COMMIT ||
         info->current_task->state == SYNC_STATE_FETCH ||
         info->current_task->state == SYNC_STATE_UPLOAD ||
         info->current_task->state == SYNC_STATE_MERGE))
        return g_strdup(path_status_tbl[SYNC_STATUS_SYNCING]);
    else if (!repo->is_readonly)
        return g_strdup(path_status_tbl[SYNC_STATUS_SYNCED]);
    else
        return g_strdup(path_status_tbl[SYNC_STATUS_READONLY]);
}

char *
seaf_sync_manager_get_path_sync_status (SeafSyncManager *mgr,
                                        const char *repo_id,
                                        const char *path,
                                        gboolean is_dir)
{
    ActivePathsInfo *info;
    SyncInfo *sync_info;
    SyncStatus ret = SYNC_STATUS_NONE;

    if (!repo_id || !path) {
        seaf_warning ("BUG: empty repo_id or path.\n");
        return NULL;
    }

    if (path[0] == 0) {
        return get_repo_sync_status (mgr, repo_id);
    }

    /* If the repo is in error, all files in it should show no sync status. */
    sync_info = get_sync_info (mgr, repo_id);
    if (sync_info && sync_info->in_error) {
        ret = SYNC_STATUS_NONE;
        goto out;
    }

    pthread_mutex_lock (&mgr->priv->paths_lock);

    info = g_hash_table_lookup (mgr->priv->active_paths, repo_id);
    if (!info) {
        pthread_mutex_unlock (&mgr->priv->paths_lock);
        ret = SYNC_STATUS_NONE;
        goto out;
    }

    ret = (SyncStatus) g_hash_table_lookup (info->paths, path);
    if (is_dir && (ret == SYNC_STATUS_NONE)) {
        /* If a dir is not in the syncing tree but in the synced tree,
         * it's synced. Otherwise if it's in the syncing tree, some files
         * under it must be syncing, so it should be in syncing status too.
         */
        if (sync_status_tree_exists (info->syncing_tree, path))
            ret = SYNC_STATUS_SYNCING;
        else if (sync_status_tree_exists (info->synced_tree, path))
            ret = SYNC_STATUS_SYNCED;
    }

    pthread_mutex_unlock (&mgr->priv->paths_lock);

    if (ret == SYNC_STATUS_SYNCED) {
        if (!seaf_repo_manager_is_path_writable(seaf->repo_mgr, repo_id, path))
            ret = SYNC_STATUS_READONLY;
        else if (seaf_filelock_manager_is_file_locked_by_me (seaf->filelock_mgr,
                                                             repo_id, path))
            ret = SYNC_STATUS_LOCKED_BY_ME;
        else if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                       repo_id, path))
            ret = SYNC_STATUS_LOCKED;
    }

out:
    return g_strdup(path_status_tbl[ret]);
}

static json_t *
active_paths_to_json (GHashTable *paths)
{
    json_t *array = NULL, *obj = NULL;
    GHashTableIter iter;
    gpointer key, value;
    char *path;
    SyncStatus status;

    array = json_array ();

    g_hash_table_iter_init (&iter, paths);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        path = key;
        status = (SyncStatus)value;

        obj = json_object ();
        json_object_set (obj, "path", json_string(path));
        json_object_set (obj, "status", json_string(path_status_tbl[status]));

        json_array_append (array, obj);
    }

    return array;
}

char *
seaf_sync_manager_list_active_paths_json (SeafSyncManager *mgr)
{
    json_t *array = NULL, *obj = NULL, *path_array = NULL;
    GHashTableIter iter;
    gpointer key, value;
    char *repo_id;
    ActivePathsInfo *info;
    char *ret = NULL;

    pthread_mutex_lock (&mgr->priv->paths_lock);

    array = json_array ();

    g_hash_table_iter_init (&iter, mgr->priv->active_paths);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        repo_id = key;
        info = value;

        obj = json_object();
        path_array = active_paths_to_json (info->paths);
        json_object_set (obj, "repo_id", json_string(repo_id));
        json_object_set (obj, "paths", path_array);

        json_array_append (array, obj);
    }

    pthread_mutex_unlock (&mgr->priv->paths_lock);

    ret = json_dumps (array, JSON_INDENT(4));
    if (!ret) {
        seaf_warning ("Failed to convert active paths to json\n");
    }

    json_decref (array);

    return ret;
}

int
seaf_sync_manager_active_paths_number (SeafSyncManager *mgr)
{
    GHashTableIter iter;
    gpointer key, value;
    ActivePathsInfo *info;
    int ret = 0;

    g_hash_table_iter_init (&iter, mgr->priv->active_paths);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        info = value;
        ret += g_hash_table_size(info->paths);
    }

    return ret;
}

void
seaf_sync_manager_remove_active_path_info (SeafSyncManager *mgr, const char *repo_id)
{
    pthread_mutex_lock (&mgr->priv->paths_lock);

    g_hash_table_remove (mgr->priv->active_paths, repo_id);

    pthread_mutex_unlock (&mgr->priv->paths_lock);

#ifdef WIN32
    /* This is a hack to tell Windows Explorer to refresh all open windows. */
    SHChangeNotify (SHCNE_ASSOCCHANGED, SHCNF_IDLIST, NULL, NULL);
#endif
}

#ifdef WIN32

static wchar_t *
win_path (const char *path)
{
    char *ret = g_strdup(path);
    wchar_t *ret_w;
    char *p;

    for (p = ret; *p != 0; ++p)
        if (*p == '/')
            *p = '\\';

    ret_w = g_utf8_to_utf16 (ret, -1, NULL, NULL, NULL);

    g_free (ret);
    return ret_w;
}

static void *
refresh_windows_explorer_thread (void *vdata)
{
    GAsyncQueue *q = vdata;
    char *path;
    wchar_t *wpath;
    int count = 0;

    while (1) {
        path = g_async_queue_pop (q);
        wpath = win_path (path);

        SHChangeNotify (SHCNE_ATTRIBUTES, SHCNF_PATHW, wpath, NULL);

        g_free (path);
        g_free (wpath);

        if (++count >= 100) {
            g_usleep (G_USEC_PER_SEC);
            count = 0;
        }
    }

    return NULL;
}

void
seaf_sync_manager_add_refresh_path (SeafSyncManager *mgr, const char *path)
{
    g_async_queue_push (mgr->priv->refresh_paths, g_strdup(path));
}

void
seaf_sync_manager_refresh_path (SeafSyncManager *mgr, const char *path)
{
    wchar_t *wpath;

    wpath = win_path (path);
    SHChangeNotify (SHCNE_ATTRIBUTES, SHCNF_PATHW, wpath, NULL);
    g_free (wpath);
}

#endif

static void
update_head_commit_ids_for_server (gpointer key, gpointer value, gpointer user_data)
{
    char *server_url = key;
    HttpServerState *state = value;

    /* Only get head commit ids from server if:
     * 1. syncing protocol version has been checked, and
     * 2. protocol version is at least 2.
     */
    if (state->http_version >= 2) {
        seaf_debug ("Updating repo head commit ids for server %s.\n", server_url);
        GList *repo_id_list = seaf_repo_manager_get_repo_id_list_by_server (seaf->repo_mgr,
                                                                            server_url);
        if (!repo_id_list) {
            return;
        }

        GHashTable *new_map = http_tx_manager_get_head_commit_ids (seaf->http_tx_mgr,
                                                                   state->effective_host,
                                                                   state->use_fileserver_port,
                                                                   repo_id_list);
        if (new_map) {
            pthread_mutex_lock (&state->head_commit_map_lock);
            g_hash_table_destroy (state->head_commit_map);
            state->head_commit_map = new_map;
            if (!state->head_commit_map_init)
                state->head_commit_map_init = TRUE;
            state->last_update_head_commit_map_time = (gint64)time(NULL);
            pthread_mutex_unlock (&state->head_commit_map_lock);
        }

        g_list_free_full (repo_id_list, g_free);
    }
}

static void *
update_cached_head_commit_ids (void *arg)
{
    SeafSyncManager *mgr = (SeafSyncManager *)arg;

    while (1) {
        g_usleep (30 * G_USEC_PER_SEC);

        g_hash_table_foreach (mgr->http_server_states, update_head_commit_ids_for_server, mgr);
    }

    return NULL;
}
