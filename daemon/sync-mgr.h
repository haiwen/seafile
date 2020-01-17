/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SYNC_MGR_H
#define SYNC_MGR_H

typedef struct _SyncInfo SyncInfo;
typedef struct _SyncTask SyncTask;

typedef struct _SeafSyncManager SeafSyncManager;
typedef struct _SeafSyncManagerPriv SeafSyncManagerPriv;

struct SeafTimer;

struct _SyncInfo {
    char       repo_id[41];     /* the repo */
    char       head_commit[41]; /* head commit on relay */
    SyncTask  *current_task;

    gboolean   in_sync;         /* set to FALSE when sync state is DONE or ERROR */

    gint       err_cnt;
    gboolean   in_error;        /* set to TRUE if err_cnt >= 3 */

    gboolean   deleted_on_relay;
    gboolean   branch_deleted_on_relay;
    gboolean   repo_corrupted;
    gboolean   need_fetch;
    gboolean   need_upload;
    gboolean   need_merge;

    /* Used by multipart upload. */
    gboolean   multipart_upload;
    gint64     total_bytes;
    gint64     uploaded_bytes;
    gboolean   end_multipart_upload;

    gint       sync_perm_err_cnt;
};

enum {
    SYNC_STATE_DONE,
    SYNC_STATE_COMMIT,
    SYNC_STATE_INIT,
    SYNC_STATE_FETCH,
    SYNC_STATE_MERGE,
    SYNC_STATE_UPLOAD,
    SYNC_STATE_ERROR,
    SYNC_STATE_CANCELED,
    SYNC_STATE_CANCEL_PENDING,
    SYNC_STATE_NUM,
};

struct _SyncTask {
    SeafSyncManager *mgr;
    SyncInfo        *info;
    char            *dest_id;
    gboolean         is_manual_sync;
    gboolean         is_initial_commit;
    int              state;
    int              error;
    char            *tx_id;
    char            *token;
    struct SeafTimer *commit_timer;

    gboolean         uploaded;

    int              http_version;

    SeafRepo        *repo;  /* for convenience, only valid when in_sync. */
};

enum _SyncStatus {
    SYNC_STATUS_NONE = 0,
    SYNC_STATUS_SYNCING,
    SYNC_STATUS_ERROR,
    SYNC_STATUS_IGNORED,
    SYNC_STATUS_SYNCED,
    SYNC_STATUS_PAUSED,
    SYNC_STATUS_READONLY,
    SYNC_STATUS_LOCKED,
    SYNC_STATUS_LOCKED_BY_ME,
    N_SYNC_STATUS,
};
typedef enum _SyncStatus SyncStatus;

struct _SeafileSession;

struct _SeafSyncManager {
    struct _SeafileSession   *seaf;

    GHashTable *sync_infos;
    int         n_running_tasks;
    gboolean    commit_job_running;
    int         sync_interval;

    GHashTable *http_server_states;

    /* Sent/recv bytes from all transfer tasks in this second.
     * Since we have http and non-http tasks, sync manager is
     * the only reasonable place to put these variables.
     */
    gint             sent_bytes;
    gint             recv_bytes;
    gint             last_sent_bytes;
    gint             last_recv_bytes;
    /* Upload/download rate limits. */
    gint             upload_limit;
    gint             download_limit;

    SeafSyncManagerPriv *priv;
};

SeafSyncManager* seaf_sync_manager_new (struct _SeafileSession *seaf);

int seaf_sync_manager_init (SeafSyncManager *mgr);
int seaf_sync_manager_start (SeafSyncManager *mgr);

int
seaf_sync_manager_add_sync_task (SeafSyncManager *mgr,
                                 const char *repo_id,
                                 GError **error);

void
seaf_sync_manager_cancel_sync_task (SeafSyncManager *mgr,
                                    const char *repo_id);


SyncInfo *
seaf_sync_manager_get_sync_info (SeafSyncManager *mgr,
                                 const char *repo_id);

int
seaf_sync_manager_disable_auto_sync (SeafSyncManager *mgr);

int
seaf_sync_manager_enable_auto_sync (SeafSyncManager *mgr);

int
seaf_sync_manager_is_auto_sync_enabled (SeafSyncManager *mgr);

const char *
sync_state_to_str (int state);

void
seaf_sync_manager_update_active_path (SeafSyncManager *mgr,
                                      const char *repo_id,
                                      const char *path,
                                      int mode,
                                      SyncStatus status,
                                      gboolean refresh);

void
seaf_sync_manager_delete_active_path (SeafSyncManager *mgr,
                                      const char *repo_id,
                                      const char *path);

char *
seaf_sync_manager_get_path_sync_status (SeafSyncManager *mgr,
                                        const char *repo_id,
                                        const char *path,
                                        gboolean is_dir);

char *
seaf_sync_manager_list_active_paths_json (SeafSyncManager *mgr);

int
seaf_sync_manager_active_paths_number (SeafSyncManager *mgr);

void
seaf_sync_manager_remove_active_path_info (SeafSyncManager *mgr, const char *repo_id);

#ifdef WIN32
/* Add to refresh queue */
void
seaf_sync_manager_add_refresh_path (SeafSyncManager *mgr, const char *path);

/* Refresh immediately. */
void
seaf_sync_manager_refresh_path (SeafSyncManager *mgr, const char *path);
#endif

void
seaf_sync_manager_set_task_error_code (SeafSyncManager *mgr,
                                       const char *repo_id,
                                       int error);

#endif
