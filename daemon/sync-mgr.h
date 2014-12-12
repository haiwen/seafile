/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SYNC_MGR_H
#define SYNC_MGR_H

typedef struct _SyncInfo SyncInfo;
typedef struct _SyncTask SyncTask;

typedef struct _SeafSyncManager SeafSyncManager;
typedef struct _SeafSyncManagerPriv SeafSyncManagerPriv;

struct CcnetTimer;

struct _SyncInfo {
    char       repo_id[41];     /* the repo */
    char       head_commit[41]; /* head commit on relay */
    SyncTask  *current_task;

    gboolean   in_sync;         /* set to FALSE when sync state is DONE or ERROR */

    gint       err_cnt;
    gboolean   deleted_on_relay;
    gboolean   branch_deleted_on_relay;
    gboolean   repo_corrupted;
    gboolean   need_fetch;
    gboolean   need_upload;
    gboolean   need_merge;
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

enum {
    SYNC_ERROR_NONE,
    SYNC_ERROR_RELAY_OFFLINE,
    SYNC_ERROR_UPGRADE_REPO,
    SYNC_ERROR_RELAY_REMOVED,
    SYNC_ERROR_NOT_LOGIN,
    SYNC_ERROR_SERVICE_DOWN,
    SYNC_ERROR_ACCESS_DENIED,
    SYNC_ERROR_QUOTA_FULL,
    SYNC_ERROR_PROC_PERM_ERR,
    SYNC_ERROR_DATA_CORRUPT,
    SYNC_ERROR_START_UPLOAD,
    SYNC_ERROR_UPLOAD,
    SYNC_ERROR_START_FETCH,
    SYNC_ERROR_FETCH,
    SYNC_ERROR_NOREPO,
    SYNC_ERROR_REPO_CORRUPT,
    SYNC_ERROR_COMMIT,
    SYNC_ERROR_MERGE,
    SYNC_ERROR_WORKTREE_DIRTY,
    SYNC_ERROR_DEPRECATED_SERVER,
    SYNC_ERROR_GET_SYNC_INFO,   /* for http sync */
    SYNC_ERROR_FILES_LOCKED,
    SYNC_ERROR_UNKNOWN,
    SYNC_ERROR_NUM,
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
    struct CcnetTimer *commit_timer;

    gboolean         server_side_merge;
    gboolean         uploaded;

    gboolean         http_sync;
    int              http_version;

    SeafRepo        *repo;  /* for convenience, only valid when in_sync. */
};

struct _SeafileSession;

struct _SeafSyncManager {
    struct _SeafileSession   *seaf;

    GHashTable *sync_infos;
    int         n_running_tasks;
    gboolean    commit_job_running;
    int         sync_interval;

    GHashTable *server_states;
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
sync_error_to_str (int error);

const char *
sync_state_to_str (int state);
#endif
