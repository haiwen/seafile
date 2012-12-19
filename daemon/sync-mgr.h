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
    SYNC_ERROR_UNKNOWN,
    SYNC_ERROR_NUM,
};

struct _SyncTask {
    SeafSyncManager *mgr;
    SyncInfo        *info;
    char            *dest_id;
    gboolean         is_sync_lan;
    gboolean         force_upload;
    gboolean         need_commit;
    gboolean         quiet;     /* don't print log messages. */
    int              state;
    int              error;
    char            *tx_id;
    char            *token;
    struct CcnetTimer *conn_timer;

    SeafRepo        *repo;  /* for convenience, only valid when in_sync. */
};

struct _SeafileSession;

struct _SeafSyncManager {
    struct _SeafileSession   *seaf;

    GHashTable *sync_infos;
    GQueue     *sync_tasks;
    int         n_running_tasks;
    int         sync_interval;

    int         wt_interval;

    SeafSyncManagerPriv *priv;
};

SeafSyncManager* seaf_sync_manager_new (struct _SeafileSession *seaf);

int seaf_sync_manager_init (SeafSyncManager *mgr);
int seaf_sync_manager_start (SeafSyncManager *mgr);

int
seaf_sync_manager_add_sync_task (SeafSyncManager *mgr,
                                 const char *repo_id,
                                 const char *dest_id,
                                 const char *token,
                                 gboolean is_sync_lan,
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
