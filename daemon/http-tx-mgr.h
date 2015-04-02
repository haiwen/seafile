#ifndef HTTP_TX_MGR_H
#define HTTP_TX_MGR_H

enum {
    HTTP_TASK_TYPE_DOWNLOAD = 0,
    HTTP_TASK_TYPE_UPLOAD,
};


/**
 * The state that can be set by user.
 *
 * A task in NORMAL state can be canceled;
 * A task in RT_STATE_FINISHED can be removed.
 */
enum HttpTaskState {
    HTTP_TASK_STATE_NORMAL = 0,
    HTTP_TASK_STATE_CANCELED,
    HTTP_TASK_STATE_FINISHED,
    HTTP_TASK_STATE_ERROR,
    N_HTTP_TASK_STATE,
};

enum HttpTaskRuntimeState {
    HTTP_TASK_RT_STATE_INIT = 0,
    HTTP_TASK_RT_STATE_CHECK,
    HTTP_TASK_RT_STATE_COMMIT,
    HTTP_TASK_RT_STATE_FS,
    HTTP_TASK_RT_STATE_BLOCK,         /* Only used in upload. */
    HTTP_TASK_RT_STATE_UPDATE_BRANCH, /* Only used in upload. */
    HTTP_TASK_RT_STATE_FINISHED,
    N_HTTP_TASK_RT_STATE,
};

enum HttpTaskError {
    HTTP_TASK_OK = 0,
    HTTP_TASK_ERR_FORBIDDEN,
    HTTP_TASK_ERR_NET,
    HTTP_TASK_ERR_SERVER,
    HTTP_TASK_ERR_BAD_REQUEST,
    HTTP_TASK_ERR_BAD_LOCAL_DATA,
    HTTP_TASK_ERR_NOT_ENOUGH_MEMORY,
    HTTP_TASK_ERR_WRITE_LOCAL_DATA,
    HTTP_TASK_ERR_NO_QUOTA,
    HTTP_TASK_ERR_FILES_LOCKED,
    HTTP_TASK_ERR_UNKNOWN,
    N_HTTP_TASK_ERROR,
};

struct _SeafileSession;
struct _HttpTxPriv;

struct _HttpTxManager {
    struct _SeafileSession   *seaf;

    struct _HttpTxPriv *priv;
};

typedef struct _HttpTxManager HttpTxManager;

struct _HttpTxTask {
    HttpTxManager *manager;

    char repo_id[37];
    int repo_version;
    char *token;
    int protocol_version;
    int type;
    char *host;
    gboolean is_clone;

    char head[41];

    char *passwd;
    char *worktree;

    int state;
    int runtime_state;
    int error;

    /* For upload progress */
    int n_blocks;
    int done_blocks;
    /* For download progress */
    int n_files;
    int done_files;

    gint tx_bytes;              /* bytes transferred in this second. */
    gint last_tx_bytes;         /* bytes transferred in the last second. */
};
typedef struct _HttpTxTask HttpTxTask;

HttpTxManager *
http_tx_manager_new (struct _SeafileSession *seaf);

int
http_tx_manager_start (HttpTxManager *mgr);

int
http_tx_manager_add_download (HttpTxManager *manager,
                              const char *repo_id,
                              int repo_version,
                              const char *host,
                              const char *token,
                              const char *server_head_id,
                              gboolean is_clone,
                              const char *passwd,
                              const char *worktree,
                              int protocol_version,
                              GError **error);

int
http_tx_manager_add_upload (HttpTxManager *manager,
                            const char *repo_id,
                            int repo_version,
                            const char *host,
                            const char *token,
                            int protocol_version,
                            GError **error);

struct _HttpProtocolVersion {
    gboolean check_success;     /* TRUE if we get response from the server. */
    gboolean not_supported;
    int version;
};
typedef struct _HttpProtocolVersion HttpProtocolVersion;

typedef void (*HttpProtocolVersionCallback) (HttpProtocolVersion *result,
                                             void *user_data);

/* Asynchronous interface for getting protocol version from a server.
 * Also used to determine if the server support http sync.
 */
int
http_tx_manager_check_protocol_version (HttpTxManager *manager,
                                        const char *host,
                                        HttpProtocolVersionCallback callback,
                                        void *user_data);

struct _HttpHeadCommit {
    gboolean check_success;
    gboolean is_corrupt;
    gboolean is_deleted;
    char head_commit[41];
};
typedef struct _HttpHeadCommit HttpHeadCommit;

typedef void (*HttpHeadCommitCallback) (HttpHeadCommit *result,
                                        void *user_data);

/* Asynchronous interface for getting head commit info from a server. */
int
http_tx_manager_check_head_commit (HttpTxManager *manager,
                                   const char *repo_id,
                                   int repo_version,
                                   const char *host,
                                   const char *token,
                                   HttpHeadCommitCallback callback,
                                   void *user_data);

typedef struct _HttpFolderPermReq {
    char repo_id[37];
    char *token;
    gint64 timestamp;
} HttpFolderPermReq;

typedef struct _HttpFolderPermRes {
    char repo_id[37];
    gint64 timestamp;
    GList *user_perms;
    GList *group_perms;
} HttpFolderPermRes;

void
http_folder_perm_req_free (HttpFolderPermReq *req);

void
http_folder_perm_res_free (HttpFolderPermRes *res);

struct _HttpFolderPerms {
    gboolean success;
    GList *results;             /* List of HttpFolderPermRes */
};
typedef struct _HttpFolderPerms HttpFolderPerms;

typedef void (*HttpGetFolderPermsCallback) (HttpFolderPerms *result,
                                            void *user_data);

/* Asynchronous interface for getting folder permissions for a repo. */
int
http_tx_manager_get_folder_perms (HttpTxManager *manager,
                                  const char *host,
                                  GList *folder_perm_requests, /* HttpFolderPermReq */
                                  HttpGetFolderPermsCallback callback,
                                  void *user_data);

int
http_tx_task_download_file_blocks (HttpTxTask *task, const char *file_id);

GList*
http_tx_manager_get_upload_tasks (HttpTxManager *manager);

GList*
http_tx_manager_get_download_tasks (HttpTxManager *manager);

HttpTxTask *
http_tx_manager_find_task (HttpTxManager *manager, const char *repo_id);

void
http_tx_manager_cancel_task (HttpTxManager *manager,
                             const char *repo_id,
                             int task_type);

int
http_tx_task_get_rate (HttpTxTask *task);

const char *
http_task_state_to_str (int state);

const char *
http_task_rt_state_to_str (int rt_state);

const char *
http_task_error_str (int task_errno);

#endif
