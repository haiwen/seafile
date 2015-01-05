/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef TRANSFER_MGR_H
#define TRANSFER_MGR_H

#include <glib.h>
#include <ccnet/timer.h>
#include <ccnet/peer.h>

#include "object-list.h"
#include "repo-mgr.h"
#include "fs-mgr.h"
#include "branch-mgr.h"

/*
 * Transfer Task.
 */

enum {
    TASK_TYPE_DOWNLOAD = 0,
    TASK_TYPE_UPLOAD,
};


/**
 * The state that can be set by user.
 *
 * A task in NORMAL state can be canceled;
 * A task in RT_STATE_FINISHED can be removed.
 */
enum TaskState {
    TASK_STATE_NORMAL = 0,
    TASK_STATE_CANCELED,
    TASK_STATE_FINISHED,
    TASK_STATE_ERROR,
    N_TASK_STATE,
};

enum TaskRuntimeState {
    TASK_RT_STATE_INIT = 0,
    TASK_RT_STATE_CHECK,
    TASK_RT_STATE_COMMIT,
    TASK_RT_STATE_FS,
    TASK_RT_STATE_CHECK_BLOCKS,
    TASK_RT_STATE_CHUNK_SERVER,
    TASK_RT_STATE_DATA,
    TASK_RT_STATE_UPDATE_BRANCH, /* Only used in upload. */
    TASK_RT_STATE_FINISHED,
    TASK_RT_STATE_NETDOWN,
    N_TASK_RT_STATE,
};

enum TaskError {
    TASK_OK = 0,
    TASK_ERR_UNKNOWN,
    TASK_ERR_NO_SERVICE,
    TASK_ERR_PROC_PERM_ERR,
    TASK_ERR_CHECK_UPLOAD_START,
    TASK_ERR_CHECK_DOWNLOAD_START,
    TASK_ERR_ACCESS_DENIED,
    TASK_ERR_BAD_REPO_ID,
    TASK_ERR_UPLOAD_COMMIT_START,
    TASK_ERR_DOWNLOAD_COMMIT_START,
    TASK_ERR_UPLOAD_COMMIT,
    TASK_ERR_DOWNLOAD_COMMIT,
    TASK_ERR_UPLOAD_FS_START,
    TASK_ERR_DOWNLOAD_FS_START,
    TASK_ERR_LOAD_FS,
    TASK_ERR_UPLOAD_FS,
    TASK_ERR_DOWNLOAD_FS,
    TASK_ERR_LOAD_BLOCK_LIST,
    TASK_ERR_START_UPDATE_BRANCH,
    TASK_ERR_NOT_FAST_FORWARD,
    TASK_ERR_QUOTA_FULL,
    TASK_ERR_CHECK_QUOTA,
    TASK_ERR_PROTOCOL_VERSION,
    TASK_ERR_BAD_LOCAL_BRANCH,
    TASK_ERR_CHECK_BLOCK_LIST,
    TASK_ERR_GET_CHUNK_SERVER,
    TASK_ERR_START_BLOCK_CLIENT,
    TASK_ERR_UPLOAD_BLOCKS,
    TASK_ERR_DOWNLOAD_BLOCKS,
    TASK_ERR_DEPRECATED_SERVER,
    TASK_ERR_FILES_LOCKED,
    N_TASK_ERROR,
};

typedef struct {
    char *addr;
    int port;
} ChunkServer;

enum {
    BLOCK_CLIENT_UNKNOWN = 0,
    BLOCK_CLIENT_SUCCESS,
    BLOCK_CLIENT_FAILED,
    BLOCK_CLIENT_NET_ERROR,
    BLOCK_CLIENT_SERVER_ERROR,
    BLOCK_CLIENT_CANCELED,

    /* result codes only used in interactive mode. */
    BLOCK_CLIENT_READY,
    BLOCK_CLIENT_ENDED,
};

#define BLOCK_TX_SESSION_KEY_LEN 32

struct _TransferTask;

typedef struct _BlockTxInfo {
    struct _TransferTask *task;
    ChunkServer *cs;
    unsigned char session_key[BLOCK_TX_SESSION_KEY_LEN];
    unsigned char *enc_session_key;      /* encrypted session_key */
    int enc_key_len;
    int cmd_pipe[2];               /* used to notify cancel */
    int done_pipe[2];              /* notify block transfer done */
    int result;
    int n_failure;
    /* TRUE if the client only transfer one batch of blocks and end.*/
    gboolean transfer_once;
    gint ready_for_transfer;
} BlockTxInfo;

struct _SeafTransferManager;

struct _TransferTask {
    struct _SeafTransferManager *manager;
    char         tx_id[37];
    char         repo_id[37];
    int          repo_version;
    char        *token;
    char        *session_token;
    int          protocol_version;
    char        *from_branch;
    char        *to_branch;
    char         head[41];
    char         remote_head[41];
    int          state;         /* NORMAL, STOPPED, CANCELED */
    int          runtime_state;
    int          last_runtime_state;
    int          type;
    gboolean     is_clone;      /* TRUE when fetching a new repo. */
    int          error;

    char        *dest_id;

    ObjectList  *commits;       /* commits need to be uploaded */
    ObjectList  *fs_roots;      /* the root of file systems to be sent/get */

    GList       *chunk_servers;
    BlockList   *block_list;
    gint         tx_bytes;      /* bytes transferred in the this second. */
    gint         last_tx_bytes; /* bytes transferred in the last second. */

    /* Fields only used by upload task. */
    int          n_uploaded;

    /* For new block transfer protocol */
    BlockTxInfo *tx_info;
    GQueue      *block_ids;

    gboolean     server_side_merge;
    /* These two fields are only used for new syncing protocol. */
    char        *passwd;
    char        *worktree;

    /* Used to display download progress for new syncing protocol */
    int          n_to_download;
    int          n_downloaded;

    gint64       rsize;            /* size remain   */
    gint64       dsize;            /* size done     */
};
typedef struct _TransferTask TransferTask;

const char *
task_state_to_str (int state);

const char *
task_rt_state_to_str (int rt_state);

const char *
task_error_str (int task_errno);

int
transfer_task_get_rate (TransferTask *task);

int
transfer_task_get_done_blocks (TransferTask *task);

void
transfer_task_set_error (TransferTask *task, int error);

void
transfer_task_set_netdown (TransferTask *task);

void
transition_state_to_error (TransferTask *task, int task_errno);

/*
 * Transfer Manager
 */

struct _SeafileSession;

struct _SeafTransferManager {
    struct _SeafileSession   *seaf;
    sqlite3         *db;

    GHashTable      *download_tasks;
    GHashTable      *upload_tasks;

    CcnetTimer      *schedule_timer;
};

typedef struct _SeafTransferManager SeafTransferManager;

SeafTransferManager *seaf_transfer_manager_new (struct _SeafileSession *seaf);

int seaf_transfer_manager_start (SeafTransferManager *manager);

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
                                    GError **error);

char *
seaf_transfer_manager_add_upload (SeafTransferManager *manager,
                                  const char *repo_id,
                                  int repo_version,
                                  const char *peer_id,
                                  const char *from_branch,
                                  const char *to_branch,
                                  const char *token,
                                  gboolean server_side_merge,
                                  GError **error);

GList*
seaf_transfer_manager_get_upload_tasks (SeafTransferManager *manager);

GList*
seaf_transfer_manager_get_download_tasks (SeafTransferManager *manager);

/* find running tranfer of a repo */
TransferTask*
seaf_transfer_manager_find_transfer_by_repo (SeafTransferManager *manager,
                                             const char *repo_id);

void
seaf_transfer_manager_remove_task (SeafTransferManager *manager,
                                   const char *tx_id,
                                   int task_type);

void
seaf_transfer_manager_cancel_task (SeafTransferManager *manager,
                                   const char *tx_id,
                                   int task_type);

GList *
seaf_transfer_manager_get_clone_heads (SeafTransferManager *mgr);

char *
seaf_transfer_manager_get_clone_head (SeafTransferManager *mgr,
                                      const char *repo_id);

/*
 * return the status code of block tx client.
 */
int
seaf_transfer_manager_download_file_blocks (SeafTransferManager *manager,
                                            TransferTask *task,
                                            const char *file_id);

#endif
