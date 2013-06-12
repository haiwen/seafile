/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef TRANSFER_MGR_H
#define TRANSFER_MGR_H

#include <glib.h>
#include <ccnet/timer.h>
#include <ccnet/peer.h>

#include "bitfield.h"
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
    TASK_ERR_BAD_LOCAL_BRANCH,
    TASK_ERR_PROTOCOL_VERSION,
    N_TASK_ERROR,
};

struct _SeafTransferManager;

typedef struct {
    struct _SeafTransferManager *manager;
    char         tx_id[37];
    char         repo_id[37];
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
    GHashTable  *processors;
    BlockList   *block_list;
    Bitfield     active;
    gint         tx_bytes;      /* bytes transferred in the this second. */
    gint         last_tx_bytes; /* bytes transferred in the last second. */

    /* Fields only used by upload task. */
    Bitfield     uploaded;
    int          n_uploaded;

    gint64       rsize;            /* size remain   */
    gint64       dsize;            /* size done     */
} TransferTask;

const char *
task_state_to_str (int state);

const char *
task_rt_state_to_str (int rt_state);

const char *
task_error_str (int task_errno);

int
transfer_task_get_rate (TransferTask *task);

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

    /* Sent/recv bytes from all tasks in this second. */
    gint             sent_bytes;
    gint             recv_bytes;
    /* Upload/download rate limits. */
    gint             upload_limit;
    gint             download_limit;
};

typedef struct _SeafTransferManager SeafTransferManager;

SeafTransferManager *seaf_transfer_manager_new (struct _SeafileSession *seaf);

int seaf_transfer_manager_start (SeafTransferManager *manager);

char *
seaf_transfer_manager_add_download (SeafTransferManager *manager,
                                    const char *repo_id,
                                    const char *peer_id,
                                    const char *from_branch,
                                    const char *to_branch,
                                    const char *token,
                                    GError **error);

char *
seaf_transfer_manager_add_upload (SeafTransferManager *manager,
                                  const char *repo_id,
                                  const char *peer_id,
                                  const char *from_branch,
                                  const char *to_branch,
                                  const char *token,
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

#endif
