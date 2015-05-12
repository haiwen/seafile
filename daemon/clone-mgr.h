/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CLONE_MGR_H
#define CLONE_MGR_H

#include <glib.h>
#include "db.h"

struct _SeafileSession;

typedef struct _CloneTask CloneTask;
typedef struct _SeafCloneManager SeafCloneManager;

enum {
    CLONE_STATE_INIT,
    CLONE_STATE_CHECK_HTTP,
    CLONE_STATE_CONNECT,
    CLONE_STATE_CHECK_PROTOCOL,
    CLONE_STATE_INDEX,
    CLONE_STATE_FETCH,
    CLONE_STATE_CHECKOUT,
    CLONE_STATE_MERGE,
    CLONE_STATE_DONE,
    CLONE_STATE_ERROR,
    CLONE_STATE_CANCEL_PENDING,
    CLONE_STATE_CANCELED,
    N_CLONE_STATES,
};

enum {
    CLONE_OK,
    CLONE_ERROR_CONNECT,
    CLONE_ERROR_INDEX,
    CLONE_ERROR_FETCH,
    CLONE_ERROR_PASSWD,
    CLONE_ERROR_CHECKOUT,
    CLONE_ERROR_MERGE,
    CLONE_ERROR_INTERNAL,
    N_CLONE_ERRORS,
};

struct _CloneTask {
    SeafCloneManager    *manager;
    int                  state;
    int                  error;
    char                 repo_id[37];
    int                  repo_version;
    char                 peer_id[41];
    char                *peer_addr;
    char                *peer_port; 
    char                *token;
    char                *email;
    char                *repo_name; /* For better display. */
    char                *tx_id;
    char                *worktree;
    char                *passwd;
    int                  enc_version;
    char                *random_key;
    char                 root_id[41];
    gboolean             is_readonly;

    /* Http sync fields */
    char                *server_url;
    char                *effective_url;
    gboolean             use_fileserver_port;
    int                  http_protocol_version;
    gboolean             http_sync;
    char                 server_head_id[41];

    gboolean             server_side_merge;
};

const char *
clone_task_state_to_str (int state);

const char *
clone_task_error_to_str (int error);

struct _SeafCloneManager {
    struct _SeafileSession  *seaf;
    sqlite3                 *db;
    GHashTable              *tasks;
    struct CcnetTimer       *check_timer;
};

SeafCloneManager *
seaf_clone_manager_new (struct _SeafileSession *session);

int
seaf_clone_manager_init (SeafCloneManager *mgr);

int
seaf_clone_manager_start (SeafCloneManager *mgr);

char *
seaf_clone_manager_gen_default_worktree (SeafCloneManager *mgr,
                                         const char *worktree_parent,
                                         const char *repo_name);

char *
seaf_clone_manager_add_task (SeafCloneManager *mgr, 
                             const char *repo_id,
                             int repo_version,
                             const char *peer_id,
                             const char *repo_name,
                             const char *token,
                             const char *passwd,
                             const char *magic,
                             int enc_version,
                             const char *random_key,
                             const char *worktree,
                             const char *peer_addr,
                             const char *peer_port,
                             const char *email,
                             const char *more_info,
                             GError **error);

/*
 * Similar to seaf_clone_manager_add_task. 
 * But create a new dir for worktree under @wt_parent.
 * The semantics is to "download" the repo into @wt_parent.
 */
char *
seaf_clone_manager_add_download_task (SeafCloneManager *mgr, 
                                      const char *repo_id,
                                      int repo_version,
                                      const char *peer_id,
                                      const char *repo_name,
                                      const char *token,
                                      const char *passwd,
                                      const char *magic,
                                      int enc_version,
                                      const char *random_key,
                                      const char *wt_parent,
                                      const char *peer_addr,
                                      const char *peer_port,
                                      const char *email,
                                      const char *more_info,
                                      GError **error);

int
seaf_clone_manager_cancel_task (SeafCloneManager *mgr,
                                const char *repo_id);

int
seaf_clone_manager_remove_task (SeafCloneManager *mgr,
                                const char *repo_id);

CloneTask *
seaf_clone_manager_get_task (SeafCloneManager *mgr,
                             const char *repo_id);

GList *
seaf_clone_manager_get_tasks (SeafCloneManager *mgr);

gboolean
seaf_clone_manager_check_worktree_path (SeafCloneManager *mgr, const char *path, GError **error);

#endif
