/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SESSION_H
#define SEAFILE_SESSION_H

#include <glib-object.h>
#include "cevent.h"
#include "job-mgr.h"

#include "block-mgr.h"
#include "fs-mgr.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "clone-mgr.h"
#include "db.h"

#include "sync-mgr.h"
#include "wt-monitor.h"
#include "mq-mgr.h"

#include "http-tx-mgr.h"
#include "filelock-mgr.h"


#define SEAFILE_TYPE_SESSION                  (seafile_session_get_type ())
#define SEAFILE_SESSION(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SESSION, SeafileSession))
#define SEAFILE_IS_SESSION(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SESSION))
#define SEAFILE_SESSION_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SESSION, SeafileSessionClass))
#define SEAFILE_IS_SESSION_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SESSION))
#define SEAFILE_SESSION_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SESSION, SeafileSessionClass))


typedef struct _SeafileSession SeafileSession;
typedef struct _SeafileSessionClass SeafileSessionClass;

struct event_base;

struct _SeafileSession {
    GObject         parent_instance;

    struct event_base   *ev_base;

    char                *client_id;
    char                *client_name;

    char                *seaf_dir;
    char                *tmp_file_dir;
    char                *worktree_dir; /* the default directory for
                                        * storing worktrees  */
    char                *ccnet_dir;
    sqlite3             *config_db;
    char                *deleted_store;
    char                *rpc_socket_path;

    uint32_t            cdc_average_block_size;
    SeafBlockManager    *block_mgr;
    SeafFSManager       *fs_mgr;
    SeafCommitManager   *commit_mgr;
    SeafBranchManager   *branch_mgr;
    SeafRepoManager     *repo_mgr;
    SeafCloneManager    *clone_mgr;
    SeafSyncManager     *sync_mgr;
    SeafWTMonitor       *wt_monitor;
    SeafMqManager       *mq_mgr;

    CEventManager       *ev_mgr;
    SeafJobManager     *job_mgr;

    HttpTxManager       *http_tx_mgr;

    SeafFilelockManager *filelock_mgr;

    /* Set after all components are up and running. */
    gboolean             started;

    gboolean             sync_extra_temp_file;
    gboolean             enable_http_sync;
    gboolean             disable_verify_certificate;

    gboolean             disable_block_hash;
    
    gboolean             hide_windows_incompatible_path_notification;

    gboolean             use_http_proxy;
    char                *http_proxy_type;
    char                *http_proxy_addr;
    int                  http_proxy_port;
    char                *http_proxy_username;
    char                *http_proxy_password;
};

struct _SeafileSessionClass
{
    GObjectClass    parent_class;
};


extern SeafileSession *seaf;

SeafileSession *
seafile_session_new(const char *seafile_dir,
                    const char *worktree_dir,
                    const char *config_dir);
void
seafile_session_prepare (SeafileSession *session);

void
seafile_session_start (SeafileSession *session);

char *
seafile_session_get_tmp_file_path (SeafileSession *session,
                                   const char *basename,
                                   char path[]);
#if 0
void
seafile_session_add_event (SeafileSession *session, 
                           const char *type,
                           const char *first, ...);
#endif

#endif /* SEAFILE_H */
