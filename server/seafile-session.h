/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SESSION_H
#define SEAFILE_SESSION_H

#include <ccnet.h>
#include <ccnet/cevent.h>
#include <ccnet/job-mgr.h>

#include "block-mgr.h"
#include "fs-mgr.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "db.h"
#include "seaf-db.h"

#include "chunkserv-mgr.h"
#include "share-mgr.h"
#include "token-mgr.h"
#include "web-accesstoken-mgr.h"
#include "passwd-mgr.h"
#include "quota-mgr.h"
#include "listen-mgr.h"
#include "size-sched.h"
#include "copy-mgr.h"

#include "mq-mgr.h"

#include "http-server.h"
#include "zip-download-mgr.h"

#include <searpc-client.h>

struct _CcnetClient;

typedef struct _SeafileSession SeafileSession;


struct _SeafileSession {
    struct _CcnetClient *session;

    SearpcClient        *ccnetrpc_client;
    SearpcClient        *ccnetrpc_client_t;
    /* Use async rpc client on server. */
    SearpcClient        *async_ccnetrpc_client;
    SearpcClient        *async_ccnetrpc_client_t;

    /* Used in threads. */
    CcnetClientPool     *client_pool;

    char                *central_config_dir;
    char                *seaf_dir;
    char                *tmp_file_dir;
    /* Config that's only loaded on start */
    GKeyFile            *config;
    SeafDB              *db;

    SeafBlockManager    *block_mgr;
    SeafFSManager       *fs_mgr;
    SeafCommitManager   *commit_mgr;
    SeafBranchManager   *branch_mgr;
    SeafRepoManager     *repo_mgr;
    SeafCSManager       *cs_mgr;
    SeafShareManager	*share_mgr;
    SeafTokenManager    *token_mgr;
    SeafPasswdManager   *passwd_mgr;
    SeafQuotaManager    *quota_mgr;
    SeafListenManager   *listen_mgr;
    SeafCopyManager     *copy_mgr;
    
    SeafWebAccessTokenManager	*web_at_mgr;

    SeafMqManager       *mq_mgr;

    CEventManager       *ev_mgr;
    CcnetJobManager     *job_mgr;

    SizeScheduler       *size_sched;

    int                  is_master;

    int                  cloud_mode;
    int                  keep_history_days;

    int                  rpc_thread_pool_size;
    int                  sync_thread_pool_size;

    HttpServerStruct    *http_server;
    ZipDownloadMgr      *zip_download_mgr;
};

extern SeafileSession *seaf;

SeafileSession *
seafile_session_new(const char *central_config_dir, 
                    const char *seafile_dir,
                    struct _CcnetClient *ccnet_session);
int
seafile_session_init (SeafileSession *session);

int
seafile_session_start (SeafileSession *session);

char *
seafile_session_get_tmp_file_path (SeafileSession *session,
                                   const char *basename,
                                   char path[]);

void
schedule_create_system_default_repo (SeafileSession *session);

char *
get_system_default_repo_id (SeafileSession *session);

int
set_system_default_repo_id (SeafileSession *session, const char *repo_id);

#endif /* SEAFILE_H */
