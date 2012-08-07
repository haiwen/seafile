#ifndef SEAFILE_SESSION_H
#define SEAFILE_SESSION_H

#include <stdint.h>
#include <glib.h>
#include <ccnet/job-mgr.h>
#include <ccnet/timer.h>

#include "block-mgr.h"
#include "fs-mgr.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "db.h"
#include "seaf-db.h"
#include "scheduler.h"
#include "mq-mgr.h"

struct _CcnetClient;

typedef struct _SeafileSession SeafileSession;

struct _SeafileSession {
    struct _CcnetClient *session;

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

    CcnetJobManager     *job_mgr;

    SeafMqManager       *mq_mgr;

    Scheduler           *scheduler;
    CcnetTimer          *refresh_timer;
};

/* singleton monitor. 
 */
extern SeafileSession *seaf;

SeafileSession *
seafile_session_new (const char *seafile_dir,
                     struct _CcnetClient *ccnet);

int
seafile_session_init (SeafileSession *session);

int
seafile_session_start (SeafileSession *session);

#endif
