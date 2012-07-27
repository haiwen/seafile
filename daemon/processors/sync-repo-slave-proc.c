/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "repo-mgr.h"
#include "branch-mgr.h"
#include "commit-mgr.h"

#include "sync-repo-slave-proc.h"
#include "sync-repo-common.h"


G_DEFINE_TYPE (SeafileSynRepoSlaveProc, seafile_sync_repo_slave_proc, CCNET_TYPE_PROCESSOR)

static int
sync_repo_slave_start (CcnetProcessor *processor, int argc, char **argv);

static int
send_repo_branch_info (CcnetProcessor *processor, const char *repo_id,
                       const char *branch);

static void
seafile_sync_repo_slave_proc_class_init (SeafileSynRepoSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "seafile-sync-repo-slave-proc";
    proc_class->start = sync_repo_slave_start;
}

static void
seafile_sync_repo_slave_proc_init (SeafileSynRepoSlaveProc *processor)
{
}


static int
sync_repo_slave_start (CcnetProcessor *processor, int argc, char **argv)
{
    if (argc != 2) {
        g_warning ("[sync-repo-slave] argc(%d) must be 2\n", argc);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    /* send the head commit of the branch */
    send_repo_branch_info (processor, argv[0], argv[1]);
    ccnet_processor_done (processor, TRUE);

    return 0;
}

static int
send_repo_branch_info (CcnetProcessor *processor, const char *repo_id,
                       const char *branch)
                       
{
    SeafRepo *repo;
    SeafBranch *seaf_branch;
    
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
         ccnet_processor_send_response (processor, SC_NO_REPO, SS_NO_REPO,
                                        NULL, 0);
         return 0;
    }

    seaf_branch = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                  repo_id, branch);
    if (seaf_branch == NULL) {
        ccnet_processor_send_response (processor, SC_NO_BRANCH, SS_NO_BRANCH,
                                       NULL, 0);
        return -1;
    }

    ccnet_processor_send_response (processor, SC_COMMIT_ID, SS_COMMIT_ID,
                                   seaf_branch->commit_id, 41);
    seaf_branch_unref (seaf_branch);

    return 0;

}

