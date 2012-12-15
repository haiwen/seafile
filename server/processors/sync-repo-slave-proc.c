/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "repo-mgr.h"
#include "branch-mgr.h"
#include "commit-mgr.h"

#include "sync-repo-slave-proc.h"
#include "sync-repo-common.h"

typedef struct {
    char repo_id[41];
    char *branch_name;

    char *rsp_code;
    char *rsp_msg;
    char commit_id[41];
} SeafileSyncRepoSlaveProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_SYNC_REPO_SLAVE_PROC, SeafileSyncRepoSlaveProcPriv))

#define USE_PRIV \
    SeafileSyncRepoSlaveProcPriv *priv = GET_PRIV(processor);

G_DEFINE_TYPE (SeafileSynRepoSlaveProc, seafile_sync_repo_slave_proc, CCNET_TYPE_PROCESSOR)

static int
sync_repo_slave_start (CcnetProcessor *processor, int argc, char **argv);

static void *
send_repo_branch_info (void *vprocessor);
static void 
thread_done (void *vprocessor);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    /* g_free works fine even if ptr is NULL. */
    g_free (priv->branch_name);
    g_free (priv->rsp_code);
    g_free (priv->rsp_msg);

    CCNET_PROCESSOR_CLASS (seafile_sync_repo_slave_proc_parent_class)->release_resource (processor);
}

static void
seafile_sync_repo_slave_proc_class_init (SeafileSynRepoSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "seafile-sync-repo-slave-proc";
    proc_class->start = sync_repo_slave_start;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileSyncRepoSlaveProcPriv));
}

static void
seafile_sync_repo_slave_proc_init (SeafileSynRepoSlaveProc *processor)
{
}


static int
sync_repo_slave_start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;

    if (argc != 2) {
        g_warning ("[sync-repo-slave] argc(%d) must be 2\n", argc);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    memcpy (priv->repo_id, argv[0], 37);
    priv->branch_name = g_strdup (argv[1]);

    /* send the head commit of the branch */
    if (ccnet_processor_thread_create (processor, 
                                       send_repo_branch_info,
                                       thread_done,
                                       processor) < 0) {
        g_warning ("[sync repo] failed to start thread.\n");
        ccnet_processor_send_response (processor, 
                                       SC_SERVER_ERROR, SS_SERVER_ERROR,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    return 0;
}

static void *
send_repo_branch_info (void *vprocessor)                       
{
    CcnetProcessor *processor = vprocessor;
    SeafRepo *repo;
    SeafBranch *seaf_branch;
    USE_PRIV;
    
    repo = seaf_repo_manager_get_repo_ex (seaf->repo_mgr, priv->repo_id);
    if (!repo) {
        priv->rsp_code = g_strdup (SC_NO_REPO);
        priv->rsp_msg = g_strdup (SS_NO_REPO);
        return vprocessor;
    } else if (repo->is_corrupted) {
        priv->rsp_code = g_strdup (SC_REPO_CORRUPT);
        priv->rsp_msg = g_strdup (SS_REPO_CORRUPT);
        return vprocessor;
    }

    seaf_branch = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                  priv->repo_id,
                                                  priv->branch_name);
    if (!seaf_branch) {
        seaf_repo_unref (repo);
        priv->rsp_code = g_strdup (SC_NO_BRANCH);
        priv->rsp_msg = g_strdup (SS_NO_BRANCH);
        return vprocessor;
    }

    priv->rsp_code = g_strdup (SC_COMMIT_ID);
    priv->rsp_msg = g_strdup (SS_COMMIT_ID);
    memcpy (priv->commit_id, seaf_branch->commit_id, 41);

    seaf_repo_unref (repo);
    seaf_branch_unref (seaf_branch);

    return vprocessor;
}

static void 
thread_done (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;

    if (processor->delay_shutdown) {
        ccnet_processor_done (processor, FALSE);
        return;
    }

    if (strcmp (priv->rsp_code, SC_COMMIT_ID) == 0) {
        ccnet_processor_send_response (processor, 
                                       priv->rsp_code, priv->rsp_msg,
                                       priv->commit_id, 41);
        ccnet_processor_done (processor, TRUE);
    } else {
        ccnet_processor_send_response (processor,
                                       priv->rsp_code, priv->rsp_msg,
                                       NULL, 0);
        ccnet_processor_done (processor, TRUE);
    }
}
