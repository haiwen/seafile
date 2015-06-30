/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "repo-mgr.h"
#include "branch-mgr.h"
#include "commit-mgr.h"

#include "sync-repo-slave-proc.h"
#include "sync-repo-common.h"

#include "seaf-db.h"
#include "log.h"

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
        seaf_warning ("[sync-repo-slave] argc(%d) must be 2\n", argc);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (!is_uuid_valid(argv[0])) {
        seaf_warning ("Invalid repo_id %s.\n", argv[0]);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    memcpy (priv->repo_id, argv[0], 37);
    priv->branch_name = g_strdup (argv[1]);

    /* send the head commit of the branch */
    if (ccnet_processor_thread_create (processor, 
                                       seaf->job_mgr,
                                       send_repo_branch_info,
                                       thread_done,
                                       processor) < 0) {
        seaf_warning ("[sync repo] failed to start thread.\n");
        ccnet_processor_send_response (processor, 
                                       SC_SERVER_ERROR, SS_SERVER_ERROR,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    return 0;
}

static gboolean
get_branch (SeafDBRow *row, void *vid)
{
    char *ret = vid;
    const char *commit_id;

    commit_id = seaf_db_row_get_column_text (row, 0);
    memcpy (ret, commit_id, 41);

    return FALSE;
}

static void *
send_repo_branch_info (void *vprocessor)                       
{
    CcnetProcessor *processor = vprocessor;
    char commit_id[41];
    char *sql;
    USE_PRIV;

    commit_id[0] = 0;

    sql = "SELECT commit_id FROM Repo r, Branch b "
        "WHERE name='master' AND r.repo_id=? AND r.repo_id = b.repo_id";
    if (seaf_db_statement_foreach_row (seaf->db, sql, 
                                       get_branch, commit_id,
                                       1, "string", priv->repo_id) < 0) {
        seaf_warning ("DB error when get branch %s.\n", priv->branch_name);
        priv->rsp_code = g_strdup (SC_REPO_CORRUPT);
        priv->rsp_msg = g_strdup (SS_REPO_CORRUPT);
        return vprocessor;
    }

    if (commit_id[0] == 0) {
        priv->rsp_code = g_strdup (SC_NO_REPO);
        priv->rsp_msg = g_strdup (SS_NO_REPO);
        return vprocessor;
    }

    priv->rsp_code = g_strdup (SC_COMMIT_ID);
    priv->rsp_msg = g_strdup (SS_COMMIT_ID);
    memcpy (priv->commit_id, commit_id, 41);    

    return vprocessor;
}

static void 
thread_done (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;

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
