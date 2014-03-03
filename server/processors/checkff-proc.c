/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "checkff-proc.h"
#include "log.h"

typedef struct {
    char repo_id[37];
    char root_id[41];
    int result;
} SeafileCheckffProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_CHECKFF_PROC, SeafileCheckffProcPriv))

#define USE_PRIV \
    SeafileCheckffProcPriv *priv = GET_PRIV(processor);

G_DEFINE_TYPE (SeafileCheckffProc, seafile_checkff_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{

    CCNET_PROCESSOR_CLASS (seafile_checkff_proc_parent_class)->release_resource (processor);
}


static void
seafile_checkff_proc_class_init (SeafileCheckffProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileCheckffProcPriv));
}

static void
seafile_checkff_proc_init (SeafileCheckffProc *processor)
{
}

typedef struct {
    gboolean fast_forward;
    char root_id[41];
} CompareAux;

static gboolean
compare_root (SeafCommit *commit, void *data, gboolean *stop)
{
    CompareAux *aux = data;

    /* If we've found a match in another branch, stop traversing. */
    if (aux->fast_forward) {
        *stop = TRUE;
        return TRUE;
    }

    if (strcmp (commit->root_id, aux->root_id) == 0) {
        aux->fast_forward = TRUE;
        *stop = TRUE;
    }

    return TRUE;
}

static gboolean
check_fast_forward (SeafRepo *repo, const char *head_id, const char *root_id)
{
    CompareAux *aux = g_new0 (CompareAux, 1);
    gboolean ret;

    memcpy (aux->root_id, root_id, 41);
    if (!seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                   repo->id,
                                                   repo->version,
                                                   head_id,
                                                   compare_root,
                                                   aux, FALSE)) {
        g_free (aux);
        return FALSE;
    }

    ret = aux->fast_forward;
    g_free (aux);
    return ret;
}

static void *
check_fast_forward_thread (void *vdata)
{
    CcnetProcessor *processor = vdata;
    USE_PRIV;
    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, priv->repo_id);
    if (!repo) {
        seaf_warning ("Cannot find repo %s.\n", priv->repo_id);
        priv->result = 0;
        return vdata;
    }

    priv->result = check_fast_forward (repo, repo->head->commit_id, priv->root_id);

    seaf_repo_unref (repo);
    return vdata;
}

static void
check_fast_forward_done (void *vdata)
{
    CcnetProcessor *processor = vdata;
    USE_PRIV;
    char res[10];

    snprintf (res, sizeof(res), "%d", priv->result);

    seaf_message ("res is %s.\n", res);

    ccnet_processor_send_response (processor, SC_OK, SS_OK, res, strlen(res)+1);
    ccnet_processor_done (processor, TRUE);
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    char *repo_id, *root_id;

    if (argc < 2) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    repo_id = argv[0];
    root_id = argv[1];
    if (strlen(repo_id) != 36 || !is_uuid_valid(repo_id) || strlen(root_id) != 40) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    memcpy (priv->repo_id, repo_id, 36);
    memcpy (priv->root_id, root_id, 40);

    ccnet_processor_thread_create (processor,
                                   seaf->job_mgr,
                                   check_fast_forward_thread,
                                   check_fast_forward_done,
                                   processor);
    return 0;
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{

}
