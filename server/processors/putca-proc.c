/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <ccnet.h>
#include "utils.h"

#include "seafile-session.h"
#include "putca-proc.h"

typedef struct  {
    char repo_id[37];
    char *token;
    GHashTable *commit_hash;

    gboolean token_valid;
    char ca_id[41];
} SeafilePutcaProcPriv;

#define SC_ID_LIST "301"
#define SS_ID_LIST "Commit id list"
#define SC_ID_LIST_END "302"
#define SS_ID_LIST_END "Commit id list end"
#define SC_CA "303"
#define SS_CA "Common ancestor"

#define SC_ACCESS_DENIED "401"
#define SS_ACCESS_DENIED "Access denied"
#define SC_NO_CA "404"
#define SS_NO_CA "No common ancestor found"

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_PUTCA_PROC, SeafilePutcaProcPriv))

#define USE_PRIV \
    SeafilePutcaProcPriv *priv = GET_PRIV(processor);

static int put_ca_start (CcnetProcessor *processor, int argc, char **argv);
static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen);

G_DEFINE_TYPE (SeafilePutcaProc, seafile_putca_proc, CCNET_TYPE_PROCESSOR)

static void
release_resource (CcnetProcessor *processor)
{
    USE_PRIV;

    if (priv->commit_hash)
        g_hash_table_destroy (priv->commit_hash);
    if (priv->token)
        g_free (priv->token);

    CCNET_PROCESSOR_CLASS (seafile_putca_proc_parent_class)->release_resource (processor);
}

static void
seafile_putca_proc_class_init (SeafilePutcaProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "putca-proc";
    proc_class->start = put_ca_start;
    proc_class->release_resource = release_resource;
    proc_class->handle_update = handle_update;

    g_type_class_add_private (klass, sizeof (SeafilePutcaProcPriv));
}

static void
seafile_putca_proc_init (SeafilePutcaProc *processor)
{
}

static void *
check_token_thread (void *vdata)
{
    CcnetProcessor *processor = vdata;
    USE_PRIV;
    char *user;

    user = seaf_repo_manager_get_email_by_token (
        seaf->repo_mgr, priv->repo_id, priv->token);
    if (!user) {
        priv->token_valid = FALSE;
        return vdata;
    }

    g_free (user);
    priv->token_valid = TRUE;
    return vdata;
}

static void
check_token_thread_done (void *vdata)
{
    CcnetProcessor *processor = vdata;
    USE_PRIV;

    if (!priv->token_valid) {
        ccnet_processor_send_response (processor, SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    } else {
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        priv->commit_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                   g_free, NULL);
    }
}

static int
put_ca_start (CcnetProcessor *processor, int argc, char **argv)
{
    char *repo_id, *token;
    USE_PRIV;

    if (argc < 2) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    repo_id = argv[0];
    token = argv[1];

    if (!is_uuid_valid (repo_id)) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    memcpy (priv->repo_id, repo_id, 36);
    priv->token = g_strdup(token);

    ccnet_processor_thread_create (processor,
                                   seaf->job_mgr,
                                   check_token_thread,
                                   check_token_thread_done,
                                   processor);

    return 0;
}

static void
process_commit_id_list (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;
    int offset;
    int size = clen - 1;
    int dummy;

    if (size % 40 != 0) {
        seaf_warning ("Invalid commid id list size %d.\n", size);
        ccnet_processor_send_response (processor,
                                       SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    for (offset = 0; offset < size - 1; offset += 40)
        g_hash_table_insert (priv->commit_hash,
                             g_strndup(&content[offset], 40), &dummy);
}

static gboolean
find_common_ancestor (SeafCommit *commit, void *data, gboolean *stop)
{
    CcnetProcessor *processor = data;
    USE_PRIV;

    /* If common ancestor has been found on other branch, stop traversing down. */
    if (priv->ca_id[0] != 0) {
        *stop = TRUE;
        return TRUE;
    }

    if (g_hash_table_lookup (priv->commit_hash, commit->commit_id)) {
        memcpy (priv->ca_id, commit->commit_id, 40);
        *stop = TRUE;
        return TRUE;
    }

    return TRUE;
}

static void *
compute_common_ancestor_thread (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;
    SeafRepo *repo = NULL;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, priv->repo_id);
    if (!repo) {
        seaf_warning ("Failed to find repo %.8s.\n", priv->repo_id);
        return vprocessor;
    }

    /* Traverse the commit tree. The first commit whose id is in the commit list
     * is the common ancestor.
     */
    if (seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                  repo->id,
                                                  repo->version,
                                                  repo->head->commit_id,
                                                  find_common_ancestor,
                                                  processor,
                                                  FALSE) < 0) {
        seaf_warning ("Failed to find common ancestor.\n");
        seaf_repo_unref (repo);
        return vprocessor;
    }

    seaf_repo_unref (repo);
    return vprocessor;
}

static void
compute_common_ancestor_done (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;

    if (priv->ca_id[0] != 0) {
        ccnet_processor_send_response (processor, SC_CA, SS_CA, priv->ca_id, 41);
        ccnet_processor_done (processor, TRUE);
    } else {
        ccnet_processor_send_response (processor, SC_NO_CA, SS_NO_CA, NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    USE_PRIV;

    if (!priv->token_valid) {
        ccnet_processor_send_response (processor, SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    if (strncmp (code, SC_ID_LIST, 3) == 0) {
        process_commit_id_list (processor, content, clen);
        return;
    } else if (strncmp (code, SC_ID_LIST_END, 3) == 0) {
        ccnet_processor_thread_create (processor,
                                       seaf->job_mgr,
                                       compute_common_ancestor_thread,
                                       compute_common_ancestor_done,
                                       processor);
        return;
    }

    seaf_warning ("Bad update: %s %s.\n", code, code_msg);
    ccnet_processor_send_response (processor, SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                   NULL, 0);
    ccnet_processor_done (processor, FALSE);
}
