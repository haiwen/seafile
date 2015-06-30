/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "putcommit-v2-proc.h"
#include "processors/objecttx-common.h"
#include "vc-common.h"

typedef struct  {
    char        head_commit_id[41];
    char        remote_commit_id[41];
    GList       *id_list;
    GHashTable  *commit_hash;
    gboolean    fast_forward;

    guint32     reader_id;
    gboolean    registered;

    char        repo_id[37];
    int         repo_version;
} SeafilePutcommitProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_PUTCOMMIT_V2_PROC, SeafilePutcommitProcPriv))

#define USE_PRIV \
    SeafilePutcommitProcPriv *priv = GET_PRIV(processor);

static int put_commit_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

G_DEFINE_TYPE (SeafilePutcommitV2Proc, seafile_putcommit_v2_proc, CCNET_TYPE_PROCESSOR)

static void
release_resource (CcnetProcessor *processor)
{
    USE_PRIV;

    if (priv->id_list)
        string_list_free (priv->id_list);
    if (priv->commit_hash)
        g_hash_table_destroy (priv->commit_hash);
    if (priv->registered)
        seaf_obj_store_unregister_async_read (seaf->commit_mgr->obj_store,
                                              priv->reader_id);

    CCNET_PROCESSOR_CLASS (seafile_putcommit_v2_proc_parent_class)->release_resource (processor);
}

static void
seafile_putcommit_v2_proc_class_init (SeafilePutcommitV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "putcommit-v2-proc";
    proc_class->start = put_commit_start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafilePutcommitProcPriv));
}

static void
seafile_putcommit_v2_proc_init (SeafilePutcommitV2Proc *processor)
{
}

static void
send_commit (CcnetProcessor *processor,
             const char *commit_id,
             char *data, int len)
{
    ObjectPack *pack = NULL;
    int pack_size;

    pack_size = sizeof(ObjectPack) + len;
    pack = malloc (pack_size);
    memcpy (pack->id, commit_id, 41);
    memcpy (pack->object, data, len);

    ccnet_processor_send_response (processor, SC_OBJECT, SS_OBJECT,
                                   (char *)pack, pack_size);
    free (pack);
}

static int
read_and_send_commit (CcnetProcessor *processor)
{
    char *id;
    USE_PRIV;

    id = priv->id_list->data;
    priv->id_list = g_list_delete_link (priv->id_list, priv->id_list);

    if (seaf_obj_store_async_read (seaf->commit_mgr->obj_store,
                                   priv->reader_id,
                                   id) < 0) {
        seaf_warning ("[putcommit] Failed to start read of %s.\n", id);
        ccnet_processor_send_response (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        g_free (id);
        return -1;
    }

    g_free (id);
    return 0;
}

static void
read_done_cb (OSAsyncResult *res, void *cb_data)
{
    CcnetProcessor *processor = cb_data;
    USE_PRIV;

    if (!res->success) {
        seaf_warning ("[putcommit] Failed to read %s.\n", res->obj_id);
        goto bad;
    }

    send_commit (processor, res->obj_id, res->data, res->len);

    seaf_debug ("Send commit %.8s.\n", res->obj_id);

    /* Send next commit. */
    if (priv->id_list != NULL)
        read_and_send_commit (processor);
    else {
        ccnet_processor_send_response (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
    }

    return;

bad:
    ccnet_processor_send_response (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                   NULL, 0);
    ccnet_processor_done (processor, FALSE);
}

static gboolean
collect_id_fast_forward (SeafCommit *commit, void *data, gboolean *stop)
{
    CcnetProcessor *processor = data;
    USE_PRIV;

    if (g_strcmp0 (commit->commit_id, priv->remote_commit_id) == 0) {
        *stop = TRUE;
        return TRUE;
    }

    /* In clone remote head is not set but we're alwasy fast-forward. */
    if (priv->remote_commit_id[0] != '\0' &&
        commit->second_parent_id != NULL) {
        *stop = TRUE;
        priv->fast_forward = FALSE;
        return TRUE;
    }

    priv->id_list = g_list_prepend (priv->id_list, g_strdup(commit->commit_id));
    return TRUE;
}

static gboolean
collect_id_remote (SeafCommit *commit, void *data, gboolean *stop)
{
    CcnetProcessor *processor = data;
    USE_PRIV;
    char *key;

    if (g_hash_table_lookup (priv->commit_hash, commit->commit_id))
        return TRUE;

    key = g_strdup(commit->commit_id);
    g_hash_table_replace (priv->commit_hash, key, key);
    return TRUE;
}

static gboolean
compute_delta (SeafCommit *commit, void *data, gboolean *stop)
{
    CcnetProcessor *processor = data;
    USE_PRIV;

    if (!g_hash_table_lookup (priv->commit_hash, commit->commit_id)) {
        priv->id_list = g_list_prepend (priv->id_list,
                                        g_strdup(commit->commit_id));
    } else {
        /* Stop traversing down from this commit if it already exists
         * in the remote branch.
         */
        *stop = TRUE;
    }

    return TRUE;
}

static int
compute_delta_commits (CcnetProcessor *processor, const char *head)
{
    gboolean ret;
    USE_PRIV;

    string_list_free (priv->id_list);
    priv->id_list = NULL;

    priv->commit_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                               g_free, NULL);

    /* When putting commits, the remote head commit must exists. */
    ret = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                    priv->repo_id,
                                                    priv->repo_version,
                                                    priv->remote_commit_id,
                                                    collect_id_remote,
                                                    processor,
                                                    FALSE);
    if (!ret) {
        seaf_warning ("[putcommit] Failed to traverse remote branch.\n");
        string_list_free (priv->id_list);
        priv->id_list = NULL;
        return -1;
    }

    ret = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                    priv->repo_id,
                                                    priv->repo_version,
                                                    head,
                                                    compute_delta,
                                                    processor,
                                                    FALSE);
    if (!ret) {
        seaf_warning ("[putcommit] Failed to compute delta commits.\n");
        string_list_free (priv->id_list);
        priv->id_list = NULL;
        return -1;
    }

    return 0;
}

static void *
collect_commit_id_thread (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;
    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, priv->repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", priv->repo_id);
        priv->id_list = NULL;
        return vprocessor;
    }
    priv->repo_version = repo->version;

    priv->fast_forward = TRUE;
    if (seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                  repo->id,
                                                  repo->version,
                                                  priv->head_commit_id,
                                                  collect_id_fast_forward,
                                                  processor,
                                                  FALSE) < 0) {
        seaf_warning ("[putcommit] Failed to collect commit id.\n");
        string_list_free (priv->id_list);
        priv->id_list = NULL;
        goto out;
    }

    if (priv->fast_forward) {
        seaf_debug ("Send commits after a fast-forward merge.\n");
        goto out;
    }

    seaf_debug ("Send commits after a real merge.\n");

    compute_delta_commits (processor, priv->head_commit_id);

out:
    seaf_repo_unref (repo);
    return vprocessor;
}

static void
collect_commit_id_done (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;

    if (!priv->id_list) {
        ccnet_processor_send_response (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    priv->reader_id =
        seaf_obj_store_register_async_read (seaf->commit_mgr->obj_store,
                                            priv->repo_id,
                                            priv->repo_version,
                                            read_done_cb,
                                            processor);
    priv->registered = TRUE;

    read_and_send_commit (processor);
}

static int
put_commit_start (CcnetProcessor *processor, int argc, char **argv)
{
    char *head_id, *remote_id = NULL;
    char *session_token;
    USE_PRIV;

    if (argc < 2) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (argc == 2) {
        head_id = argv[0];
        session_token = argv[1];
    } else if (argc >= 3) {
        head_id = argv[0];
        remote_id = argv[1];
        session_token = argv[2];
    }

    if (strlen(head_id) != 40 || (remote_id && strlen(remote_id) != 40)) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (seaf_token_manager_verify_token (seaf->token_mgr,
                                         NULL,
                                         processor->peer_id,
                                         session_token, priv->repo_id) < 0) {
        ccnet_processor_send_response (processor, 
                                       SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    memcpy (priv->head_commit_id, head_id, 41);
    if (remote_id != NULL)
        memcpy (priv->remote_commit_id, remote_id, 41);
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    ccnet_processor_thread_create (processor,
                                   seaf->job_mgr,
                                   collect_commit_id_thread,
                                   collect_commit_id_done,
                                   processor);

    return 0;
}

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    ccnet_processor_done (processor, FALSE);
}
