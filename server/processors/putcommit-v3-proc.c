/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "putcommit-v3-proc.h"
#include "processors/objecttx-common.h"

typedef struct  {
    char        head_commit_id[41];
    guint32     reader_id;
    gboolean    registered;

    /* Used for getting repo info */
    char        repo_id[37];
    int         repo_version;
    gboolean    success;
} SeafilePutcommitProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_PUTCOMMIT_V3_PROC, SeafilePutcommitProcPriv))

#define USE_PRIV \
    SeafilePutcommitProcPriv *priv = GET_PRIV(processor);

static int put_commit_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

G_DEFINE_TYPE (SeafilePutcommitV3Proc, seafile_putcommit_v3_proc, CCNET_TYPE_PROCESSOR)

static void
release_resource (CcnetProcessor *processor)
{
    USE_PRIV;

    if (priv->registered)
        seaf_obj_store_unregister_async_read (seaf->commit_mgr->obj_store,
                                              priv->reader_id);

    CCNET_PROCESSOR_CLASS (seafile_putcommit_v3_proc_parent_class)->release_resource (processor);
}

static void
seafile_putcommit_v3_proc_class_init (SeafilePutcommitV3ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "putcommit-v3-proc";
    proc_class->start = put_commit_start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafilePutcommitProcPriv));
}

static void
seafile_putcommit_v3_proc_init (SeafilePutcommitV3Proc *processor)
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

    ccnet_processor_send_response (processor, SC_OK, SS_OK,
                                   (char *)pack, pack_size);
    free (pack);
}

static int
read_and_send_commit (CcnetProcessor *processor, const char *commit_id)
{
    USE_PRIV;

    if (seaf_obj_store_async_read (seaf->commit_mgr->obj_store,
                                   priv->reader_id,
                                   commit_id) < 0) {
        seaf_warning ("[putcommit] Failed to start read of %s.\n", commit_id);
        ccnet_processor_send_response (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    return 0;
}

static void
read_done_cb (OSAsyncResult *res, void *cb_data)
{
    CcnetProcessor *processor = cb_data;

    if (!res->success) {
        seaf_warning ("[putcommit] Failed to read %s.\n", res->obj_id);
        ccnet_processor_send_response (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    send_commit (processor, res->obj_id, res->data, res->len);

    seaf_debug ("Send commit %.8s.\n", res->obj_id);
}

static void *
get_repo_info_thread (void *data)
{
    CcnetProcessor *processor = data;
    USE_PRIV;
    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, priv->repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", priv->repo_id);
        priv->success = FALSE;
        return data;
    }

    priv->repo_version = repo->version;
    priv->success = TRUE;

    seaf_repo_unref (repo);
    return data;
}

static void
get_repo_info_done (void *data)
{
    CcnetProcessor *processor = data;
    USE_PRIV;

    if (priv->success) {
        priv->reader_id =
            seaf_obj_store_register_async_read (seaf->commit_mgr->obj_store,
                                                priv->repo_id,
                                                priv->repo_version,
                                                read_done_cb,
                                                processor);
        priv->registered = TRUE;

        read_and_send_commit (processor, priv->head_commit_id);
    } else {
        ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }
}

static int
put_commit_start (CcnetProcessor *processor, int argc, char **argv)
{
    char *head_id;
    char *session_token;
    USE_PRIV;

    if (argc < 2) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    head_id = argv[0];
    session_token = argv[1];

    if (strlen(head_id) != 40) {
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

    memcpy (priv->head_commit_id, head_id, 40);
    ccnet_processor_thread_create (processor,
                                   seaf->job_mgr,
                                   get_repo_info_thread,
                                   get_repo_info_done,
                                   processor);

    return 0;
}

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    ccnet_processor_done (processor, FALSE);
}
