/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "recvcommit-v3-proc.h"
#include "processors/objecttx-common.h"
#include "seaf-utils.h"

enum {
    INIT,
    RECV_OBJECT
};

typedef struct {
    guint32 writer_id;
    gboolean registered;

    /* Used for getting repo info */
    char        repo_id[37];
    int         repo_version;
    gboolean    success;
} RecvcommitPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_RECVCOMMIT_V3_PROC, RecvcommitPriv))

#define USE_PRIV \
    RecvcommitPriv *priv = GET_PRIV(processor);

static int recv_commit_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);
static void
write_done_cb (OSAsyncResult *res, void *cb_data);


G_DEFINE_TYPE (SeafileRecvcommitV3Proc, seafile_recvcommit_v3_proc, CCNET_TYPE_PROCESSOR)

static void
release_resource (CcnetProcessor *processor)
{
    USE_PRIV;

    if (priv->registered)
        seaf_obj_store_unregister_async_write (seaf->commit_mgr->obj_store,
                                               priv->writer_id);

    CCNET_PROCESSOR_CLASS (seafile_recvcommit_v3_proc_parent_class)->release_resource (processor);
}

static void
seafile_recvcommit_v3_proc_class_init (SeafileRecvcommitV3ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "recvcommit-v3-proc";
    proc_class->start = recv_commit_start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (RecvcommitPriv));
}

static void
seafile_recvcommit_v3_proc_init (SeafileRecvcommitV3Proc *processor)
{
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
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        processor->state = RECV_OBJECT;
        priv->writer_id =
            seaf_obj_store_register_async_write (seaf->commit_mgr->obj_store,
                                                 priv->repo_id,
                                                 priv->repo_version,
                                                 write_done_cb,
                                                 processor);
        priv->registered = TRUE;
    } else {
        ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }
}

static int
recv_commit_start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    char *session_token;

    if (argc != 2) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    session_token = argv[1];
    if (seaf_token_manager_verify_token (seaf->token_mgr,
                                         NULL,
                                         processor->peer_id,
                                         session_token, priv->repo_id) == 0) {
        ccnet_processor_thread_create (processor,
                                       seaf->job_mgr,
                                       get_repo_info_thread,
                                       get_repo_info_done,
                                       processor);
        return 0;
    } else {
        ccnet_processor_send_response (processor, 
                                       SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
}

static void
write_done_cb (OSAsyncResult *res, void *cb_data)
{
    CcnetProcessor *processor = cb_data;

    if (!res->success) {
        ccnet_processor_send_response (processor, SC_BAD_OBJECT, SS_BAD_OBJECT,
                                       NULL, 0);
        seaf_warning ("[recvcommit] Failed to write commit object.\n");
        ccnet_processor_done (processor, FALSE);
    } else {
        ccnet_processor_send_response (processor, SC_ACK, SS_ACK, NULL, 0);
    }
}

static int
save_commit (CcnetProcessor *processor, ObjectPack *pack, int len)
{
    USE_PRIV;

    return seaf_obj_store_async_write (seaf->commit_mgr->obj_store,
                                       priv->writer_id,
                                       pack->id,
                                       pack->object,
                                       len - 41,
                                       TRUE);
}

static void
receive_commit (CcnetProcessor *processor, char *content, int clen)
{
    ObjectPack *pack = (ObjectPack *)content;

    if (clen < sizeof(ObjectPack)) {
        seaf_warning ("[recvcommit] invalid object id.\n");
        goto bad;
    }

    seaf_debug ("[recvcommit] recv commit object %.8s\n", pack->id);

    if (save_commit (processor, pack, clen) < 0) {
        goto bad;
    }

    return;

bad:
    ccnet_processor_send_response (processor, SC_BAD_OBJECT, SS_BAD_OBJECT,
                                   NULL, 0);
    seaf_warning ("[recvcommit] Failed to write commit object.\n");
    ccnet_processor_done (processor, FALSE);
}

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    switch (processor->state) {
    case RECV_OBJECT:
        if (strncmp(code, SC_OBJECT, 3) == 0) {
            receive_commit (processor, content, clen);
        } else if (strncmp(code, SC_END, 3) == 0) {
            seaf_debug ("[recvcommit] Recv commit end.\n");
            ccnet_processor_done (processor, TRUE);
        } else {
            seaf_warning ("[recvcommit] Bad update: %s %s\n", code, code_msg);
            ccnet_processor_send_response (processor,
                                           SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                           NULL, 0);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    default:
        g_return_if_reached ();
    }
}
