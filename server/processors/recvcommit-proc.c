/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "recvcommit-proc.h"
#include "processors/objecttx-common.h"
#include "seaf-utils.h"

#include "log.h"

#define CHECK_INTERVAL 100      /* 100ms */

enum {
    RECV_IDS,
    FETCH_OBJECT
};

typedef struct  {
    char        object_path[SEAF_PATH_MAX];
    char        tmp_object_path[SEAF_PATH_MAX];
    char        buf[4096];
    char       *bufptr;
    int         pending_objects;
} SeafileRecvcommitProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_RECVCOMMIT_PROC, SeafileRecvcommitProcPriv))

#define USE_PRIV \
    SeafileRecvcommitProcPriv *priv = GET_PRIV(processor);

static int recv_commit_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);


G_DEFINE_TYPE (SeafileRecvcommitProc, seafile_recvcommit_proc, CCNET_TYPE_PROCESSOR)

static void
seafile_recvcommit_proc_class_init (SeafileRecvcommitProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "recvcommit-proc";
    proc_class->start = recv_commit_start;
    proc_class->handle_update = handle_update;

    g_type_class_add_private (klass, sizeof (SeafileRecvcommitProcPriv));
}

static void
seafile_recvcommit_proc_init (SeafileRecvcommitProc *processor)
{
}

inline static void
request_object_batch_begin (SeafileRecvcommitProcPriv *priv)
{
    priv->bufptr = priv->buf;
}

inline static void
request_object_batch (SeafileRecvcommitProcPriv *priv, const char *id)
{
    memcpy (priv->bufptr, id, 40);
    priv->bufptr += 40;
    *priv->bufptr = '\n';
    priv->bufptr++;

    ++priv->pending_objects;
}

inline static void
request_object_batch_flush (CcnetProcessor *processor,
                            SeafileRecvcommitProcPriv *priv)
{
    if (priv->bufptr == priv->buf)
        return;
    *priv->bufptr = '\0';       /* add ending '\0' */
    priv->bufptr++;
    ccnet_processor_send_response (processor, SC_GET_OBJECT, SS_GET_OBJECT,
                                   priv->buf, priv->bufptr - priv->buf);
}

static int
recv_commit_start (CcnetProcessor *processor, int argc, char **argv)
{
    char *session_token;

    if (argc != 2) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    session_token = argv[1];
    if (seaf_token_manager_verify_token (seaf->token_mgr,
                                         processor->peer_id,
                                         session_token, NULL) == 0) {
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        processor->state = RECV_IDS;
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
check_commit (CcnetProcessor *processor, const char *commit_id)
{
    USE_PRIV;

    if (!seaf_commit_manager_commit_exists (seaf->commit_mgr, commit_id)) {
        request_object_batch (priv, commit_id);
    }
}

static int
save_commit (ObjectPack *pack, int len)
{
    return seaf_obj_store_write_obj (seaf->commit_mgr->obj_store,
                                     pack->id,
                                     pack->object,
                                     len - 41);
}

static void
receive_commit (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;
    ObjectPack *pack = (ObjectPack *)content;

    if (clen < sizeof(ObjectPack)) {
        seaf_warning ("invalid object id.\n");
        goto bad;
    }

    --priv->pending_objects;

    /* TODO: check commit format here. */

    if (save_commit (pack, clen) < 0) {
        goto bad;
    }

    if (priv->pending_objects == 0) {
        ccnet_processor_send_response (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
    }

    return;

bad:
    ccnet_processor_send_response (processor, SC_BAD_OBJECT,
                                   SS_BAD_OBJECT, NULL, 0);
    seaf_warning ("Bad commit object received.\n");
    ccnet_processor_done (processor, FALSE);
}

static void
process_commit_list (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;
    char *object_id;
    int n_objects;
    int i;

    if (clen % 41 != 1 || content[clen-1] != '\0') {
        seaf_warning ("Bad commit id list.\n");
        ccnet_processor_send_response (processor, SC_BAD_OL, SS_BAD_OL, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    n_objects = clen/41;

    request_object_batch_begin(priv);

    object_id = content;
    for (i = 0; i < n_objects; ++i) {
        object_id[40] = '\0';
        check_commit (processor, object_id);
        object_id += 41;
    }
    
    request_object_batch_flush (processor, priv);

    if (priv->pending_objects == 0) {
        ccnet_processor_send_response (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
    }
}

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    switch (processor->state) {
    case RECV_IDS:
        if (strncmp(code, SC_COMMIT_IDS, 3) == 0) {
            /* add to inspect queue */
            process_commit_list (processor, content, clen);
        } else if (strncmp(code, SC_END, 3) == 0) {
            /* change state to FETCH_OBJECT */
            processor->state = FETCH_OBJECT;
        } else {
            seaf_warning ("Bad update: %s %s\n", code, code_msg);
            ccnet_processor_send_response (processor,
                                           SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                           NULL, 0);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    case FETCH_OBJECT:
        if (strncmp(code, SC_OBJECT, 3) == 0) {
            receive_commit (processor, content, clen);
        } else {
            seaf_warning ("Bad update: %s %s\n", code, code_msg);
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
