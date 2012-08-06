/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "include.h"

#include <ccnet/processor.h>
#include "rpcserver-proc.h"
#include "searpc-server.h"
#include "rpc-common.h"

typedef struct {
    char *buf;
    int   len;
    int   off;
} CcnetRpcserverProcPriv;

#define GET_PRIV(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_RPCSERVER_PROC, CcnetRpcserverProcPriv))

G_DEFINE_TYPE (CcnetRpcserverProc, ccnet_rpcserver_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (ccnet_rpcserver_proc_parent_class)->release_resource (processor);
}


static void
ccnet_rpcserver_proc_class_init (CcnetRpcserverProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;
    proc_class->name = "rpcserver-proc";

    g_type_class_add_private (klass, sizeof(CcnetRpcserverProcPriv));
}

static void
ccnet_rpcserver_proc_init (CcnetRpcserverProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    return 0;
}


static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    CcnetRpcserverProcPriv *priv = GET_PRIV (processor);

    if (memcmp (code, SC_CLIENT_CALL, 3) == 0) {
        gsize ret_len;
        char *svc_name = processor->name;
        char *ret = searpc_server_call_function (svc_name, content, clen, &ret_len);

        g_assert (ret != NULL);
        if (ret_len < MAX_TRANSFER_LENGTH) {
            ccnet_processor_send_response (
                processor, SC_SERVER_RET, SS_SERVER_RET, ret, ret_len + 1);
            g_free (ret);
            /* ccnet_processor_done (processor, TRUE); */
            return;
        }

        /* we need to split data into multiple segments */
        priv->buf = ret;
        priv->len = ret_len + 1; /* include trailing '\0' */
        priv->off = 0;

        ccnet_processor_send_response (processor, SC_SERVER_MORE,
                                       SS_SERVER_MORE, priv->buf,
                                       MAX_TRANSFER_LENGTH);
        priv->off = MAX_TRANSFER_LENGTH;

        return;
    }

    if (memcmp (code, SC_CLIENT_MORE, 3) == 0) {
        if (priv->off + MAX_TRANSFER_LENGTH < priv->len) {
            ccnet_processor_send_response (
                processor, SC_SERVER_MORE, SS_SERVER_MORE,
                priv->buf + priv->off, MAX_TRANSFER_LENGTH);
            priv->off += MAX_TRANSFER_LENGTH;
        } else {
            ccnet_processor_send_response (
                processor, SC_SERVER_RET, SS_SERVER_RET,
                priv->buf + priv->off, priv->len - priv->off);
            g_free (priv->buf);
            /* ccnet_processor_done (processor, TRUE); */
        }
        return;
    }

    ccnet_processor_send_response (processor, SC_BAD_UPDATE_CODE,
                                   SS_BAD_UPDATE_CODE, NULL, 0);
    g_warning ("[rpc-server] Bad update: %s %s.\n", code, code_msg);
    if (priv->buf)
        g_free (priv->buf);
    ccnet_processor_done (processor, FALSE);
}
