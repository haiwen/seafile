/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "include.h"

#include <ccnet/ccnet-client.h>
#include <ccnet/processor.h>
#include <ccnet/job-mgr.h>
#include "threaded-rpcserver-proc.h"
#include "searpc-server.h"
#include "rpc-common.h"

typedef struct {
    char *call_buf;
    gsize call_len;
    char *buf;
    gsize len;
    int   off;
    char *error_message;
} CcnetThreadedRpcserverProcPriv;

#define GET_PRIV(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_THREADED_RPCSERVER_PROC, CcnetThreadedRpcserverProcPriv))

G_DEFINE_TYPE (CcnetThreadedRpcserverProc, ccnet_threaded_rpcserver_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (ccnet_threaded_rpcserver_proc_parent_class)->release_resource (processor);
}


static void
ccnet_threaded_rpcserver_proc_class_init (CcnetThreadedRpcserverProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;
    proc_class->name = "threaded-rpcserver-proc";

    g_type_class_add_private (klass, sizeof(CcnetThreadedRpcserverProcPriv));
}

static void
ccnet_threaded_rpcserver_proc_init (CcnetThreadedRpcserverProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    return 0;
}

static void *
call_function_job (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    CcnetThreadedRpcserverProcPriv *priv = GET_PRIV(processor);
    char *svc_name = processor->name;

    priv->buf = searpc_server_call_function (svc_name, priv->call_buf, priv->call_len,
                                             &priv->len);
    g_free (priv->call_buf);

    return vprocessor;
}

static void
call_function_done (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    CcnetThreadedRpcserverProcPriv *priv = GET_PRIV(processor);

    if (priv->buf) {
        if (priv->len < MAX_TRANSFER_LENGTH) {
            ccnet_processor_send_response (processor, SC_SERVER_RET, SS_SERVER_RET,
                                           priv->buf, priv->len + 1);
            g_free (priv->buf);
            /* ccnet_processor_done (processor, TRUE); */
            return;
        }

        /* we need to split data into multiple segments */
        ccnet_processor_send_response (processor, SC_SERVER_MORE,
                                       SS_SERVER_MORE, priv->buf,
                                       MAX_TRANSFER_LENGTH);
        priv->off = MAX_TRANSFER_LENGTH;
    } else {
        char *message = priv->error_message ? priv->error_message : "";
        ccnet_processor_send_response (processor, SC_SERVER_ERR, 
                                       message,
                                       NULL, 0);
        g_free (priv->error_message);
        ccnet_processor_done (processor, FALSE);
    }
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    CcnetThreadedRpcserverProcPriv *priv = GET_PRIV (processor);

    if (memcmp (code, SC_CLIENT_CALL, 3) == 0) {
        priv->call_buf = g_memdup (content, clen);
        priv->call_len = (gsize)clen;
        ccnet_job_manager_schedule_job (processor->session->job_mgr,
                                        call_function_job,
                                        call_function_done,
                                        processor);
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
