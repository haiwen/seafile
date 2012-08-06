/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>

#include <ccnet.h>
#include <searpc-client.h>
#include "rpc-common.h"
#include "async-rpc-proc.h"

#define MAX_RET_LEN 5242880     /* 5M */

typedef struct {
    const char *service;
    char *fcall_str;
    size_t fcall_len;
    void *rpc_priv;
    GString *buf;
} CcnetAsyncRpcProcPriv;

#define GET_PRIV(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE ((o), CCNET_TYPE_ASYNC_RPC_PROC, CcnetAsyncRpcProcPriv))

G_DEFINE_TYPE (CcnetAsyncRpcProc, ccnet_async_rpc_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CcnetAsyncRpcProcPriv *priv = GET_PRIV (processor);
    g_free (priv->fcall_str);
    g_assert (priv->buf == NULL);

    CCNET_PROCESSOR_CLASS (ccnet_async_rpc_proc_parent_class)->release_resource (processor);
}


static void
ccnet_async_rpc_proc_class_init (CcnetAsyncRpcProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
    proc_class->name = "async-rpc-proc";

    g_type_class_add_private (klass, sizeof(CcnetAsyncRpcProcPriv));
}

static void
ccnet_async_rpc_proc_init (CcnetAsyncRpcProc *processor)
{
}

void
ccnet_async_rpc_proc_set_rpc (CcnetAsyncRpcProc *proc,
                              const char *service,
                              char *fcall_str,
                              size_t fcall_len,
                              void *rpc_priv)
{
    CcnetAsyncRpcProcPriv *priv = GET_PRIV (proc);

    priv->service = service;
    priv->fcall_str = fcall_str;
    priv->fcall_len = fcall_len;
    priv->rpc_priv = rpc_priv;
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    CcnetAsyncRpcProcPriv *priv = GET_PRIV (processor);
    char buf[256];

    if (argc != 0) {
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (processor->peer_id) {
        snprintf (buf, sizeof(buf), "remote %s %s",
                  processor->peer_id, priv->service);
    } else
        snprintf (buf, sizeof(buf), "%s", priv->service);
    ccnet_processor_send_request (processor, buf);

    return 0;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    CcnetAsyncRpcProcPriv *priv = GET_PRIV (processor);
    
    if (memcmp (code, SC_OK, 3) == 0) {
        ccnet_processor_send_update (processor, SC_CLIENT_CALL, SS_CLIENT_CALL,
                                     priv->fcall_str,
                                     priv->fcall_len);
        return;
    }

    if (memcmp (code, SC_SERVER_RET, 3) == 0) {
        if (priv->buf == NULL)
            searpc_client_generic_callback (content, clen, priv->rpc_priv, NULL);
        else {
            g_string_append_len (priv->buf, content, clen);
            searpc_client_generic_callback (priv->buf->str, priv->buf->len,
                                            priv->rpc_priv, NULL);
            g_string_free (priv->buf, TRUE);
            priv->buf = NULL;
        }
        ccnet_processor_done (processor, TRUE);
    } else if (memcmp (code, SC_SERVER_MORE, 3) == 0) {
        if (priv->buf == NULL)
            priv->buf = g_string_new (NULL);
        g_string_append_len (priv->buf, content, clen);

        if (priv->buf->len > MAX_RET_LEN) {
            g_warning ("[async-rpc] ret is too long\n");
            g_string_free (priv->buf, TRUE);
            priv->buf = NULL;
            ccnet_processor_send_update (processor, "400",
                                         "Too many data", NULL, 0);
            ccnet_processor_done (processor, FALSE);
        } else
            ccnet_processor_send_update (
                processor, SC_CLIENT_MORE, SS_CLIENT_MORE, NULL, 0);
    }

}
