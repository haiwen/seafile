/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_ASYNC_RPC_PROC_H
#define CCNET_ASYNC_RPC_PROC_H

#include <glib-object.h>


#define CCNET_TYPE_ASYNC_RPC_PROC                  (ccnet_async_rpc_proc_get_type ())
#define CCNET_ASYNC_RPC_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_ASYNC_RPC_PROC, CcnetAsyncRpcProc))
#define CCNET_IS_ASYNC_RPC_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_ASYNC_RPC_PROC))
#define CCNET_ASYNC_RPC_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_ASYNC_RPC_PROC, CcnetAsyncRpcProcClass))
#define IS_CCNET_ASYNC_RPC_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_ASYNC_RPC_PROC))
#define CCNET_ASYNC_RPC_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_ASYNC_RPC_PROC, CcnetAsyncRpcProcClass))

typedef struct _CcnetAsyncRpcProc CcnetAsyncRpcProc;
typedef struct _CcnetAsyncRpcProcClass CcnetAsyncRpcProcClass;

struct _CcnetAsyncRpcProc {
    CcnetProcessor parent_instance;
};

struct _CcnetAsyncRpcProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_async_rpc_proc_get_type ();

void ccnet_async_rpc_proc_set_rpc (CcnetAsyncRpcProc *proc,
                                   const char *service,
                                   char *fcall_str,
                                   size_t fcall_len,
                                   void *rpc_priv);
#endif

