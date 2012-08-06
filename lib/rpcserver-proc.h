/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_RPCSERVER_PROC_H
#define CCNET_RPCSERVER_PROC_H

#include <glib-object.h>


#define CCNET_TYPE_RPCSERVER_PROC                  (ccnet_rpcserver_proc_get_type ())
#define CCNET_RPCSERVER_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_RPCSERVER_PROC, CcnetRpcserverProc))
#define CCNET_IS_RPCSERVER_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_RPCSERVER_PROC))
#define CCNET_RPCSERVER_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_RPCSERVER_PROC, CcnetRpcserverProcClass))
#define IS_CCNET_RPCSERVER_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_RPCSERVER_PROC))
#define CCNET_RPCSERVER_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_RPCSERVER_PROC, CcnetRpcserverProcClass))

typedef struct _CcnetRpcserverProc CcnetRpcserverProc;
typedef struct _CcnetRpcserverProcClass CcnetRpcserverProcClass;

struct _CcnetRpcserverProc {
    CcnetProcessor parent_instance;
};

struct _CcnetRpcserverProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_rpcserver_proc_get_type ();

#endif

