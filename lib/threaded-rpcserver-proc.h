/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_THREADED_RPCSERVER_PROC_H
#define CCNET_THREADED_RPCSERVER_PROC_H

#include <glib-object.h>


#define CCNET_TYPE_THREADED_RPCSERVER_PROC                  (ccnet_threaded_rpcserver_proc_get_type ())
#define CCNET_THREADED_RPCSERVER_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_THREADED_RPCSERVER_PROC, CcnetThreadedRpcserverProc))
#define CCNET_IS_THREADED_RPCSERVER_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_THREADED_RPCSERVER_PROC))
#define CCNET_THREADED_RPCSERVER_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_THREADED_RPCSERVER_PROC, CcnetThreadedRpcserverProcClass))
#define IS_CCNET_THREADED_RPCSERVER_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_THREADED_RPCSERVER_PROC))
#define CCNET_THREADED_RPCSERVER_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_THREADED_RPCSERVER_PROC, CcnetThreadedRpcserverProcClass))

typedef struct _CcnetThreadedRpcserverProc CcnetThreadedRpcserverProc;
typedef struct _CcnetThreadedRpcserverProcClass CcnetThreadedRpcserverProcClass;

struct _CcnetThreadedRpcserverProc {
    CcnetProcessor parent_instance;
};

struct _CcnetThreadedRpcserverProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_threaded_rpcserver_proc_get_type ();

#endif

