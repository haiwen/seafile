/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_RECVBRANCH_PROC_H
#define SEAFILE_RECVBRANCH_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_RECVBRANCH_PROC                  (seafile_recvbranch_proc_get_type ())
#define SEAFILE_RECVBRANCH_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_RECVBRANCH_PROC, SeafileRecvbranchProc))
#define SEAFILE_IS_RECVBRANCH_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_RECVBRANCH_PROC))
#define SEAFILE_RECVBRANCH_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_RECVBRANCH_PROC, SeafileRecvbranchProcClass))
#define IS_SEAFILE_RECVBRANCH_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_RECVBRANCH_PROC))
#define SEAFILE_RECVBRANCH_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_RECVBRANCH_PROC, SeafileRecvbranchProcClass))

typedef struct _SeafileRecvbranchProc SeafileRecvbranchProc;
typedef struct _SeafileRecvbranchProcClass SeafileRecvbranchProcClass;

struct _SeafileRecvbranchProc {
    CcnetProcessor parent_instance;
};

struct _SeafileRecvbranchProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_recvbranch_proc_get_type ();

#endif

