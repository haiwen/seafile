/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_RECVFS_V2_PROC_H
#define SEAFILE_RECVFS_V2_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_RECVFS_V2_PROC                  (seafile_recvfs_v2_proc_get_type ())
#define SEAFILE_RECVFS_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_RECVFS_V2_PROC, SeafileRecvfsV2Proc))
#define SEAFILE_IS_RECVFS_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_RECVFS_V2_PROC))
#define SEAFILE_RECVFS_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_RECVFS_V2_PROC, SeafileRecvfsV2ProcClass))
#define IS_SEAFILE_RECVFS_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_RECVFS_V2_PROC))
#define SEAFILE_RECVFS_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_RECVFS_V2_PROC, SeafileRecvfsV2ProcClass))

typedef struct _SeafileRecvfsV2Proc SeafileRecvfsV2Proc;
typedef struct _SeafileRecvfsV2ProcClass SeafileRecvfsV2ProcClass;

struct _SeafileRecvfsV2Proc {
    CcnetProcessor parent_instance;
};

struct _SeafileRecvfsV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_recvfs_v2_proc_get_type ();

#endif

