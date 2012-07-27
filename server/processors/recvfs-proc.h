/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_RECVFS_PROC_H
#define SEAFILE_RECVFS_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_RECVFS_PROC                  (seafile_recvfs_proc_get_type ())
#define SEAFILE_RECVFS_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_RECVFS_PROC, SeafileRecvfsProc))
#define SEAFILE_IS_RECVFS_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_RECVFS_PROC))
#define SEAFILE_RECVFS_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_RECVFS_PROC, SeafileRecvfsProcClass))
#define IS_SEAFILE_RECVFS_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_RECVFS_PROC))
#define SEAFILE_RECVFS_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_RECVFS_PROC, SeafileRecvfsProcClass))

typedef struct _SeafileRecvfsProc SeafileRecvfsProc;
typedef struct _SeafileRecvfsProcClass SeafileRecvfsProcClass;

struct _SeafileRecvfsProc {
    CcnetProcessor parent_instance;
};

struct _SeafileRecvfsProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_recvfs_proc_get_type ();

#endif

