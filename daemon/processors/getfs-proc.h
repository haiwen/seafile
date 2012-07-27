/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_GETFS_PROC_H
#define SEAFILE_GETFS_PROC_H

#include <glib-object.h>
#include "transfer-mgr.h"

#define SEAFILE_TYPE_GETFS_PROC                  (seafile_getfs_proc_get_type ())
#define SEAFILE_GETFS_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_GETFS_PROC, SeafileGetfsProc))
#define SEAFILE_IS_GETFS_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_GETFS_PROC))
#define SEAFILE_GETFS_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_GETFS_PROC, SeafileGetfsProcClass))
#define IS_SEAFILE_GETFS_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_GETFS_PROC))
#define SEAFILE_GETFS_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_GETFS_PROC, SeafileGetfsProcClass))

typedef struct _SeafileGetfsProc SeafileGetfsProc;
typedef struct _SeafileGetfsProcClass SeafileGetfsProcClass;

struct _SeafileGetfsProc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
};

struct _SeafileGetfsProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_getfs_proc_get_type ();

#endif

