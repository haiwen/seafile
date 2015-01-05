/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_GETFS_V2_PROC_H
#define SEAFILE_GETFS_V2_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>
#include "transfer-mgr.h"

#define SEAFILE_TYPE_GETFS_V2_PROC                  (seafile_getfs_v2_proc_get_type ())
#define SEAFILE_GETFS_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_GETFS_V2_PROC, SeafileGetfsV2Proc))
#define SEAFILE_IS_GETFS_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_GETFS_V2_PROC))
#define SEAFILE_GETFS_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_GETFS_V2_PROC, SeafileGetfsV2ProcClass))
#define IS_SEAFILE_GETFS_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_GETFS_V2_PROC))
#define SEAFILE_GETFS_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_GETFS_V2_PROC, SeafileGetfsV2ProcClass))

typedef struct _SeafileGetfsV2Proc SeafileGetfsV2Proc;
typedef struct _SeafileGetfsV2ProcClass SeafileGetfsV2ProcClass;

struct _SeafileGetfsV2Proc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
};

struct _SeafileGetfsV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_getfs_v2_proc_get_type ();

#endif

