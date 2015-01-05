/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SENDFS_V2_PROC_H
#define SEAFILE_SENDFS_V2_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>
#include "transfer-mgr.h"

#define SEAFILE_TYPE_SENDFS_V2_PROC                  (seafile_sendfs_v2_proc_get_type ())
#define SEAFILE_SENDFS_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SENDFS_V2_PROC, SeafileSendfsV2Proc))
#define SEAFILE_IS_SENDFS_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SENDFS_V2_PROC))
#define SEAFILE_SENDFS_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SENDFS_V2_PROC, SeafileSendfsV2ProcClass))
#define IS_SEAFILE_SENDFS_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SENDFS_V2_PROC))
#define SEAFILE_SENDFS_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SENDFS_V2_PROC, SeafileSendfsV2ProcClass))

typedef struct _SeafileSendfsV2Proc SeafileSendfsV2Proc;
typedef struct _SeafileSendfsV2ProcClass SeafileSendfsV2ProcClass;

struct _SeafileSendfsV2Proc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
};

struct _SeafileSendfsV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sendfs_v2_proc_get_type ();

#endif

