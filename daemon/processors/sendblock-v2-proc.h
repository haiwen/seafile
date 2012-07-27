/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SENDBLOCK_V2_PROC_H
#define SEAFILE_SENDBLOCK_V2_PROC_H

#include <glib-object.h>
#include "transfer-mgr.h"

#define SEAFILE_TYPE_SENDBLOCK_V2_PROC                  (seafile_sendblock_v2_proc_get_type ())
#define SEAFILE_SENDBLOCK_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SENDBLOCK_V2_PROC, SeafileSendblockV2Proc))
#define SEAFILE_IS_SENDBLOCK_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SENDBLOCK_V2_PROC))
#define SEAFILE_SENDBLOCK_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SENDBLOCK_V2_PROC, SeafileSendblockV2ProcClass))
#define IS_SEAFILE_SENDBLOCK_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SENDBLOCK_V2_PROC))
#define SEAFILE_SENDBLOCK_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SENDBLOCK_V2_PROC, SeafileSendblockV2ProcClass))

typedef struct _SeafileSendblockV2Proc SeafileSendblockV2Proc;
typedef struct _SeafileSendblockV2ProcClass SeafileSendblockV2ProcClass;

struct _SeafileSendblockV2Proc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
    Bitfield       active;
    Bitfield       block_bitmap;

    int            tx_bytes;
    int            tx_time;
    double         avg_tx_rate;
    int            pending_blocks;
};

struct _SeafileSendblockV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sendblock_v2_proc_get_type ();

int seafile_sendblock_v2_proc_send_block (SeafileSendblockV2Proc *proc,
                                          int block_idx);

gboolean seafile_sendblock_v2_proc_is_ready (SeafileSendblockV2Proc *proc);

#endif
