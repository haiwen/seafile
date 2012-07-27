/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_GETBLOCK_V2_PROC_H
#define SEAFILE_GETBLOCK_V2_PROC_H

#include <glib-object.h>
#include "transfer-mgr.h"

#define SEAFILE_TYPE_GETBLOCK_V2_PROC                  (seafile_getblock_v2_proc_get_type ())
#define SEAFILE_GETBLOCK_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_GETBLOCK_V2_PROC, SeafileGetblockV2Proc))
#define SEAFILE_IS_GETBLOCK_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_GETBLOCK_V2_PROC))
#define SEAFILE_GETBLOCK_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_GETBLOCK_V2_PROC, SeafileGetblockV2ProcClass))
#define IS_SEAFILE_GETBLOCK_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_GETBLOCK_V2_PROC))
#define SEAFILE_GETBLOCK_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_GETBLOCK_V2_PROC, SeafileGetblockV2ProcClass))

typedef struct _SeafileGetblockV2Proc SeafileGetblockV2Proc;
typedef struct _SeafileGetblockV2ProcClass SeafileGetblockV2ProcClass;

struct _SeafileGetblockV2Proc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
    Bitfield       active;       /* what blocks to download from the peer */
    Bitfield       block_bitmap; /* what blocks the peer have */

    int            tx_bytes;
    int            tx_time;
    double         avg_tx_rate;
    int            pending_blocks;
};

struct _SeafileGetblockV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_getblock_v2_proc_get_type ();

int seafile_getblock_v2_proc_get_block (SeafileGetblockV2Proc *proc,
                                     int block_idx);

gboolean seafile_getblock_v2_proc_is_ready (SeafileGetblockV2Proc *proc);

#endif
