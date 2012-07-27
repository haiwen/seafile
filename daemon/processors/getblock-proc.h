/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_GETBLOCK_PROC_H
#define SEAFILE_GETBLOCK_PROC_H

#include <glib-object.h>
#include "transfer-mgr.h"

#define SEAFILE_TYPE_GETBLOCK_PROC                  (seafile_getblock_proc_get_type ())
#define SEAFILE_GETBLOCK_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_GETBLOCK_PROC, SeafileGetblockProc))
#define SEAFILE_IS_GETBLOCK_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_GETBLOCK_PROC))
#define SEAFILE_GETBLOCK_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_GETBLOCK_PROC, SeafileGetblockProcClass))
#define IS_SEAFILE_GETBLOCK_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_GETBLOCK_PROC))
#define SEAFILE_GETBLOCK_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_GETBLOCK_PROC, SeafileGetblockProcClass))

typedef struct _SeafileGetblockProc SeafileGetblockProc;
typedef struct _SeafileGetblockProcClass SeafileGetblockProcClass;

struct _SeafileGetblockProc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
    Bitfield       active;       /* what blocks to download from the peer */
    Bitfield       block_bitmap; /* what blocks the peer have */

    int            tx_bytes;
    int            tx_time;
    double         avg_tx_rate;
    int            pending_blocks;
};

struct _SeafileGetblockProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_getblock_proc_get_type ();

int seafile_getblock_proc_get_block (SeafileGetblockProc *proc,
                                     int block_idx);

gboolean seafile_getblock_proc_is_ready (SeafileGetblockProc *proc);

#endif
