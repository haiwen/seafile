/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SENDBLOCK_PROC_H
#define SEAFILE_SENDBLOCK_PROC_H

#include <glib-object.h>
#include "transfer-mgr.h"

#define SEAFILE_TYPE_SENDBLOCK_PROC                  (seafile_sendblock_proc_get_type ())
#define SEAFILE_SENDBLOCK_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SENDBLOCK_PROC, SeafileSendblockProc))
#define SEAFILE_IS_SENDBLOCK_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SENDBLOCK_PROC))
#define SEAFILE_SENDBLOCK_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SENDBLOCK_PROC, SeafileSendblockProcClass))
#define IS_SEAFILE_SENDBLOCK_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SENDBLOCK_PROC))
#define SEAFILE_SENDBLOCK_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SENDBLOCK_PROC, SeafileSendblockProcClass))

typedef struct _SeafileSendblockProc SeafileSendblockProc;
typedef struct _SeafileSendblockProcClass SeafileSendblockProcClass;

struct _SeafileSendblockProc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
    Bitfield       active;
    Bitfield       block_bitmap;

    int            tx_bytes;
    int            tx_time;
    double         avg_tx_rate;
    int            pending_blocks;
};

struct _SeafileSendblockProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sendblock_proc_get_type ();

int seafile_sendblock_proc_send_block (SeafileSendblockProc *proc,
                                       int block_idx);

gboolean seafile_sendblock_proc_is_ready (SeafileSendblockProc *proc);

#endif
