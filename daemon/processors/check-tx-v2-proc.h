/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_CHECK_TX_V2_PROC_H
#define SEAFILE_CHECK_TX_V2_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#include "transfer-mgr.h"

#define SEAFILE_TYPE_CHECK_TX_V2_PROC               (seafile_check_tx_v2_proc_get_type ())
#define SEAFILE_CHECK_TX_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_CHECK_TX_V2_PROC, SeafileCheckTxV2Proc))
#define SEAFILE_IS_CHECK_TX_V2_PROC(obj)            (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_CHECK_TX_PROC))
#define SEAFILE_CHECK_TX_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_CHECK_TX_V2_PROC, SeafileCheckTxV2ProcClass))
#define IS_SEAFILE_CHECK_TX_V2_PROC_CLASS(klass)    (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_CHECK_TX_V2_PROC))
#define SEAFILE_CHECK_TX_V2_PROC_GET_CLASS(obj)     (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_CHECK_TX_V2_PROC, SeafileCheckTxV2ProcClass))

typedef struct _SeafileCheckTxV2Proc SeafileCheckTxV2Proc;
typedef struct _SeafileCheckTxV2ProcClass SeafileCheckTxV2ProcClass;

struct _SeafileCheckTxV2Proc {
    CcnetProcessor parent_instance;

    int           type;
    TransferTask *task;
};

struct _SeafileCheckTxV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_check_tx_v2_proc_get_type ();

#endif
