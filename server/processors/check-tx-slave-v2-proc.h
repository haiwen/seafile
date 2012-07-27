/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_CHECK_TX_SLAVE_V2_PROC_H
#define SEAFILE_CHECK_TX_SLAVE_V2_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#define SEAFILE_TYPE_CHECK_TX_SLAVE_V2_PROC                  (seafile_check_tx_slave_v2_proc_get_type ())
#define SEAFILE_CHECK_TX_SLAVE_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_CHECK_TX_SLAVE_V2_PROC, SeafileCheckTxSlaveV2Proc))
#define SEAFILE_IS_CHECK_TX_SLAVE_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_CHECK_TX_SLAVE_V2_PROC))
#define SEAFILE_CHECK_TX_SLAVE_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_CHECK_TX_SLAVE_V2_PROC, SeafileCheckTxSlaveV2ProcClass))
#define IS_SEAFILE_CHECK_TX_SLAVE_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_CHECK_TX_SLAVE_V2_PROC))
#define SEAFILE_CHECK_TX_SLAVE_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_CHECK_TX_SLAVE_V2_PROC, SeafileCheckTxSlaveV2ProcClass))

typedef struct _SeafileCheckTxSlaveV2Proc SeafileCheckTxSlaveV2Proc;
typedef struct _SeafileCheckTxSlaveV2ProcClass SeafileCheckTxSlaveV2ProcClass;

struct _SeafileCheckTxSlaveV2Proc {
    CcnetProcessor parent_instance;
};

struct _SeafileCheckTxSlaveV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_check_tx_slave_v2_proc_get_type ();

#endif
