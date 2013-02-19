/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_CHECK_TX_SLAVE_V3_PROC_H
#define SEAFILE_CHECK_TX_SLAVE_V3_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#define SEAFILE_TYPE_CHECK_TX_SLAVE_V3_PROC                  (seafile_check_tx_slave_v3_proc_get_type ())
#define SEAFILE_CHECK_TX_SLAVE_V3_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_CHECK_TX_SLAVE_V3_PROC, SeafileCheckTxSlaveV3Proc))
#define SEAFILE_IS_CHECK_TX_SLAVE_V3_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_CHECK_TX_SLAVE_V3_PROC))
#define SEAFILE_CHECK_TX_SLAVE_V3_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_CHECK_TX_SLAVE_V3_PROC, SeafileCheckTxSlaveV3ProcClass))
#define IS_SEAFILE_CHECK_TX_SLAVE_V3_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_CHECK_TX_SLAVE_V3_PROC))
#define SEAFILE_CHECK_TX_SLAVE_V3_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_CHECK_TX_SLAVE_V3_PROC, SeafileCheckTxSlaveV3ProcClass))

typedef struct _SeafileCheckTxSlaveV3Proc SeafileCheckTxSlaveV3Proc;
typedef struct _SeafileCheckTxSlaveV3ProcClass SeafileCheckTxSlaveV3ProcClass;

struct _SeafileCheckTxSlaveV3Proc {
    CcnetProcessor parent_instance;
};

struct _SeafileCheckTxSlaveV3ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_check_tx_slave_v3_proc_get_type ();

#endif
