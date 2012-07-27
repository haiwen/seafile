/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_CHECK_TX_SLAVE_PROC_H
#define SEAFILE_CHECK_TX_SLAVE_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#define SEAFILE_TYPE_CHECK_TX_SLAVE_PROC                  (seafile_check_tx_slave_proc_get_type ())
#define SEAFILE_CHECK_TX_SLAVE_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_CHECK_TX_SLAVE_PROC, SeafileCheckTxSlaveProc))
#define SEAFILE_IS_CHECK_TX_SLAVE_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_CHECK_TX_SLAVE_PROC))
#define SEAFILE_CHECK_TX_SLAVE_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_CHECK_TX_SLAVE_PROC, SeafileCheckTxSlaveProcClass))
#define IS_SEAFILE_CHECK_TX_SLAVE_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_CHECK_TX_SLAVE_PROC))
#define SEAFILE_CHECK_TX_SLAVE_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_CHECK_TX_SLAVE_PROC, SeafileCheckTxSlaveProcClass))

typedef struct _SeafileCheckTxSlaveProc SeafileCheckTxSlaveProc;
typedef struct _SeafileCheckTxSlaveProcClass SeafileCheckTxSlaveProcClass;

struct _SeafileCheckTxSlaveProc {
    CcnetProcessor parent_instance;
};

struct _SeafileCheckTxSlaveProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_check_tx_slave_proc_get_type ();

#endif

