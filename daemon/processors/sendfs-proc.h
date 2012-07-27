/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SENDFS_PROC_H
#define SEAFILE_SENDFS_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>
#include "transfer-mgr.h"

#define SEAFILE_TYPE_SENDFS_PROC                  (seafile_sendfs_proc_get_type ())
#define SEAFILE_SENDFS_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SENDFS_PROC, SeafileSendfsProc))
#define SEAFILE_IS_SENDFS_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SENDFS_PROC))
#define SEAFILE_SENDFS_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SENDFS_PROC, SeafileSendfsProcClass))
#define IS_SEAFILE_SENDFS_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SENDFS_PROC))
#define SEAFILE_SENDFS_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SENDFS_PROC, SeafileSendfsProcClass))

typedef struct _SeafileSendfsProc SeafileSendfsProc;
typedef struct _SeafileSendfsProcClass SeafileSendfsProcClass;

struct _SeafileSendfsProc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
    int last_idx;               /* used in send root fs to peer */
};

struct _SeafileSendfsProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sendfs_proc_get_type ();

#endif

