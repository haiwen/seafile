/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_GETCS_V2_PROC_H
#define SEAFILE_GETCS_V2_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>
#include "transfer-mgr.h"

#define SEAFILE_TYPE_GETCS_V2_PROC                  (seafile_getcs_v2_proc_get_type ())
#define SEAFILE_GETCS_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_GETCS_V2_PROC, SeafileGetcsV2Proc))
#define SEAFILE_IS_GETCS_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_GETCS_V2_PROC))
#define SEAFILE_GETCS_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_GETCS_V2_PROC, SeafileGetcsV2ProcClass))
#define IS_SEAFILE_GETCS_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_GETCS_V2_PROC))
#define SEAFILE_GETCS_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_GETCS_V2_PROC, SeafileGetcsV2ProcClass))

typedef struct _SeafileGetcsV2Proc SeafileGetcsV2Proc;
typedef struct _SeafileGetcsV2ProcClass SeafileGetcsV2ProcClass;

struct _SeafileGetcsV2Proc {
    CcnetProcessor parent_instance;

    TransferTask *task;
};

struct _SeafileGetcsV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_getcs_v2_proc_get_type ();

#endif

