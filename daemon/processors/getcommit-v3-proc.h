/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_GETCOMMIT_V3_PROC_H
#define SEAFILE_GETCOMMIT_V3_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_GETCOMMIT_V3_PROC                  (seafile_getcommit_v3_proc_get_type ())
#define SEAFILE_GETCOMMIT_V3_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_GETCOMMIT_V3_PROC, SeafileGetcommitV3Proc))
#define SEAFILE_IS_GETCOMMIT_V3_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_GETCOMMIT_V3_PROC))
#define SEAFILE_GETCOMMIT_V3_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_GETCOMMIT_V3_PROC, SeafileGetcommitV3ProcClass))
#define IS_SEAFILE_GETCOMMIT_V3_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_GETCOMMIT_V3_PROC))
#define SEAFILE_GETCOMMIT_V3_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_GETCOMMIT_V3_PROC, SeafileGetcommitV3ProcClass))

typedef struct _SeafileGetcommitV3Proc SeafileGetcommitV3Proc;
typedef struct _SeafileGetcommitV3ProcClass SeafileGetcommitV3ProcClass;

struct _SeafileGetcommitV3Proc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
};

struct _SeafileGetcommitV3ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_getcommit_v3_proc_get_type ();

#endif
