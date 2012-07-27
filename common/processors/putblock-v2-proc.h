/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTBLOCK_V2_PROC_H
#define SEAFILE_PUTBLOCK_V2_PROC_H

#include <glib-object.h>
#include <ccnet/timer.h>

#define SEAFILE_TYPE_PUTBLOCK_V2_PROC                  (seafile_putblock_v2_proc_get_type ())
#define SEAFILE_PUTBLOCK_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTBLOCK_V2_PROC, SeafilePutblockV2Proc))
#define SEAFILE_IS_PUTBLOCK_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTBLOCK_V2_PROC))
#define SEAFILE_PUTBLOCK_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTBLOCK_V2_PROC, SeafilePutblockV2ProcClass))
#define IS_SEAFILE_PUTBLOCK_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTBLOCK_V2_PROC))
#define SEAFILE_PUTBLOCK_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTBLOCK_V2_PROC, SeafilePutblockV2ProcClass))

typedef struct _SeafilePutblockV2Proc SeafilePutblockV2Proc;
typedef struct _SeafilePutblockV2ProcClass SeafilePutblockV2ProcClass;

struct _SeafilePutblockV2Proc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutblockV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putblock_v2_proc_get_type ();

#endif
