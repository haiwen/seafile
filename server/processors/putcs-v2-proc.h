/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTCS_V2_PROC_H
#define SEAFILE_PUTCS_V2_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#define SEAFILE_TYPE_PUTCS_V2_PROC                  (seafile_putcs_v2_proc_get_type ())
#define SEAFILE_PUTCS_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTCS_V2_PROC, SeafilePutcsV2Proc))
#define SEAFILE_IS_PUTCS_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTCS_V2_PROC))
#define SEAFILE_PUTCS_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTCS_V2_PROC, SeafilePutcsV2ProcClass))
#define IS_SEAFILE_PUTCS_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTCS_V2_PROC))
#define SEAFILE_PUTCS_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTCS_V2_PROC, SeafilePutcsV2ProcClass))

typedef struct _SeafilePutcsV2Proc SeafilePutcsV2Proc;
typedef struct _SeafilePutcsV2ProcClass SeafilePutcsV2ProcClass;

struct _SeafilePutcsV2Proc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutcsV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putcs_v2_proc_get_type ();

#endif

