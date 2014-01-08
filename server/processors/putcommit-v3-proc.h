/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTCOMMIT_V3_PROC_H
#define SEAFILE_PUTCOMMIT_V3_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_PUTCOMMIT_V3_PROC                  (seafile_putcommit_v3_proc_get_type ())
#define SEAFILE_PUTCOMMIT_V3_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTCOMMIT_V3_PROC, SeafilePutcommitV3Proc))
#define SEAFILE_IS_PUTCOMMIT_V3_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTCOMMIT_V3_PROC))
#define SEAFILE_PUTCOMMIT_V3_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTCOMMIT_V3_PROC, SeafilePutcommitV3ProcClass))
#define IS_SEAFILE_PUTCOMMIT_V3_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTCOMMIT_V3_PROC))
#define SEAFILE_PUTCOMMIT_V3_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTCOMMIT_V3_PROC, SeafilePutcommitV3ProcClass))

typedef struct _SeafilePutcommitV3Proc SeafilePutcommitV3Proc;
typedef struct _SeafilePutcommitV3ProcClass SeafilePutcommitV3ProcClass;

struct _SeafilePutcommitV3Proc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutcommitV3ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putcommit_v3_proc_get_type ();

#endif
