/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTCOMMIT_V2_PROC_H
#define SEAFILE_PUTCOMMIT_V2_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_PUTCOMMIT_V2_PROC                  (seafile_putcommit_v2_proc_get_type ())
#define SEAFILE_PUTCOMMIT_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTCOMMIT_V2_PROC, SeafilePutcommitV2Proc))
#define SEAFILE_IS_PUTCOMMIT_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTCOMMIT_V2_PROC))
#define SEAFILE_PUTCOMMIT_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTCOMMIT_V2_PROC, SeafilePutcommitV2ProcClass))
#define IS_SEAFILE_PUTCOMMIT_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTCOMMIT_V2_PROC))
#define SEAFILE_PUTCOMMIT_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTCOMMIT_V2_PROC, SeafilePutcommitV2ProcClass))

typedef struct _SeafilePutcommitV2Proc SeafilePutcommitV2Proc;
typedef struct _SeafilePutcommitV2ProcClass SeafilePutcommitV2ProcClass;

struct _SeafilePutcommitV2Proc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutcommitV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putcommit_v2_proc_get_type ();

#endif
