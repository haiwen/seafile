/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTBRANCH_PROC_H
#define SEAFILE_PUTBRANCH_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_PUTBRANCH_PROC                  (seafile_putbranch_proc_get_type ())
#define SEAFILE_PUTBRANCH_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTBRANCH_PROC, SeafilePutbranchProc))
#define SEAFILE_IS_PUTBRANCH_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTBRANCH_PROC))
#define SEAFILE_PUTBRANCH_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTBRANCH_PROC, SeafilePutbranchProcClass))
#define IS_SEAFILE_PUTBRANCH_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTBRANCH_PROC))
#define SEAFILE_PUTBRANCH_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTBRANCH_PROC, SeafilePutbranchProcClass))

typedef struct _SeafilePutbranchProc SeafilePutbranchProc;
typedef struct _SeafilePutbranchProcClass SeafilePutbranchProcClass;

struct _SeafilePutbranchProc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutbranchProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putbranch_proc_get_type ();

#endif

