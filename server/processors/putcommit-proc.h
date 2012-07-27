/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTCOMMIT_PROC_H
#define SEAFILE_PUTCOMMIT_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_PUTCOMMIT_PROC                  (seafile_putcommit_proc_get_type ())
#define SEAFILE_PUTCOMMIT_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTCOMMIT_PROC, SeafilePutcommitProc))
#define SEAFILE_IS_PUTCOMMIT_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTCOMMIT_PROC))
#define SEAFILE_PUTCOMMIT_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTCOMMIT_PROC, SeafilePutcommitProcClass))
#define IS_SEAFILE_PUTCOMMIT_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTCOMMIT_PROC))
#define SEAFILE_PUTCOMMIT_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTCOMMIT_PROC, SeafilePutcommitProcClass))

typedef struct _SeafilePutcommitProc SeafilePutcommitProc;
typedef struct _SeafilePutcommitProcClass SeafilePutcommitProcClass;

struct _SeafilePutcommitProc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutcommitProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putcommit_proc_get_type ();

#endif
