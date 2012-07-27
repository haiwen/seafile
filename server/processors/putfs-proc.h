/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTFS_PROC_H
#define SEAFILE_PUTFS_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_PUTFS_PROC                  (seafile_putfs_proc_get_type ())
#define SEAFILE_PUTFS_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTFS_PROC, SeafilePutfsProc))
#define SEAFILE_IS_PUTFS_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTFS_PROC))
#define SEAFILE_PUTFS_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTFS_PROC, SeafilePutfsProcClass))
#define IS_SEAFILE_PUTFS_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTFS_PROC))
#define SEAFILE_PUTFS_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTFS_PROC, SeafilePutfsProcClass))

typedef struct _SeafilePutfsProc SeafilePutfsProc;
typedef struct _SeafilePutfsProcClass SeafilePutfsProcClass;

struct _SeafilePutfsProc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutfsProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putfs_proc_get_type ();

#endif

