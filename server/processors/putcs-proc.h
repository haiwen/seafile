/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTCS_PROC_H
#define SEAFILE_PUTCS_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#define SEAFILE_TYPE_PUTCS_PROC                  (seafile_putcs_proc_get_type ())
#define SEAFILE_PUTCS_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTCS_PROC, SeafilePutcsProc))
#define SEAFILE_IS_PUTCS_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTCS_PROC))
#define SEAFILE_PUTCS_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTCS_PROC, SeafilePutcsProcClass))
#define IS_SEAFILE_PUTCS_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTCS_PROC))
#define SEAFILE_PUTCS_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTCS_PROC, SeafilePutcsProcClass))

typedef struct _SeafilePutcsProc SeafilePutcsProc;
typedef struct _SeafilePutcsProcClass SeafilePutcsProcClass;

struct _SeafilePutcsProc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutcsProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putcs_proc_get_type ();

#endif

