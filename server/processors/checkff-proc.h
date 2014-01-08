/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_CHECKFF_PROC_H
#define SEAFILE_CHECKFF_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_CHECKFF_PROC                  (seafile_checkff_proc_get_type ())
#define SEAFILE_CHECKFF_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_CHECKFF_PROC, SeafileCheckffProc))
#define SEAFILE_IS_CHECKFF_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_CHECKFF_PROC))
#define SEAFILE_CHECKFF_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_CHECKFF_PROC, SeafileCheckffProcClass))
#define IS_SEAFILE_CHECKFF_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_CHECKFF_PROC))
#define SEAFILE_CHECKFF_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_CHECKFF_PROC, SeafileCheckffProcClass))

typedef struct _SeafileCheckffProc SeafileCheckffProc;
typedef struct _SeafileCheckffProcClass SeafileCheckffProcClass;

struct _SeafileCheckffProc {
    CcnetProcessor parent_instance;
};

struct _SeafileCheckffProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_checkff_proc_get_type ();

#endif

