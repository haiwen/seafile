/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_CHECKBL_PROC_H
#define SEAFILE_CHECKBL_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_CHECKBL_PROC                  (seafile_checkbl_proc_get_type ())
#define SEAFILE_CHECKBL_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_CHECKBL_PROC, SeafileCheckblProc))
#define SEAFILE_IS_CHECKBL_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_CHECKBL_PROC))
#define SEAFILE_CHECKBL_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_CHECKBL_PROC, SeafileCheckblProcClass))
#define IS_SEAFILE_CHECKBL_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_CHECKBL_PROC))
#define SEAFILE_CHECKBL_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_CHECKBL_PROC, SeafileCheckblProcClass))

typedef struct _SeafileCheckblProc SeafileCheckblProc;
typedef struct _SeafileCheckblProcClass SeafileCheckblProcClass;

struct _SeafileCheckblProc {
    CcnetProcessor parent_instance;
};

struct _SeafileCheckblProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_checkbl_proc_get_type ();

#endif

