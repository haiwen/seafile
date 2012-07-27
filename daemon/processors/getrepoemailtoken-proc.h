/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_GETREPOEMAILTOKEN_PROC_H
#define SEAFILE_GETREPOEMAILTOKEN_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_GETREPOEMAILTOKEN_PROC                  (seafile_getrepoemailtoken_proc_get_type ())
#define SEAFILE_GETREPOEMAILTOKEN_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_GETREPOEMAILTOKEN_PROC, SeafileGetrepoemailtokenProc))
#define SEAFILE_IS_GETREPOEMAILTOKEN_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_GETREPOEMAILTOKEN_PROC))
#define SEAFILE_GETREPOEMAILTOKEN_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_GETREPOEMAILTOKEN_PROC, SeafileGetrepoemailtokenProcClass))
#define IS_SEAFILE_GETREPOEMAILTOKEN_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_GETREPOEMAILTOKEN_PROC))
#define SEAFILE_GETREPOEMAILTOKEN_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_GETREPOEMAILTOKEN_PROC, SeafileGetrepoemailtokenProcClass))

typedef struct _SeafileGetrepoemailtokenProc SeafileGetrepoemailtokenProc;
typedef struct _SeafileGetrepoemailtokenProcClass SeafileGetrepoemailtokenProcClass;

struct _SeafileGetrepoemailtokenProc {
    CcnetProcessor parent_instance;
};

struct _SeafileGetrepoemailtokenProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_getrepoemailtoken_proc_get_type ();

#endif

