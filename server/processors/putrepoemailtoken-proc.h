/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTREPOEMAILTOKEN_PROC_H
#define SEAFILE_PUTREPOEMAILTOKEN_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_PUTREPOEMAILTOKEN_PROC                  (seafile_putrepoemailtoken_proc_get_type ())
#define SEAFILE_PUTREPOEMAILTOKEN_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTREPOEMAILTOKEN_PROC, SeafilePutrepoemailtokenProc))
#define SEAFILE_IS_PUTREPOEMAILTOKEN_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTREPOEMAILTOKEN_PROC))
#define SEAFILE_PUTREPOEMAILTOKEN_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTREPOEMAILTOKEN_PROC, SeafilePutrepoemailtokenProcClass))
#define IS_SEAFILE_PUTREPOEMAILTOKEN_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTREPOEMAILTOKEN_PROC))
#define SEAFILE_PUTREPOEMAILTOKEN_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTREPOEMAILTOKEN_PROC, SeafilePutrepoemailtokenProcClass))

typedef struct _SeafilePutrepoemailtokenProc SeafilePutrepoemailtokenProc;
typedef struct _SeafilePutrepoemailtokenProcClass SeafilePutrepoemailtokenProcClass;

struct _SeafilePutrepoemailtokenProc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutrepoemailtokenProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putrepoemailtoken_proc_get_type ();

#endif

