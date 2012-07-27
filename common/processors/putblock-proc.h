/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTBLOCK_PROC_H
#define SEAFILE_PUTBLOCK_PROC_H

#include <glib-object.h>
#include <ccnet/timer.h>

#define SEAFILE_TYPE_PUTBLOCK_PROC                  (seafile_putblock_proc_get_type ())
#define SEAFILE_PUTBLOCK_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTBLOCK_PROC, SeafilePutblockProc))
#define SEAFILE_IS_PUTBLOCK_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTBLOCK_PROC))
#define SEAFILE_PUTBLOCK_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTBLOCK_PROC, SeafilePutblockProcClass))
#define IS_SEAFILE_PUTBLOCK_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTBLOCK_PROC))
#define SEAFILE_PUTBLOCK_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTBLOCK_PROC, SeafilePutblockProcClass))

typedef struct _SeafilePutblockProc SeafilePutblockProc;
typedef struct _SeafilePutblockProcClass SeafilePutblockProcClass;

struct _SeafilePutblockProc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutblockProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putblock_proc_get_type ();

#endif
