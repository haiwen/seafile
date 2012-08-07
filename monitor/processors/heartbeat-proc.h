/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_HEARTBEAT_PROC_H
#define SEAFILE_HEARTBEAT_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#define SEAFILE_TYPE_HEARTBEAT_PROC                  (seafile_heartbeat_proc_get_type ())
#define SEAFILE_HEARTBEAT_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_HEARTBEAT_PROC, SeafileHeartbeatProc))
#define SEAFILE_IS_HEARTBEAT_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_HEARTBEAT_PROC))
#define SEAFILE_HEARTBEAT_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_HEARTBEAT_PROC, SeafileHeartbeatProcClass))
#define IS_SEAFILE_HEARTBEAT_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_HEARTBEAT_PROC))
#define SEAFILE_HEARTBEAT_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_HEARTBEAT_PROC, SeafileHeartbeatProcClass))

typedef struct _SeafileHeartbeatProc SeafileHeartbeatProc;
typedef struct _SeafileHeartbeatProcClass SeafileHeartbeatProcClass;

struct _SeafileHeartbeatProc {
    CcnetProcessor parent_instance;
};

struct _SeafileHeartbeatProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_heartbeat_proc_get_type ();

#endif

