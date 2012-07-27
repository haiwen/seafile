/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_NOTIFYSYNC_SLAVE_PROC_H
#define SEAFILE_NOTIFYSYNC_SLAVE_PROC_H

#include <glib-object.h>

#define SEAFILE_TYPE_NOTIFYSYNC_SLAVE_PROC                  (seafile_notifysync_slave_proc_get_type ())
#define SEAFILE_NOTIFYSYNC_SLAVE_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_NOTIFYSYNC_SLAVE_PROC, SeafileNotifysyncSlaveProc))
#define SEAFILE_IS_NOTIFYSYNC_SLAVE_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_NOTIFYSYNC_SLAVE_PROC))
#define SEAFILE_NOTIFYSYNC_SLAVE_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_NOTIFYSYNC_SLAVE_PROC, SeafileNotifysyncSlaveProcClass))
#define SEAFILE_IS_NOTIFYSYNC_SLAVE_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_NOTIFYSYNC_SLAVE_PROC))
#define SEAFILE_NOTIFYSYNC_SLAVE_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_NOTIFYSYNC_SLAVE_PROC, SeafileNotifysyncSlaveProcClass))

typedef struct _SeafileNotifysyncSlaveProc SeafileNotifysyncSlaveProc;
typedef struct _SeafileNotifysyncSlaveProcClass SeafileNotifysyncSlaveProcClass;

struct _SeafileNotifysyncSlaveProc {
    CcnetProcessor parent_instance;
};

struct _SeafileNotifysyncSlaveProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_notifysync_slave_proc_get_type ();

#endif
