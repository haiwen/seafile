/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_NOTIFYSYNC_PROC_H
#define SEAFILE_NOTIFYSYNC_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_NOTIFYSYNC_PROC                  (seafile_notifysync_proc_get_type ())
#define SEAFILE_NOTIFYSYNC_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_NOTIFYSYNC_PROC, SeafileNotifysyncProc))
#define SEAFILE_IS_NOTIFYSYNC_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_NOTIFYSYNC_PROC))
#define SEAFILE_NOTIFYSYNC_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_NOTIFYSYNC_PROC, SeafileNotifysyncProcClass))
#define IS_SEAFILE_NOTIFYSYNC_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_NOTIFYSYNC_PROC))
#define SEAFILE_NOTIFYSYNC_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_NOTIFYSYNC_PROC, SeafileNotifysyncProcClass))

typedef struct _SeafileNotifysyncProc SeafileNotifysyncProc;
typedef struct _SeafileNotifysyncProcClass SeafileNotifysyncProcClass;

struct _SeafileNotifysyncProc {
    CcnetProcessor parent_instance;
};

struct _SeafileNotifysyncProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_notifysync_proc_get_type ();

#endif

