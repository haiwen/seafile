/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef PUT_SHAREDB_PROC_H
#define PUT_SHAREDB_PROC_H

#include <glib-object.h>

#include <ccnet/processor.h>

#define SEAFILE_TYPE_PUT_SHAREDB_PROC                  (put_sharedb_proc_get_type ())
#define PUT_SHAREDB_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_CHECKIN_PROC, PutSharedbProc))
#define SEAFILE_IS_CHECKIN_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_CHECKIN_PROC))
#define PUT_SHAREDB_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_CHECKIN_PROC, PutSharedbProcClass))
#define IS_PUT_SHAREDB_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_CHECKIN_PROC))
#define PUT_SHAREDB_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_CHECKIN_PROC, PutSharedbProcClass))

typedef struct _PutSharedbProc PutSharedbProc;
typedef struct _PutSharedbProcClass PutSharedbProcClass;

struct _PutSharedbProc {
    CcnetProcessor parent_instance;
};

struct _PutSharedbProcClass {
    CcnetProcessorClass parent_class;
};

GType put_sharedb_proc_get_type ();

#endif
