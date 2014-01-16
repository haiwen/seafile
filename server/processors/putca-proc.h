/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_PUTCA_PROC_H
#define SEAFILE_PUTCA_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_PUTCA_PROC                  (seafile_putca_proc_get_type ())
#define SEAFILE_PUTCA_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_PUTCA_PROC, SeafilePutcaProc))
#define SEAFILE_IS_PUTCA_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_PUTCA_PROC))
#define SEAFILE_PUTCA_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_PUTCA_PROC, SeafilePutcaProcClass))
#define IS_SEAFILE_PUTCA_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_PUTCA_PROC))
#define SEAFILE_PUTCA_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_PUTCA_PROC, SeafilePutcaProcClass))

typedef struct _SeafilePutcaProc SeafilePutcaProc;
typedef struct _SeafilePutcaProcClass SeafilePutcaProcClass;

struct _SeafilePutcaProc {
    CcnetProcessor parent_instance;
};

struct _SeafilePutcaProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_putca_proc_get_type ();

#endif
