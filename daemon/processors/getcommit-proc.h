/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_GETCOMMIT_PROC_H
#define SEAFILE_GETCOMMIT_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_GETCOMMIT_PROC                  (seafile_getcommit_proc_get_type ())
#define SEAFILE_GETCOMMIT_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_GETCOMMIT_PROC, SeafileGetcommitProc))
#define SEAFILE_IS_GETCOMMIT_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_GETCOMMIT_PROC))
#define SEAFILE_GETCOMMIT_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_GETCOMMIT_PROC, SeafileGetcommitProcClass))
#define IS_SEAFILE_GETCOMMIT_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_GETCOMMIT_PROC))
#define SEAFILE_GETCOMMIT_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_GETCOMMIT_PROC, SeafileGetcommitProcClass))

typedef struct _SeafileGetcommitProc SeafileGetcommitProc;
typedef struct _SeafileGetcommitProcClass SeafileGetcommitProcClass;

struct _SeafileGetcommitProc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
};

struct _SeafileGetcommitProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_getcommit_proc_get_type ();

#endif
