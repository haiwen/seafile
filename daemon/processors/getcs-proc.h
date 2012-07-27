/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_GETCS_PROC_H
#define SEAFILE_GETCS_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>
#include "transfer-mgr.h"

#define SEAFILE_TYPE_GETCS_PROC                  (seafile_getcs_proc_get_type ())
#define SEAFILE_GETCS_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_GETCS_PROC, SeafileGetcsProc))
#define SEAFILE_IS_GETCS_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_GETCS_PROC))
#define SEAFILE_GETCS_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_GETCS_PROC, SeafileGetcsProcClass))
#define IS_SEAFILE_GETCS_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_GETCS_PROC))
#define SEAFILE_GETCS_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_GETCS_PROC, SeafileGetcsProcClass))

typedef struct _SeafileGetcsProc SeafileGetcsProc;
typedef struct _SeafileGetcsProcClass SeafileGetcsProcClass;

struct _SeafileGetcsProc {
    CcnetProcessor parent_instance;

    TransferTask *task;
};

struct _SeafileGetcsProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_getcs_proc_get_type ();

#endif

