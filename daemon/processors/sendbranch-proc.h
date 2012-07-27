/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SENDBRANCH_PROC_H
#define SEAFILE_SENDBRANCH_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#include "transfer-mgr.h"

#define SEAFILE_TYPE_SENDBRANCH_PROC                  (seafile_sendbranch_proc_get_type ())
#define SEAFILE_SENDBRANCH_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SENDBRANCH_PROC, SeafileSendbranchProc))
#define SEAFILE_IS_SENDBRANCH_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SENDBRANCH_PROC))
#define SEAFILE_SENDBRANCH_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SENDBRANCH_PROC, SeafileSendbranchProcClass))
#define IS_SEAFILE_SENDBRANCH_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SENDBRANCH_PROC))
#define SEAFILE_SENDBRANCH_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SENDBRANCH_PROC, SeafileSendbranchProcClass))

typedef struct _SeafileSendbranchProc SeafileSendbranchProc;
typedef struct _SeafileSendbranchProcClass SeafileSendbranchProcClass;

struct _SeafileSendbranchProc {
    CcnetProcessor parent_instance;

    TransferTask *task;
};

struct _SeafileSendbranchProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sendbranch_proc_get_type ();

#endif

