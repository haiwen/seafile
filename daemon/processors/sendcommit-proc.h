/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SENDCOMMIT_PROC_H
#define SEAFILE_SENDCOMMIT_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_SENDCOMMIT_PROC                  (seafile_sendcommit_proc_get_type ())
#define SEAFILE_SENDCOMMIT_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SENDCOMMIT_PROC, SeafileSendcommitProc))
#define SEAFILE_IS_SENDCOMMIT_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SENDCOMMIT_PROC))
#define SEAFILE_SENDCOMMIT_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SENDCOMMIT_PROC, SeafileSendcommitProcClass))
#define IS_SEAFILE_SENDCOMMIT_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SENDCOMMIT_PROC))
#define SEAFILE_SENDCOMMIT_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SENDCOMMIT_PROC, SeafileSendcommitProcClass))

typedef struct _SeafileSendcommitProc SeafileSendcommitProc;
typedef struct _SeafileSendcommitProcClass SeafileSendcommitProcClass;

struct _SeafileSendcommitProc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
};

struct _SeafileSendcommitProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sendcommit_proc_get_type ();

#endif
