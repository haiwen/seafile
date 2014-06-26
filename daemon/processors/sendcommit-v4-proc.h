/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SENDCOMMIT_V4_PROC_H
#define SEAFILE_SENDCOMMIT_V4_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_SENDCOMMIT_V4_PROC                  (seafile_sendcommit_v4_proc_get_type ())
#define SEAFILE_SENDCOMMIT_V4_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SENDCOMMIT_V4_PROC, SeafileSendcommitV4Proc))
#define SEAFILE_IS_SENDCOMMIT_V4_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SENDCOMMIT_V4_PROC))
#define SEAFILE_SENDCOMMIT_V4_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SENDCOMMIT_V4_PROC, SeafileSendcommitV4ProcClass))
#define IS_SEAFILE_SENDCOMMIT_V4_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SENDCOMMIT_V4_PROC))
#define SEAFILE_SENDCOMMIT_V4_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SENDCOMMIT_V4_PROC, SeafileSendcommitV4ProcClass))

typedef struct _SeafileSendcommitV4Proc SeafileSendcommitV4Proc;
typedef struct _SeafileSendcommitV4ProcClass SeafileSendcommitV4ProcClass;

struct _SeafileSendcommitV4Proc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
};

struct _SeafileSendcommitV4ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sendcommit_v4_proc_get_type ();

#endif
