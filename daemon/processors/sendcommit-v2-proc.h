/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SENDCOMMIT_V2_PROC_H
#define SEAFILE_SENDCOMMIT_V2_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_SENDCOMMIT_V2_PROC                  (seafile_sendcommit_v2_proc_get_type ())
#define SEAFILE_SENDCOMMIT_V2_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SENDCOMMIT_V2_PROC, SeafileSendcommitV2Proc))
#define SEAFILE_IS_SENDCOMMIT_V2_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SENDCOMMIT_V2_PROC))
#define SEAFILE_SENDCOMMIT_V2_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SENDCOMMIT_V2_PROC, SeafileSendcommitV2ProcClass))
#define IS_SEAFILE_SENDCOMMIT_V2_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SENDCOMMIT_V2_PROC))
#define SEAFILE_SENDCOMMIT_V2_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SENDCOMMIT_V2_PROC, SeafileSendcommitV2ProcClass))

typedef struct _SeafileSendcommitV2Proc SeafileSendcommitV2Proc;
typedef struct _SeafileSendcommitV2ProcClass SeafileSendcommitV2ProcClass;

struct _SeafileSendcommitV2Proc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
};

struct _SeafileSendcommitV2ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sendcommit_v2_proc_get_type ();

#endif
