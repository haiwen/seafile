/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SENDCOMMIT_V3_NEW_PROC_H
#define SEAFILE_SENDCOMMIT_V3_NEW_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_SENDCOMMIT_V3_NEW_PROC                  (seafile_sendcommit_v3_new_proc_get_type ())
#define SEAFILE_SENDCOMMIT_V3_NEW_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SENDCOMMIT_V3_NEW_PROC, SeafileSendcommitV3NewProc))
#define SEAFILE_IS_SENDCOMMIT_V3_NEW_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SENDCOMMIT_V3_NEW_PROC))
#define SEAFILE_SENDCOMMIT_V3_NEW_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SENDCOMMIT_V3_NEW_PROC, SeafileSendcommitV3NewProcClass))
#define IS_SEAFILE_SENDCOMMIT_V3_NEW_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SENDCOMMIT_V3_NEW_PROC))
#define SEAFILE_SENDCOMMIT_V3_NEW_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SENDCOMMIT_V3_NEW_PROC, SeafileSendcommitV3NewProcClass))

typedef struct _SeafileSendcommitV3NewProc SeafileSendcommitV3NewProc;
typedef struct _SeafileSendcommitV3NewProcClass SeafileSendcommitV3NewProcClass;

struct _SeafileSendcommitV3NewProc {
    CcnetProcessor parent_instance;

    TransferTask  *tx_task;
};

struct _SeafileSendcommitV3NewProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sendcommit_v3_new_proc_get_type ();

#endif
