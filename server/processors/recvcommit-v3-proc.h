/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_RECVCOMMIT_V3_PROC_H
#define SEAFILE_RECVCOMMIT_V3_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_RECVCOMMIT_V3_PROC                  (seafile_recvcommit_v3_proc_get_type ())
#define SEAFILE_RECVCOMMIT_V3_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_RECVCOMMIT_V3_PROC, SeafileRecvcommitV3Proc))
#define SEAFILE_IS_RECVCOMMIT_V3_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_RECVCOMMIT_V3_PROC))
#define SEAFILE_RECVCOMMIT_V3_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_RECVCOMMIT_V3_PROC, SeafileRecvcommitV3ProcClass))
#define IS_SEAFILE_RECVCOMMIT_V3_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_RECVCOMMIT_V3_PROC))
#define SEAFILE_RECVCOMMIT_V3_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_RECVCOMMIT_V3_PROC, SeafileRecvcommitV3ProcClass))

typedef struct _SeafileRecvcommitV3Proc SeafileRecvcommitV3Proc;
typedef struct _SeafileRecvcommitV3ProcClass SeafileRecvcommitV3ProcClass;

struct _SeafileRecvcommitV3Proc {
    CcnetProcessor parent_instance;
};

struct _SeafileRecvcommitV3ProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_recvcommit_v3_proc_get_type ();

#endif
