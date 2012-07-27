/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_RECVCOMMIT_PROC_H
#define SEAFILE_RECVCOMMIT_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_RECVCOMMIT_PROC                  (seafile_recvcommit_proc_get_type ())
#define SEAFILE_RECVCOMMIT_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_RECVCOMMIT_PROC, SeafileRecvcommitProc))
#define SEAFILE_IS_RECVCOMMIT_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_RECVCOMMIT_PROC))
#define SEAFILE_RECVCOMMIT_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_RECVCOMMIT_PROC, SeafileRecvcommitProcClass))
#define IS_SEAFILE_RECVCOMMIT_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_RECVCOMMIT_PROC))
#define SEAFILE_RECVCOMMIT_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_RECVCOMMIT_PROC, SeafileRecvcommitProcClass))

typedef struct _SeafileRecvcommitProc SeafileRecvcommitProc;
typedef struct _SeafileRecvcommitProcClass SeafileRecvcommitProcClass;

struct _SeafileRecvcommitProc {
    CcnetProcessor parent_instance;
};

struct _SeafileRecvcommitProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_recvcommit_proc_get_type ();

#endif
