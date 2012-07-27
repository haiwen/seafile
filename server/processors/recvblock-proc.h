/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_RECVBLOCK_PROC_H
#define SEAFILE_RECVBLOCK_PROC_H

#include <glib-object.h>

#define SEAFILE_TYPE_RECVBLOCK_PROC                  (seafile_recvblock_proc_get_type ())
#define SEAFILE_RECVBLOCK_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_RECVBLOCK_PROC, SeafileRecvblockProc))
#define SEAFILE_IS_RECVBLOCK_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_RECVBLOCK_PROC))
#define SEAFILE_RECVBLOCK_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_RECVBLOCK_PROC, SeafileRecvblockProcClass))
#define IS_SEAFILE_RECVBLOCK_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_RECVBLOCK_PROC))
#define SEAFILE_RECVBLOCK_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_RECVBLOCK_PROC, SeafileRecvblockProcClass))

typedef struct _SeafileRecvblockProc SeafileRecvblockProc;
typedef struct _SeafileRecvblockProcClass SeafileRecvblockProcClass;

struct _SeafileRecvblockProc {
    CcnetProcessor parent_instance;
};

struct _SeafileRecvblockProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_recvblock_proc_get_type ();

#endif
