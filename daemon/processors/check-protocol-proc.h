/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_CHECK_PROTOCOL_PROC_H
#define SEAFILE_CHECK_PROTOCOL_PROC_H

#include <glib-object.h>
#include <ccnet.h>

#define SEAFILE_TYPE_CHECK_PROTOCOL_PROC                  (seafile_check_protocol_proc_get_type ())
#define SEAFILE_CHECK_PROTOCOL_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_CHECK_PROTOCOL_PROC, SeafileCheckProtocolProc))
#define SEAFILE_IS_CHECK_PROTOCOL_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_CHECK_PROTOCOL_PROC))
#define SEAFILE_CHECK_PROTOCOL_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_CHECK_PROTOCOL_PROC, SeafileCheckProtocolProcClass))
#define IS_SEAFILE_CHECK_PROTOCOL_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_CHECK_PROTOCOL_PROC))
#define SEAFILE_CHECK_PROTOCOL_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_CHECK_PROTOCOL_PROC, SeafileCheckProtocolProcClass))

typedef struct _SeafileCheckProtocolProc SeafileCheckProtocolProc;
typedef struct _SeafileCheckProtocolProcClass SeafileCheckProtocolProcClass;

struct _SeafileCheckProtocolProc {
    CcnetProcessor parent_instance;

    int protocol_version;
};

struct _SeafileCheckProtocolProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_check_protocol_proc_get_type ();

#endif
