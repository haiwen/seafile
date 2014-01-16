/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_GETCA_PROC_H
#define SEAFILE_GETCA_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_GETCA_PROC                  (seafile_getca_proc_get_type ())
#define SEAFILE_GETCA_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_GETCA_PROC, SeafileGetcaProc))
#define SEAFILE_IS_GETCA_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_GETCA_PROC))
#define SEAFILE_GETCA_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_GETCA_PROC, SeafileGetcaProcClass))
#define IS_SEAFILE_GETCA_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_GETCA_PROC))
#define SEAFILE_GETCA_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_GETCA_PROC, SeafileGetcaProcClass))

typedef struct _SeafileGetcaProc SeafileGetcaProc;
typedef struct _SeafileGetcaProcClass SeafileGetcaProcClass;

/* Error code used in processor->failure */
#define GETCA_PROC_ACCESS_DENIED 401
#define GETCA_PROC_NO_CA 404

struct _SeafileGetcaProc {
    CcnetProcessor parent_instance;

    char ca_id[41];
};

struct _SeafileGetcaProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_getca_proc_get_type ();

#endif
