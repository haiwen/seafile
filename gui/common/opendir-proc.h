/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_OPENDIR_PROC_H
#define CCNET_OPENDIR_PROC_H

#include <glib-object.h>


#define CCNET_TYPE_OPENDIR_PROC                  (ccnet_opendir_proc_get_type ())
#define CCNET_OPENDIR_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), CCNET_TYPE_OPENDIR_PROC, CcnetOpendirProc))
#define CCNET_IS_OPENDIR_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), CCNET_TYPE_OPENDIR_PROC))
#define CCNET_OPENDIR_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), CCNET_TYPE_OPENDIR_PROC, CcnetOpendirProcClass))
#define IS_CCNET_OPENDIR_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), CCNET_TYPE_OPENDIR_PROC))
#define CCNET_OPENDIR_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), CCNET_TYPE_OPENDIR_PROC, CcnetOpendirProcClass))

typedef struct _CcnetOpendirProc CcnetOpendirProc;
typedef struct _CcnetOpendirProcClass CcnetOpendirProcClass;

struct _CcnetOpendirProc {
    CcnetProcessor parent_instance;
};

struct _CcnetOpendirProcClass {
    CcnetProcessorClass parent_class;
};

GType ccnet_opendir_proc_get_type (void);

#endif

