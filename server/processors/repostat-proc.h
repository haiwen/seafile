/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_REPOSTAT_PROC_H
#define SEAFILE_REPOSTAT_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#define SEAFILE_TYPE_REPOSTAT_PROC                  (seafile_repostat_proc_get_type ())
#define SEAFILE_REPOSTAT_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_REPOSTAT_PROC, SeafileRepostatProc))
#define SEAFILE_IS_REPOSTAT_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_REPOSTAT_PROC))
#define SEAFILE_REPOSTAT_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_REPOSTAT_PROC, SeafileRepostatProcClass))
#define IS_SEAFILE_REPOSTAT_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_REPOSTAT_PROC))
#define SEAFILE_REPOSTAT_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_REPOSTAT_PROC, SeafileRepostatProcClass))

typedef struct _SeafileRepostatProc SeafileRepostatProc;
typedef struct _SeafileRepostatProcClass SeafileRepostatProcClass;

struct _SeafileRepostatProc {
    CcnetProcessor parent_instance;

    char repo_id[41];
};

struct _SeafileRepostatProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_repostat_proc_get_type ();

#endif

