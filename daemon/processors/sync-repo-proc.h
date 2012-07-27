/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SYNC_REPO_PROC_H
#define SEAFILE_SYNC_REPO_PROC_H

#include <glib-object.h>
#include <ccnet.h>

#define SEAFILE_TYPE_SYNC_REPO_PROC                  (seafile_sync_repo_proc_get_type ())
#define SEAFILE_SYNC_REPO_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SYNC_REPO_PROC, SeafileSyncRepoProc))
#define SEAFILE_IS_SYNC_REPO_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SYNC_REPO_PROC))
#define SEAFILE_SYNC_REPO_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SYNC_REPO_PROC, SeafileSyncRepoProcClass))
#define IS_SEAFILE_SYNC_REPO_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SYNC_REPO_PROC))
#define SEAFILE_SYNC_REPO_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SYNC_REPO_PROC, SeafileSyncRepoProcClass))

typedef struct _SeafileSyncRepoProc SeafileSyncRepoProc;
typedef struct _SeafileSyncRepoProcClass SeafileSyncRepoProcClass;

struct _SyncTask;

struct _SeafileSyncRepoProc {
    CcnetProcessor parent_instance;

    struct _SyncTask *task;
};

struct _SeafileSyncRepoProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sync_repo_proc_get_type ();

void
seafile_sync_repo_proc_set_repo (SeafileSyncRepoProc *processor,
                                 char *repo_id);

#endif
