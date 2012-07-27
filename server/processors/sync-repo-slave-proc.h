/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_SYNC_REPO_SLAVE_PROC_H
#define SEAFILE_SYNC_REPO_SLAVE_PROC_H

#include <glib-object.h>
#include <ccnet.h>

#define SEAFILE_TYPE_SYNC_REPO_SLAVE_PROC                  (seafile_sync_repo_slave_proc_get_type ())
#define SEAFILE_SYNC_REPO_SLAVE_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_SYNC_REPO_SLAVE_PROC, SeafileSynRepoSlaveProc))
#define SEAFILE_IS_SYNC_REPO_SLAVE_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_SYNC_REPO_SLAVE_PROC))
#define SEAFILE_SYNC_REPO_SLAVE_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_SYNC_REPO_SLAVE_PROC, SeafileSynRepoSlaveProcClass))
#define IS_SEAFILE_SYNC_REPO_SLAVE_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_SYNC_REPO_SLAVE_PROC))
#define SEAFILE_SYNC_REPO_SLAVE_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_SYNC_REPO_SLAVE_PROC, SeafileSynRepoSlaveProcClass))

typedef struct _SeafileSynRepoSlaveProc SeafileSynRepoSlaveProc;
typedef struct _SeafileSynRepoSlaveProcClass SeafileSynRepoSlaveProcClass;

struct _SeafileSynRepoSlaveProc {
    CcnetProcessor parent_instance;
};

struct _SeafileSynRepoSlaveProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_sync_repo_slave_proc_get_type ();

#endif
