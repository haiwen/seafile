/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdint.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <ccnet.h>
#include <ccnet/cevent.h>
#include <ccnet/ccnet-object.h>
#include <utils.h>

#include "seafile-session.h"
#include "seafile-config.h"
#include "vc-utils.h"
#include "seaf-utils.h"
#include "gc.h"
#include "log.h"
#include "seaf-ext.h"

enum {
	REPO_COMMITTED,
    REPO_FETCHED,
    REPO_UPLOADED,
    REPO_WORKTREE_CHECKED,
	LAST_SIGNAL
};

int signals[LAST_SIGNAL];

G_DEFINE_TYPE (SeafileSession, seafile_session, G_TYPE_OBJECT);


static void
seafile_session_class_init (SeafileSessionClass *klass)
{

    signals[REPO_COMMITTED] =
        g_signal_new ("repo-committed", SEAFILE_TYPE_SESSION,
                      G_SIGNAL_RUN_LAST,
                      0,        /* no class singal handler */
                      NULL, NULL, /* no accumulator */
                      g_cclosure_marshal_VOID__POINTER,
                      G_TYPE_NONE, 1, G_TYPE_POINTER);

    signals[REPO_FETCHED] =
        g_signal_new ("repo-fetched", SEAFILE_TYPE_SESSION,
                      G_SIGNAL_RUN_LAST,
                      0,        /* no class singal handler */
                      NULL, NULL, /* no accumulator */
                      g_cclosure_marshal_VOID__POINTER,
                      G_TYPE_NONE, 1, G_TYPE_POINTER);

    signals[REPO_UPLOADED] =
        g_signal_new ("repo-uploaded", SEAFILE_TYPE_SESSION,
                      G_SIGNAL_RUN_LAST,
                      0,        /* no class singal handler */
                      NULL, NULL, /* no accumulator */
                      g_cclosure_marshal_VOID__POINTER,
                      G_TYPE_NONE, 1, G_TYPE_POINTER);

}


SeafileSession *
seafile_session_new(const char *seafile_dir,
                    const char *worktree_dir,
                    struct _CcnetClient *ccnet_session)
{
    char *abs_seafile_dir;
    char *abs_worktree_dir;
    char *tmp_file_dir;
    char *db_path;
    sqlite3 *config_db;
    SeafileSession *session = NULL;

#ifndef SEAF_TOOL
    if (!ccnet_session)
        return NULL;
#endif    

    abs_worktree_dir = ccnet_expand_path (worktree_dir);
    abs_seafile_dir = ccnet_expand_path (seafile_dir);
    tmp_file_dir = g_build_filename (abs_seafile_dir, "tmpfiles", NULL);
    db_path = g_build_filename (abs_seafile_dir, "config.db", NULL);

    if (checkdir_with_mkdir (abs_seafile_dir) < 0) {
        g_warning ("Config dir %s does not exist and is unable to create\n",
                   abs_seafile_dir);
        goto onerror;
    }

    if (checkdir_with_mkdir (abs_worktree_dir) < 0) {
        g_warning ("Worktree %s does not exist and is unable to create\n",
                   abs_worktree_dir);
        goto onerror;
    }

    if (checkdir_with_mkdir (tmp_file_dir) < 0) {
        g_warning ("Temp file dir %s does not exist and is unable to create\n",
                   tmp_file_dir);
        goto onerror;
    }

    config_db = seafile_session_config_open_db (db_path);
    if (!config_db) {
        g_warning ("Failed to open config db.\n");
        goto onerror;
    }

    session = g_object_new (SEAFILE_TYPE_SESSION, NULL);
    session->seaf_dir = abs_seafile_dir;
    session->tmp_file_dir = tmp_file_dir;
    session->worktree_dir = abs_worktree_dir;
    session->session = ccnet_session;
    session->config_db = config_db;

    session->fs_mgr = seaf_fs_manager_new (session, abs_seafile_dir);
    if (!session->fs_mgr)
        goto onerror;
    session->block_mgr = seaf_block_manager_new (session, abs_seafile_dir);
    if (!session->block_mgr)
        goto onerror;
    session->commit_mgr = seaf_commit_manager_new (session);
    if (!session->commit_mgr)
        goto onerror;
    session->repo_mgr = seaf_repo_manager_new (session);
    if (!session->repo_mgr)
        goto onerror;
    session->branch_mgr = seaf_branch_manager_new (session);
    if (!session->branch_mgr)
        goto onerror;

    session->transfer_mgr = seaf_transfer_manager_new (session);
    if (!session->transfer_mgr)
        goto onerror;
    session->clone_mgr = seaf_clone_manager_new (session);
    if (!session->clone_mgr)
        goto onerror;
#ifndef SEAF_TOOL    
    session->sync_mgr = seaf_sync_manager_new (session);
    if (!session->sync_mgr)
        goto onerror;
    session->wt_monitor = seaf_wt_monitor_new (session);
    if (!session->wt_monitor)
        goto onerror;

    session->job_mgr = ccnet_job_manager_new ();
    session->ev_mgr = cevent_manager_new ();
    if (!session->ev_mgr)
        goto onerror;
    
    session->mq_mgr = seaf_mq_manager_new (session);
    if (!session->mq_mgr)
        goto onerror;
#endif    

    return session;

onerror:
    free (abs_seafile_dir);
    free (abs_worktree_dir);
    g_free (tmp_file_dir);
    g_free (db_path);
    g_free (session);
    return NULL;    
}


static void
seafile_session_init (SeafileSession *session)
{
}

void
seafile_session_prepare (SeafileSession *session)
{
    /* Start mq manager earlier, so that we can send notifications
     * when start repo manager. */
    seaf_mq_manager_init (session->mq_mgr);
    seaf_commit_manager_init (session->commit_mgr);
    seaf_fs_manager_init (session->fs_mgr);
    seaf_branch_manager_init (session->branch_mgr);
    seaf_repo_manager_init (session->repo_mgr);
    seaf_clone_manager_init (session->clone_mgr);
#ifndef SEAF_TOOL    
    seaf_sync_manager_init (session->sync_mgr);
#endif
    seaf_mq_manager_set_heartbeat_name (session->mq_mgr,
                                        "seafile.heartbeat");
}


void
seafile_session_start (SeafileSession *session)
{
    if (cevent_manager_start (session->ev_mgr) < 0) {
        g_error ("Failed to start event manager.\n");
        return;
    }

    if (seaf_transfer_manager_start (session->transfer_mgr) < 0) {
        g_error ("Failed to start transfer manager.\n");
        return;
    }

    if (seaf_sync_manager_start (session->sync_mgr) < 0) {
        g_error ("Failed to start sync manager.\n");
        return;
    }

    if (seaf_wt_monitor_start (session->wt_monitor) < 0) {
        g_error ("Failed to start worktree monitor.\n");
        return;
    }

    if (seaf_mq_manager_start (session->mq_mgr) < 0) {
        g_error ("Failed to start mq manager.\n");
        return;
    }

    /* Must be after wt monitor, since we may add watch to repo worktree. */
    if (seaf_repo_manager_start (session->repo_mgr) < 0) {
        g_error ("Failed to start repo manager.\n");
        return;
    }

    if (seaf_clone_manager_start (session->clone_mgr) < 0) {
        g_error ("Failed to start clone manager.\n");
        return;
    }

    if (seaf_extension_pipe_start (session) < 0) {
        g_error ("Failed to start extension pipe\n");
        return;
    }

    /* Clean up unused blocks on restart.
     * This would set a flag to tell other threads and download tasks
     * to wait until GC completes.
     */
    if (gc_start () < 0) {
        g_warning ("Failed to start gc.\n");
    }
}

#if 0
void
seafile_session_add_event (SeafileSession *session, 
                           const char *type,
                           const char *first, ...)
{
    gchar *body;
    va_list args;

    va_start (args, first);
    body = key_value_list_to_json_v (first, args);
    va_end (args);

    CcnetEvent *event = g_object_new (CCNET_TYPE_EVENT, 
                                      "etype", type, 
                                      "body", body, NULL);
    ccnet_client_send_event(session->session, (GObject *)event);
    g_object_unref (event);

    g_free (body);
}
#endif

