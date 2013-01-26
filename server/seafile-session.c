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

#include <ccnet/cevent.h>
#include <utils.h>

#include "seafile-session.h"
#include "seafile-config.h"

#include "monitor-rpc-wrappers.h"

#include "seaf-db.h"
#include "seaf-utils.h"

#define CONNECT_INTERVAL_MSEC 10 * 1000

static void
load_monitor_id (SeafileSession *session);

SeafileSession *
seafile_session_new(const char *seafile_dir,
                    CcnetClient *ccnet_session)
{
    char *abs_seafile_dir;
    char *tmp_file_dir;
    char *config_file_path;
    char *db_path;
    sqlite3 *config_db;
    GKeyFile *config;
    SeafileSession *session = NULL;

    if (!ccnet_session)
        return NULL;

    abs_seafile_dir = ccnet_expand_path (seafile_dir);
    tmp_file_dir = g_build_filename (abs_seafile_dir, "tmpfiles", NULL);
    config_file_path = g_build_filename (abs_seafile_dir, "seafile.conf", NULL);
    db_path = g_build_filename (abs_seafile_dir, "config.db", NULL);

    if (checkdir_with_mkdir (abs_seafile_dir) < 0) {
        g_warning ("Config dir %s does not exist and is unable to create\n",
                   abs_seafile_dir);
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

    GError *error = NULL;
    config = g_key_file_new ();
    if (!g_key_file_load_from_file (config, config_file_path, 
                                    G_KEY_FILE_NONE, &error)) {
        g_warning ("Failed to load config file.\n");
        g_key_file_free (config);
        goto onerror;
    }

    session = g_new0(SeafileSession, 1);
    session->seaf_dir = abs_seafile_dir;
    session->tmp_file_dir = tmp_file_dir;
    session->session = ccnet_session;
    session->config_db = config_db;
    session->config = config;

    load_monitor_id (session);

    if (load_database_config (session) < 0) {
        g_warning ("Failed to load database config.\n");
        goto onerror;
    }

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

    session->cs_mgr = seaf_cs_manager_new (session);
    if (!session->cs_mgr)
        goto onerror;

    session->share_mgr = seaf_share_manager_new (session);
    if (!session->share_mgr)
        goto onerror;
    
    session->web_at_mgr = seaf_web_at_manager_new (session);
    if (!session->web_at_mgr)
        goto onerror;

    session->token_mgr = seaf_token_manager_new (session);
    if (!session->token_mgr)
        goto onerror;

    session->passwd_mgr = seaf_passwd_manager_new (session);
    if (!session->passwd_mgr)
        goto onerror;

    session->quota_mgr = seaf_quota_manager_new (session);
    if (!session->quota_mgr)
        goto onerror;

    session->listen_mgr = seaf_listen_manager_new (session);
    if (!session->listen_mgr)
        goto onerror;

    session->job_mgr = ccnet_job_manager_new ();
    session->ev_mgr = cevent_manager_new ();
    if (!session->ev_mgr)
        goto onerror;

    session->mq_mgr = seaf_mq_manager_new (session);
    if (!session->mq_mgr)
        goto onerror;

    return session;

onerror:
    free (abs_seafile_dir);
    g_free (tmp_file_dir);
    g_free (config_file_path);
    g_free (db_path);
    g_free (session);
    return NULL;    
}

int
seafile_session_init (SeafileSession *session)
{
    if (seaf_commit_manager_init (session->commit_mgr) < 0)
        return -1;

    if (seaf_fs_manager_init (session->fs_mgr) < 0)
        return -1;

    if (seaf_branch_manager_init (session->branch_mgr) < 0)
        return -1;

    if (seaf_repo_manager_init (session->repo_mgr) < 0)
        return -1;

    if (seaf_quota_manager_init (session->quota_mgr) < 0)
        return -1;

    seaf_mq_manager_init (session->mq_mgr);
    seaf_mq_manager_set_heartbeat_name (session->mq_mgr,
                                        "seaf_server.heartbeat");

    return 0;
}

int
seafile_session_start (SeafileSession *session)
{
    if (cevent_manager_start (session->ev_mgr) < 0) {
        g_error ("Failed to start event manager.\n");
        return -1;
    }

    if (seaf_cs_manager_start (session->cs_mgr) < 0) {
        g_error ("Failed to start chunk server manager.\n");
        return -1;
    }

    if (seaf_share_manager_start (session->share_mgr) < 0) {
        g_error ("Failed to start share manager.\n");
        return -1;
    }

    if (seaf_web_at_manager_start (session->web_at_mgr) < 0) {
        g_error ("Failed to start web access check manager.\n");
        return -1;
    }

    if (seaf_passwd_manager_start (session->passwd_mgr) < 0) {
        g_error ("Failed to start password manager.\n");
        return -1;
    }

    if (seaf_mq_manager_start (session->mq_mgr) < 0) {
        g_error ("Failed to start mq manager.\n");
        return -1;
    }

    if (seaf_listen_manager_start (session->listen_mgr) < 0) {
        g_error ("Failed to start listen manager.\n");
        return -1;
    }

    return 0;
}

int
seafile_session_set_monitor (SeafileSession *session, const char *peer_id)
{
    if (seafile_session_config_set_string (session, 
                                           KEY_MONITOR_ID,
                                           peer_id) < 0) {
        g_warning ("Failed to set monitor id.\n");
        return -1;
    }

    session->monitor_id = g_strdup(peer_id);
    return 0;
}

static void
load_monitor_id (SeafileSession *session)
{
    char *monitor_id;

    monitor_id = seafile_session_config_get_string (session, 
                                                    KEY_MONITOR_ID);

    if (monitor_id) {
        session->monitor_id = monitor_id;
    } else {
        /* Set monitor to myself if not set by user. */
        session->monitor_id = g_strdup(session->session->base.id);
    }
}

static gboolean
get_total_size (SeafDBRow *row, void *vpsize)
{
    gint64 *psize = vpsize;

    *psize += seaf_db_row_get_column_int64 (row, 0);

    return TRUE;
}

gint64
get_user_quota_usage (SeafileSession *seaf, const char *email)
{
    char sql[256];
    gint64 ret = 0;

    snprintf (sql, sizeof(sql), 
              "SELECT size FROM RepoOwner, RepoSize WHERE "
              "owner_id='%s' AND RepoOwner.repo_id=RepoSize.repo_id",
              email);
    if (seaf_db_foreach_selected_row (seaf->db, sql,
                                      get_total_size, &ret) < 0)
        return -1;

    return ret;
}

gint64
get_org_quota_usage (SeafileSession *seaf, int org_id)
{
    char sql[256];
    gint64 ret = 0;

    snprintf (sql, sizeof(sql), 
              "SELECT size FROM OrgRepo, RepoSize WHERE "
              "org_id=%d AND OrgRepo.repo_id=RepoSize.repo_id",
              org_id);
    if (seaf_db_foreach_selected_row (seaf->db, sql,
                                      get_total_size, &ret) < 0)
        return -1;

    return ret;
}

gint64
get_org_user_quota_usage (SeafileSession *seaf,
                          int org_id,
                          const char *user)
{
    char sql[256];
    gint64 ret = 0;

    snprintf (sql, sizeof(sql), 
              "SELECT size FROM OrgRepo, RepoSize WHERE "
              "org_id=%d AND user = '%s' AND OrgRepo.repo_id=RepoSize.repo_id",
              org_id, user);
    if (seaf_db_foreach_selected_row (seaf->db, sql,
                                      get_total_size, &ret) < 0)
        return -1;

    return ret;
}
