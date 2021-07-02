/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdint.h>
#ifndef WIN32
#include <dirent.h>
#include <unistd.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#include <event2/event_compat.h>
#include <event2/event_struct.h>
#else
#include <event.h>
#endif

#include <glib.h>

#include "utils.h"

#include "seafile-session.h"
#include "seafile-config.h"
#include "vc-utils.h"
#include "log.h"

#define MAX_THREADS 50

enum {
	REPO_COMMITTED,
    REPO_FETCHED,
    REPO_UPLOADED,
    REPO_HTTP_FETCHED,
    REPO_HTTP_UPLOADED,
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
    signals[REPO_HTTP_FETCHED] =
        g_signal_new ("repo-http-fetched", SEAFILE_TYPE_SESSION,
                      G_SIGNAL_RUN_LAST,
                      0,        /* no class singal handler */
                      NULL, NULL, /* no accumulator */
                      g_cclosure_marshal_VOID__POINTER,
                      G_TYPE_NONE, 1, G_TYPE_POINTER);

    signals[REPO_HTTP_UPLOADED] =
        g_signal_new ("repo-http-uploaded", SEAFILE_TYPE_SESSION,
                      G_SIGNAL_RUN_LAST,
                      0,        /* no class singal handler */
                      NULL, NULL, /* no accumulator */
                      g_cclosure_marshal_VOID__POINTER,
                      G_TYPE_NONE, 1, G_TYPE_POINTER);
}

static int
create_deleted_store_dirs (const char *deleted_store)
{
    char *commits = NULL, *fs = NULL, *blocks = NULL;
    int ret = 0;

    if (checkdir_with_mkdir (deleted_store) < 0) {
        seaf_warning ("Directory %s does not exist and is unable to create\n",
                      deleted_store);
        return -1;
    }

    commits = g_build_filename (deleted_store, "commits", NULL);
    if (checkdir_with_mkdir (commits) < 0) {
        seaf_warning ("Directory %s does not exist and is unable to create\n",
                      commits);
        ret = -1;
        goto out;
    }

    fs = g_build_filename (deleted_store, "fs", NULL);
    if (checkdir_with_mkdir (fs) < 0) {
        seaf_warning ("Directory %s does not exist and is unable to create\n",
                      fs);
        ret = -1;
        goto out;
    }

    blocks = g_build_filename (deleted_store, "blocks", NULL);
    if (checkdir_with_mkdir (blocks) < 0) {
        seaf_warning ("Directory %s does not exist and is unable to create\n",
                      blocks);
        ret = -1;
        goto out;
    }

out:
    g_free (commits);
    g_free (fs);
    g_free (blocks);
    return ret;
}

SeafileSession *
seafile_session_new(const char *seafile_dir,
                    const char *worktree_dir,
                    const char *ccnet_dir)
{
    char *abs_seafile_dir;
    char *abs_worktree_dir;
    char *abs_ccnet_dir;
    char *tmp_file_dir;
    char *db_path;
    char *deleted_store;
    sqlite3 *config_db;
    SeafileSession *session = NULL;

    abs_worktree_dir = ccnet_expand_path (worktree_dir);
    abs_seafile_dir = ccnet_expand_path (seafile_dir);
    abs_ccnet_dir = ccnet_expand_path (ccnet_dir);
    tmp_file_dir = g_build_filename (abs_seafile_dir, "tmpfiles", NULL);
    db_path = g_build_filename (abs_seafile_dir, "config.db", NULL);
    deleted_store = g_build_filename (abs_seafile_dir, "deleted_store", NULL);

    if (checkdir_with_mkdir (abs_seafile_dir) < 0) {
        seaf_warning ("Config dir %s does not exist and is unable to create\n",
                      abs_seafile_dir);
        goto onerror;
    }

    if (checkdir_with_mkdir (abs_worktree_dir) < 0) {
        seaf_warning ("Worktree %s does not exist and is unable to create\n",
                      abs_worktree_dir);
        goto onerror;
    }

    if (checkdir_with_mkdir (tmp_file_dir) < 0) {
        seaf_warning ("Temp file dir %s does not exist and is unable to create\n",
                      tmp_file_dir);
        goto onerror;
    }

    if (create_deleted_store_dirs (deleted_store) < 0)
        goto onerror;

    config_db = seafile_session_config_open_db (db_path);
    if (!config_db) {
        seaf_warning ("Failed to open config db.\n");
        goto onerror;
    }

    session = g_object_new (SEAFILE_TYPE_SESSION, NULL);
    session->ev_base = event_base_new ();
    session->seaf_dir = abs_seafile_dir;
    session->tmp_file_dir = tmp_file_dir;
    session->worktree_dir = abs_worktree_dir;
    session->ccnet_dir = abs_ccnet_dir;
    session->config_db = config_db;
    session->deleted_store = deleted_store;

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

    session->clone_mgr = seaf_clone_manager_new (session);
    if (!session->clone_mgr)
        goto onerror;
    session->sync_mgr = seaf_sync_manager_new (session);
    if (!session->sync_mgr)
        goto onerror;
    session->wt_monitor = seaf_wt_monitor_new (session);
    if (!session->wt_monitor)
        goto onerror;
    session->http_tx_mgr = http_tx_manager_new (session);
    if (!session->http_tx_mgr)
        goto onerror;

    session->filelock_mgr = seaf_filelock_manager_new (session);
    if (!session->filelock_mgr)
        goto onerror;

    session->job_mgr = seaf_job_manager_new (session, MAX_THREADS);
    session->ev_mgr = cevent_manager_new ();
    if (!session->ev_mgr)
        goto onerror;
    
    session->mq_mgr = seaf_mq_manager_new ();
    if (!session->mq_mgr)
        goto onerror;

    return session;

onerror:
    free (abs_seafile_dir);
    free (abs_worktree_dir);
    free (abs_ccnet_dir);
    g_free (tmp_file_dir);
    g_free (db_path);
    g_free (deleted_store);
    g_free (session);
    return NULL;    
}


static void
seafile_session_init (SeafileSession *session)
{
}

static void
load_system_proxy (SeafileSession *session)
{
    char *system_proxy_txt = g_build_filename (seaf->seaf_dir, "system-proxy.txt", NULL);
    json_t *json = NULL;
    if (!g_file_test (system_proxy_txt, G_FILE_TEST_EXISTS)) {
        seaf_warning ("Can't load system proxy: file %s doesn't exist\n", system_proxy_txt);
        goto out;
    }

    json_error_t jerror;
    json = json_load_file(system_proxy_txt, 0, &jerror);
    if (!json) {
        if (strlen(jerror.text) > 0)
            seaf_warning ("Failed to load system proxy information: %s.\n", jerror.text);
        else
            seaf_warning ("Failed to load system proxy information\n");
        goto out;
    }
    const char *type;
    type = json_object_get_string_member (json, "type");
    if (!type) {
        seaf_warning ("Failed to load system proxy information: proxy type missing\n");
        goto out;
    }
    if (strcmp(type, "none") != 0 && strcmp(type, "socks") != 0 && strcmp(type, "http") != 0) {
        seaf_warning ("Failed to load system proxy information: invalid proxy type %s\n", type);
        goto out;
    }
    if (g_strcmp0(type, "none") == 0) {
        goto out;
    }
    session->http_proxy_type = g_strdup(type);
    session->http_proxy_addr = g_strdup(json_object_get_string_member (json, "addr"));
    session->http_proxy_port = json_object_get_int_member (json, "port");
    session->http_proxy_username = g_strdup(json_object_get_string_member (json, "username"));
    session->http_proxy_password = g_strdup(json_object_get_string_member (json, "password"));

out:
    g_free (system_proxy_txt);
    if (json)
        json_decref(json);
}

static char *
generate_client_id ()
{
    char *uuid = gen_uuid();
    unsigned char buf[20];
    char sha1[41];

    calculate_sha1 (buf, uuid, 20);
    rawdata_to_hex (buf, sha1, 20);

    g_free (uuid);
    return g_strdup(sha1);
}

static void
read_ccnet_conf (const char *ccnet_dir, char **client_id, char **client_name)
{
    char *ccnet_conf_path = g_build_path ("/", ccnet_dir, "ccnet.conf", NULL);
    GKeyFile *key_file = g_key_file_new ();
    GError *error = NULL;

    if (!g_file_test (ccnet_conf_path, G_FILE_TEST_IS_REGULAR))
        goto out;

    if (!g_key_file_load_from_file (key_file, ccnet_conf_path, 0, &error)) {
        seaf_warning ("Failed to read ccnet.conf: %s.\n", error->message);
        g_clear_error (&error);
        goto out;
    }

    *client_id = g_key_file_get_string (key_file, "General", "ID", &error);
    if (error) {
        seaf_warning ("Failed to read client id from ccnet.conf: %s.\n", error->message);
        g_clear_error (&error);
        goto out;
    }

    *client_name = g_key_file_get_string (key_file, "General", "NAME", &error);
    if (error) {
        seaf_warning ("Failed to read client name from ccnet.conf: %s.\n", error->message);
        g_clear_error (&error);
        goto out;
    }

out:
    g_free (ccnet_conf_path);
    g_key_file_free (key_file);
}

void
seafile_session_prepare (SeafileSession *session)
{
    char *client_id = NULL, *client_name = NULL;

    /* load config */

    read_ccnet_conf (session->ccnet_dir, &client_id, &client_name);

    session->client_id = seafile_session_config_get_string (session, KEY_CLIENT_ID);
    if (!session->client_id) {
        if (client_id) {
            session->client_id = g_strdup (client_id);
        } else {
            session->client_id = generate_client_id();
        }
        seafile_session_config_set_string (session,
                                           KEY_CLIENT_ID,
                                           session->client_id);
    }

    session->client_name = seafile_session_config_get_string (session, KEY_CLIENT_NAME);
    if (!session->client_name) {
        if (client_name) {
            session->client_name = g_strdup (client_name);
            seafile_session_config_set_string (session,
                                               KEY_CLIENT_NAME,
                                               session->client_name);
        } else {
            session->client_name = g_strdup("unknown");
        }
    }

    seaf_warning ("client id = %s, client_name = %s\n", session->client_id, session->client_name);
    g_free (client_id);
    g_free (client_name);

    session->sync_extra_temp_file = seafile_session_config_get_bool
        (session, KEY_SYNC_EXTRA_TEMP_FILE);

    /* Enable http sync by default. */
    session->enable_http_sync = TRUE;

    session->disable_verify_certificate = seafile_session_config_get_bool
        (session, KEY_DISABLE_VERIFY_CERTIFICATE);

    session->use_http_proxy =
        seafile_session_config_get_bool(session, KEY_USE_PROXY);

    gboolean use_system_proxy =
        seafile_session_config_get_bool(session, "use_system_proxy");

    if (use_system_proxy) {
        load_system_proxy(session);
    } else {
        session->http_proxy_type =
            seafile_session_config_get_string(session, KEY_PROXY_TYPE);
        session->http_proxy_addr =
            seafile_session_config_get_string(session, KEY_PROXY_ADDR);
        session->http_proxy_port =
            seafile_session_config_get_int(session, KEY_PROXY_PORT, NULL);
        session->http_proxy_username =
            seafile_session_config_get_string(session, KEY_PROXY_USERNAME);
        session->http_proxy_password =
            seafile_session_config_get_string(session, KEY_PROXY_PASSWORD);
    }

    int block_size = seafile_session_config_get_int(session, KEY_CDC_AVERAGE_BLOCK_SIZE, NULL);
    if (block_size >= 1024) {
        session->cdc_average_block_size = block_size;
    } else if (block_size == -1) {
        session->cdc_average_block_size = 0;
    } else {
        session->cdc_average_block_size = 0;
        seaf_message ("Block size less than 1KB. Use default block size(8MB).\n");
    }

    session->disable_block_hash =
        seafile_session_config_get_bool (session, KEY_DISABLE_BLOCK_HASH);
    
    session->hide_windows_incompatible_path_notification =
        seafile_session_config_get_bool (session, KEY_HIDE_WINDOWS_INCOMPATIBLE_PATH_NOTIFICATION);
    
    /* Start mq manager earlier, so that we can send notifications
     * when start repo manager. */
    seaf_mq_manager_init (session->mq_mgr);
    seaf_commit_manager_init (session->commit_mgr);
    seaf_fs_manager_init (session->fs_mgr);
    seaf_branch_manager_init (session->branch_mgr);
    seaf_filelock_manager_init (session->filelock_mgr);
    seaf_repo_manager_init (session->repo_mgr);
    seaf_clone_manager_init (session->clone_mgr);
#ifndef SEAF_TOOL    
    seaf_sync_manager_init (session->sync_mgr);
#endif
}

/* static void */
/* recover_interrupted_merges () */
/* { */
/*     GList *repos, *ptr; */
/*     SeafRepo *repo; */
/*     SeafRepoMergeInfo info; */
/*     char *err_msg = NULL; */
/*     gboolean unused; */

/*     repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1); */
/*     for (ptr = repos; ptr; ptr = ptr->next) { */
/*         repo = ptr->data; */

/*         if (seaf_repo_manager_get_merge_info (seaf->repo_mgr, repo->id, &info) < 0) { */
/*             seaf_warning ("Failed to get merge info for repo %s.\n", repo->id); */
/*             continue; */
/*         } */

/*         if (info.in_merge) { */
/*             seaf_message ("Recovering merge for repo %.8s.\n", repo->id); */

/*             /\* No one else is holding the lock. *\/ */
/*             pthread_mutex_lock (&repo->lock); */
/*             if (seaf_repo_merge (repo, "master", &err_msg, &unused) < 0) { */
/*                 g_free (err_msg); */
/*             } */
/*             pthread_mutex_unlock (&repo->lock); */
/*         } */
/*     } */
/*     g_list_free (repos); */
/* } */

static gboolean
is_repo_store_in_use (const char *repo_id)
{
    if (seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id))
        return TRUE;

    char sql[256];
    snprintf (sql, sizeof(sql), "SELECT 1 FROM CloneTasks WHERE repo_id='%s'",
              repo_id);
    if (sqlite_check_for_existence (seaf->clone_mgr->db, sql))
        return TRUE;

    return FALSE;
}

static void
cleanup_unused_repo_stores (const char *type)
{
    char *top_store_dir;
    const char *repo_id;

    top_store_dir = g_build_filename (seaf->seaf_dir, "storage", type, NULL);

    GError *error = NULL;
    GDir *dir = g_dir_open (top_store_dir, 0, &error);
    if (!dir) {
        seaf_warning ("Failed to open store dir %s: %s.\n",
                      top_store_dir, error->message);
        g_free (top_store_dir);
        return;
    }

    while ((repo_id = g_dir_read_name(dir)) != NULL) {
        if (!is_repo_store_in_use (repo_id)) {
            seaf_message ("Moving %s for deleted repo %s.\n", type, repo_id);
            seaf_repo_manager_move_repo_store (seaf->repo_mgr, type, repo_id);
        }
    }

    g_free (top_store_dir);
    g_dir_close (dir);
}

static void *
on_start_cleanup_job (void *vdata)
{
    /* recover_interrupted_merges (); */

    /* Ignore migration errors. If any blocks is not migrated successfully,
     * there will be some sync error in run time. The user has to recover the
     * error by resyncing.
     */
    /* migrate_client_v0_repos (); */

    cleanup_unused_repo_stores ("commits");
    cleanup_unused_repo_stores ("fs");
    cleanup_unused_repo_stores ("blocks");

    return vdata;
}

static void
cleanup_job_done (void *vdata)
{
    SeafileSession *session = vdata;

    if (cevent_manager_start (session->ev_mgr) < 0) {
        g_error ("Failed to start event manager.\n");
        return;
    }

    if (http_tx_manager_start (session->http_tx_mgr) < 0) {
        g_error ("Failed to start http transfer manager.\n");
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

    /* Must be after wt monitor, since we may add watch to repo worktree. */
    if (seaf_repo_manager_start (session->repo_mgr) < 0) {
        g_error ("Failed to start repo manager.\n");
        return;
    }

    if (seaf_clone_manager_start (session->clone_mgr) < 0) {
        g_error ("Failed to start clone manager.\n");
        return;
    }

    if (seaf_filelock_manager_start (session->filelock_mgr) < 0) {
        g_error ("Failed to start filelock manager.\n");
        return;
    }

    /* The system is up and running. */
    session->started = TRUE;
}

static void
on_start_cleanup (SeafileSession *session)
{
    seaf_job_manager_schedule_job (seaf->job_mgr, 
                                   on_start_cleanup_job, 
                                   cleanup_job_done,
                                   session);
}

void
seafile_session_start (SeafileSession *session)
{
    /* Finish cleanup task before anything is run. */
    on_start_cleanup (session);
}

