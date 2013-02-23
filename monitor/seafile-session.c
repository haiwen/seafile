#include "common.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ccnet.h>
#include <utils.h>

#include "seafile-session.h"
#include "seafile-config.h"
#include "seaf-utils.h"

#define MAX_THREADS 50
#define REFRESH_INTV 86400      /* 24 hours */

static int
refresh_all_repo_sizes (void *vsession);

SeafileSession *
seafile_session_new(const char *seafile_dir,
                    CcnetClient *ccnet_session)
{
    char *abs_seafile_dir;
    char *tmp_file_dir;
    char *config_file_path;
    struct stat st;
    GKeyFile *config;
    SeafileSession *session = NULL;

    if (!ccnet_session)
        return NULL;

    abs_seafile_dir = ccnet_expand_path (seafile_dir);
    tmp_file_dir = g_build_filename (abs_seafile_dir, "tmpfiles", NULL);
    config_file_path = g_build_filename (abs_seafile_dir, "seafile.conf", NULL);

    if (g_lstat(abs_seafile_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
        g_warning ("Seafile data dir %s does not exist and is unable to create\n",
                   abs_seafile_dir);
        goto onerror;
    }

    if (g_lstat(tmp_file_dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
        g_warning ("Seafile tmp dir %s does not exist and is unable to create\n",
                   tmp_file_dir);
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
    session->config = config;

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

    session->job_mgr = ccnet_job_manager_new (MAX_THREADS);

    session->scheduler = scheduler_new (session);

    session->mq_mgr = seaf_mq_manager_new (session);
    if (!session->mq_mgr)
        goto onerror;

    return session;

onerror:
    free (abs_seafile_dir);
    g_free (tmp_file_dir);
    g_free (config_file_path);
    g_free (session);
    return NULL;    
}

int
seafile_session_init (SeafileSession *session)
{
    seaf_commit_manager_init (session->commit_mgr);
    seaf_fs_manager_init (session->fs_mgr);
    seaf_branch_manager_init (session->branch_mgr);
    seaf_repo_manager_init (session->repo_mgr);

    if (scheduler_init (session->scheduler) < 0)
        return -1;

    seaf_mq_manager_init (session->mq_mgr);
    seaf_mq_manager_set_heartbeat_name (session->mq_mgr,
                                        "seaf_mon.heartbeat");

    return 0;
}

int
seafile_session_start (SeafileSession *session)
{
    if (seaf_mq_manager_start (session->mq_mgr) < 0) {
        g_error ("Failed to start mq manager.\n");
        return -1;
    }

    /* refresh on restart. */
    refresh_all_repo_sizes (session);

    /* refresh every 24 hours. */
    session->refresh_timer = ccnet_timer_new (refresh_all_repo_sizes,
                                              session,
                                              REFRESH_INTV * 1000);

    return 0;
}

static int
refresh_all_repo_sizes (void *vsession)
{
    SeafileSession *session = vsession;
    GList *id_list;
    GList *ptr;
    char *repo_id;

    id_list = seaf_repo_manager_get_repo_id_list (session->repo_mgr);

    for (ptr = id_list; ptr != NULL; ptr = ptr->next) {
        repo_id = ptr->data;
        schedule_repo_size_computation (session->scheduler, repo_id);
        g_free (repo_id);
    }
    g_list_free (id_list);

    return 1;
}
