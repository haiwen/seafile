/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
#include "log.h"

#include "seafile-error-impl.h"
#include "seafile-session.h"
#include "vc-utils.h"
#include "utils.h"
#include "seafile-config.h"

#include "timer.h"

#define CLONE_DB "clone.db"

#define CHECK_CONNECT_INTERVAL 5

static void
on_repo_http_fetched (SeafileSession *seaf,
                      HttpTxTask *tx_task,
                      SeafCloneManager *mgr);

static void
transition_state (CloneTask *task, int new_state);

static void
transition_to_error (CloneTask *task, int error);

static int
add_transfer_task (CloneTask *task, GError **error);

static const char *state_str[] = {
    "init",
    "check server",
    "fetch",
    "done",
    "error",
    "canceling",
    "canceled",
    /* States only used by old protocol. */
    "connect",
    "connect",                  /* Use "connect" for CHECK_PROTOCOL */
    "index",
    "checkout",
    "merge",
};

static void
mark_clone_done_v2 (SeafRepo *repo, CloneTask *task)
{
    SeafBranch *local = NULL;

    seaf_repo_manager_set_repo_worktree (repo->manager,
                                         repo,
                                         task->worktree);

    local = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "local");
    if (!local) {
        seaf_warning ("Cannot get branch local for repo %s(%.10s).\n",
                      repo->name, repo->id);
        transition_to_error (task, SYNC_ERROR_ID_LOCAL_DATA_CORRUPT);
        return;
    }
    /* Set repo head to mark checkout done. */
    seaf_repo_set_head (repo, local);
    seaf_branch_unref (local);

    if (repo->encrypted) {
        if (seaf_repo_manager_set_repo_passwd (seaf->repo_mgr,
                                               repo,
                                               task->passwd) < 0) {
            seaf_warning ("[Clone mgr] failed to set passwd for %s.\n", repo->id);
            transition_to_error (task, SYNC_ERROR_ID_GENERAL_ERROR);
            return;
        }
    }

    if (task->is_readonly) {
        seaf_repo_set_readonly (repo);
    }

    if (task->sync_wt_name) {
        seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                             repo->id,
                                             REPO_SYNC_WORKTREE_NAME,
                                             "true");
    }

    if (task->server_url)
        repo->server_url = g_strdup(task->server_url);

    if (repo->auto_sync && (repo->sync_interval == 0)) {
        if (seaf_wt_monitor_watch_repo (seaf->wt_monitor,
                                        repo->id, repo->worktree) < 0) {
            seaf_warning ("failed to watch repo %s(%.10s).\n", repo->name, repo->id);
            transition_to_error (task, SYNC_ERROR_ID_GENERAL_ERROR);
            return;
        }
    }

    /* For compatibility, still set these two properties.
     * So that if we downgrade to an old version, the syncing can still work.
     */
    seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                         repo->id,
                                         REPO_REMOTE_HEAD,
                                         repo->head->commit_id);
    seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                         repo->id,
                                         REPO_LOCAL_HEAD,
                                         repo->head->commit_id);

    transition_state (task, CLONE_STATE_DONE);
}

static void
start_clone_v2 (CloneTask *task)
{
    GError *error = NULL;

    if (g_access (task->worktree, F_OK) != 0 &&
        g_mkdir_with_parents (task->worktree, 0777) < 0) {
        seaf_warning ("[clone mgr] Failed to create worktree %s.\n",
                      task->worktree);
        transition_to_error (task, SYNC_ERROR_ID_WRITE_LOCAL_DATA);
        return;
    }

    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, task->repo_id);
    if (repo != NULL) {
        seaf_repo_manager_set_repo_token (seaf->repo_mgr, repo, task->token);
        seaf_repo_manager_set_repo_email (seaf->repo_mgr, repo, task->email);
        seaf_repo_manager_set_repo_relay_info (seaf->repo_mgr, repo->id,
                                               task->peer_addr, task->peer_port);
        if (task->server_url) {
            seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                                 repo->id,
                                                 REPO_PROP_SERVER_URL,
                                                 task->server_url);
        }

        mark_clone_done_v2 (repo, task);
        return;
    }

    if (add_transfer_task (task, &error) == 0)
        transition_state (task, CLONE_STATE_FETCH);
    else
        transition_to_error (task, SYNC_ERROR_ID_NOT_ENOUGH_MEMORY);
}

static void
check_head_commit_done (HttpHeadCommit *result, void *user_data)
{
    CloneTask *task = user_data;

    if (task->state == CLONE_STATE_CANCEL_PENDING) {
        transition_state (task, CLONE_STATE_CANCELED);
        return;
    }

    if (result->check_success && !result->is_corrupt && !result->is_deleted) {
        memcpy (task->server_head_id, result->head_commit, 40);
        start_clone_v2 (task);
    } else {
        transition_to_error (task, result->error_code);
    }
}

static void
http_check_head_commit (CloneTask *task)
{
    int ret = http_tx_manager_check_head_commit (seaf->http_tx_mgr,
                                                 task->repo_id,
                                                 task->repo_version,
                                                 task->effective_url,
                                                 task->token,
                                                 task->use_fileserver_port,
                                                 check_head_commit_done,
                                                 task);
    if (ret < 0)
        transition_to_error (task, SYNC_ERROR_ID_NOT_ENOUGH_MEMORY);
}

static char *
http_fileserver_url (const char *url)
{
    const char *host;
    char *colon;
    char *url_no_port;
    char *ret = NULL;

    /* Just return the url itself if it's invalid. */
    if (strlen(url) <= strlen("http://"))
        return g_strdup(url);

    /* Skip protocol schem. */
    host = url + strlen("http://");

    colon = strrchr (host, ':');
    if (colon) {
        url_no_port = g_strndup(url, colon - url);
        ret = g_strconcat(url_no_port, ":8082", NULL);
        g_free (url_no_port);
    } else {
        ret = g_strconcat(url, ":8082", NULL);
    }

    return ret;
}

static void
check_http_fileserver_protocol_done (HttpProtocolVersion *result, void *user_data)
{
    CloneTask *task = user_data;

    if (task->state == CLONE_STATE_CANCEL_PENDING) {
        transition_state (task, CLONE_STATE_CANCELED);
        return;
    }

    if (result->check_success && !result->not_supported) {
        task->http_protocol_version = result->version;
        task->effective_url = http_fileserver_url (task->server_url);
        task->use_fileserver_port = TRUE;
        http_check_head_commit (task);
    } else {
        /* Wait for periodic retry. */
        transition_to_error (task, result->error_code);
    }
}

static void
check_http_protocol_done (HttpProtocolVersion *result, void *user_data)
{
    CloneTask *task = user_data;

    if (task->state == CLONE_STATE_CANCEL_PENDING) {
        transition_state (task, CLONE_STATE_CANCELED);
        return;
    }

    if (result->check_success && !result->not_supported) {
        task->http_protocol_version = result->version;
        task->effective_url = g_strdup(task->server_url);
        http_check_head_commit (task);
    } else if (strncmp(task->server_url, "https", 5) != 0) {
        char *host_fileserver = http_fileserver_url(task->server_url);
        if (http_tx_manager_check_protocol_version (seaf->http_tx_mgr,
                                                    host_fileserver,
                                                    TRUE,
                                                    check_http_fileserver_protocol_done,
                                                    task) < 0)
            transition_to_error (task, SYNC_ERROR_ID_NOT_ENOUGH_MEMORY);
        g_free (host_fileserver);
    } else {
        /* Wait for periodic retry. */
        transition_to_error (task, result->error_code);
    }
}

static void
check_http_protocol (CloneTask *task)
{
    if (http_tx_manager_check_protocol_version (seaf->http_tx_mgr,
                                                task->server_url,
                                                FALSE,
                                                check_http_protocol_done,
                                                task) < 0) {
        transition_to_error (task, SYNC_ERROR_ID_NOT_ENOUGH_MEMORY);
        return;
    }

    transition_state (task, CLONE_STATE_CHECK_SERVER);
}

static CloneTask *
clone_task_new (const char *repo_id,
                const char *repo_name,
                const char *token,
                const char *worktree,
                const char *passwd,
                const char *email)
{
    CloneTask *task = g_new0 (CloneTask, 1);

    memcpy (task->repo_id, repo_id, 37);
    task->token = g_strdup (token);
    task->worktree = g_strdup(worktree);
    task->email = g_strdup(email);
    if (repo_name)
        task->repo_name = g_strdup(repo_name);
    if (passwd)
        task->passwd = g_strdup (passwd);
    task->error = SYNC_ERROR_ID_NO_ERROR;

    return task;
}

static void
clone_task_free (CloneTask *task)
{
    g_free (task->tx_id);
    g_free (task->worktree);
    g_free (task->passwd);
    g_free (task->token);
    g_free (task->repo_name);
    g_free (task->peer_addr);
    g_free (task->peer_port);
    g_free (task->email);
    g_free (task->random_key);
    g_free (task->server_url);
    g_free (task->effective_url);

    g_free (task);
}

const char *
clone_task_state_to_str (int state)
{
    if (state < 0 || state >= N_CLONE_STATES)
        return NULL;
    return state_str[state];
}

SeafCloneManager *
seaf_clone_manager_new (SeafileSession *session)
{
    SeafCloneManager *mgr = g_new0 (SeafCloneManager, 1);

    char *db_path = g_build_path ("/", session->seaf_dir, CLONE_DB, NULL);
    if (sqlite_open_db (db_path, &mgr->db) < 0) {
        g_critical ("[Clone mgr] Failed to open db\n");
        g_free (db_path);
        g_free (mgr);
        return NULL;
    }

    mgr->seaf = session;
    mgr->tasks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                        g_free, (GDestroyNotify)clone_task_free);
    return mgr;
}

static gboolean
load_enc_info_cb (sqlite3_stmt *stmt, void *data)
{
    CloneTask *task = data;
    int enc_version;
    const char *random_key;

    enc_version = sqlite3_column_int (stmt, 0);
    random_key = (const char *)sqlite3_column_text (stmt, 1);

    task->enc_version = enc_version;
    task->random_key = g_strdup (random_key);

    return FALSE;
}

static int
load_clone_enc_info (CloneTask *task)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "SELECT enc_version, random_key FROM CloneEncInfo WHERE repo_id='%s'",
              task->repo_id);

    if (sqlite_foreach_selected_row (task->manager->db, sql,
                                     load_enc_info_cb, task) < 0)
        return -1;

    return 0;
}

static gboolean
load_version_info_cb (sqlite3_stmt *stmt, void *data)
{
    CloneTask *task = data;
    int repo_version;

    repo_version = sqlite3_column_int (stmt, 0);

    task->repo_version = repo_version;

    return FALSE;
}

static void
load_clone_repo_version_info (CloneTask *task)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "SELECT repo_version FROM CloneVersionInfo WHERE repo_id='%s'",
              task->repo_id);

    sqlite_foreach_selected_row (task->manager->db, sql,
                                 load_version_info_cb, task);
}

static gboolean
load_more_info_cb (sqlite3_stmt *stmt, void *data)
{
    CloneTask *task = data;
    json_error_t jerror;
    json_t *object = NULL;
    const char *more_info;

    more_info = (const char *)sqlite3_column_text (stmt, 0);
    object = json_loads (more_info, 0, &jerror);
    if (!object) {
        seaf_warning ("Failed to load more sync info from json: %s.\n", jerror.text);
        return FALSE;
    }
        
    json_t *integer = json_object_get (object, "is_readonly");
    task->is_readonly = json_integer_value (integer);
    json_t *string = json_object_get (object, "server_url");
    if (string)
        task->server_url = g_strdup (json_string_value (string));
    json_t *repo_salt = json_object_get (object, "repo_salt");
    if (repo_salt)
        task->repo_salt = g_strdup (json_string_value (repo_salt));
    json_decref (object);

    return FALSE;
}

static void
load_clone_more_info (CloneTask *task)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "SELECT more_info FROM CloneTasksMoreInfo WHERE repo_id='%s'",
              task->repo_id);

    sqlite_foreach_selected_row (task->manager->db, sql,
                                 load_more_info_cb, task);
}

static gboolean
restart_task (sqlite3_stmt *stmt, void *data)
{
    SeafCloneManager *mgr = data;
    const char *repo_id, *repo_name, *token, *worktree, *passwd;
    const char *email;
    CloneTask *task;
    SeafRepo *repo;

    repo_id = (const char *)sqlite3_column_text (stmt, 0);
    repo_name = (const char *)sqlite3_column_text (stmt, 1);
    token = (const char *)sqlite3_column_text (stmt, 2);
    worktree = (const char *)sqlite3_column_text (stmt, 4);
    passwd = (const char *)sqlite3_column_text (stmt, 5);
    email = (const char *)sqlite3_column_text (stmt, 8);

    task = clone_task_new (repo_id, repo_name, token,
                           worktree, passwd, email);
    task->manager = mgr;
    /* Default to 1. */
    task->enc_version = 1;

    if (passwd && load_clone_enc_info (task) < 0) {
        clone_task_free (task);
        return TRUE;
    }

    task->repo_version = 0;
    load_clone_repo_version_info (task);

    load_clone_more_info (task);

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);

    if (repo != NULL && repo->head != NULL) {
        transition_state (task, CLONE_STATE_DONE);
        return TRUE;
    }

    if (task->repo_version > 0) {
        if (task->server_url) {
            check_http_protocol (task);
        } else {
            transition_to_error (task, SYNC_ERROR_ID_GENERAL_ERROR);
            return TRUE;
        }
    }

    g_hash_table_insert (mgr->tasks, g_strdup(task->repo_id), task);

    return TRUE;
}

int
seaf_clone_manager_init (SeafCloneManager *mgr)
{
    const char *sql;

    sql = "CREATE TABLE IF NOT EXISTS CloneTasks "
        "(repo_id TEXT PRIMARY KEY, repo_name TEXT, "
        "token TEXT, dest_id TEXT,"
        "worktree_parent TEXT, passwd TEXT, "
        "server_addr TEXT, server_port TEXT, email TEXT);";
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS CloneTasksMoreInfo "
        "(repo_id TEXT PRIMARY KEY, more_info TEXT);";
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS CloneEncInfo "
        "(repo_id TEXT PRIMARY KEY, enc_version INTEGER, random_key TEXT);";
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS CloneVersionInfo "
        "(repo_id TEXT PRIMARY KEY, repo_version INTEGER);";
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS CloneServerURL "
        "(repo_id TEXT PRIMARY KEY, server_url TEXT);";
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    return 0;
}

static int check_connect_pulse (void *vmanager)
{
    SeafCloneManager *mgr = vmanager;
    CloneTask *task;
    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, mgr->tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        if (task->state == CLONE_STATE_ERROR &&
            task->repo_version > 0 &&
            sync_error_level (task->error) == SYNC_ERROR_LEVEL_NETWORK) {
            task->error = SYNC_ERROR_ID_NO_ERROR;
            check_http_protocol (task);
        }
    }

    return TRUE;
}

int
seaf_clone_manager_start (SeafCloneManager *mgr)
{
    mgr->check_timer = seaf_timer_new (check_connect_pulse, mgr,
                                       CHECK_CONNECT_INTERVAL * 1000);

    char *sql = "SELECT * FROM CloneTasks";
    if (sqlite_foreach_selected_row (mgr->db, sql, restart_task, mgr) < 0)
        return -1;

    g_signal_connect (seaf, "repo-http-fetched",
                      (GCallback)on_repo_http_fetched, mgr);

    return 0;
}

static int
save_task_to_db (SeafCloneManager *mgr, CloneTask *task)
{
    char *sql;

    if (task->passwd)
        sql = sqlite3_mprintf ("REPLACE INTO CloneTasks VALUES "
            "('%q', '%q', '%q', NULL, '%q', '%q', NULL, NULL, '%q')",
                                task->repo_id, task->repo_name,
                                task->token,
                                task->worktree, task->passwd,
                                task->email);
    else
        sql = sqlite3_mprintf ("REPLACE INTO CloneTasks VALUES "
            "('%q', '%q', '%q', NULL, '%q', NULL, NULL, NULL, '%q')",
                                task->repo_id, task->repo_name,
                                task->token,
                                task->worktree, task->email);

    if (sqlite_query_exec (mgr->db, sql) < 0) {
        sqlite3_free (sql);
        return -1;
    }
    sqlite3_free (sql);

    if (task->passwd && task->enc_version >= 2 && task->random_key) {
        sql = sqlite3_mprintf ("REPLACE INTO CloneEncInfo VALUES "
                               "('%q', %d, '%q')",
                               task->repo_id, task->enc_version, task->random_key);
        if (sqlite_query_exec (mgr->db, sql) < 0) {
            sqlite3_free (sql);
            return -1;
        }
        sqlite3_free (sql);
    }

    sql = sqlite3_mprintf ("REPLACE INTO CloneVersionInfo VALUES "
                           "('%q', %d)",
                           task->repo_id, task->repo_version);
    if (sqlite_query_exec (mgr->db, sql) < 0) {
        sqlite3_free (sql);
        return -1;
    }
    sqlite3_free (sql);

    if (task->is_readonly || task->server_url || task->repo_salt) {
        /* need to store more info */
        json_t *object = NULL;
        gchar *info = NULL;

        object = json_object ();
        json_object_set_new (object, "is_readonly", json_integer (task->is_readonly));
        if (task->server_url)
            json_object_set_new (object, "server_url", json_string(task->server_url));
    
        info = json_dumps (object, 0);
        json_decref (object);
        sql = sqlite3_mprintf ("REPLACE INTO CloneTasksMoreInfo VALUES "
                           "('%q', '%q')", task->repo_id, info);
        if (sqlite_query_exec (mgr->db, sql) < 0) {
            sqlite3_free (sql);
            g_free (info);
            return -1;
        }
        sqlite3_free (sql);
        g_free (info);
    }

    return 0;
}

static int
remove_task_from_db (SeafCloneManager *mgr, const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql), 
              "DELETE FROM CloneTasks WHERE repo_id='%s'",
              repo_id);
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    snprintf (sql, sizeof(sql), 
              "DELETE FROM CloneEncInfo WHERE repo_id='%s'",
              repo_id);
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    snprintf (sql, sizeof(sql), 
              "DELETE FROM CloneVersionInfo WHERE repo_id='%s'",
              repo_id);
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    snprintf (sql, sizeof(sql), 
              "DELETE FROM CloneTasksMoreInfo WHERE repo_id='%s'",
              repo_id);
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    return 0;
}

static void
transition_state (CloneTask *task, int new_state)
{
    seaf_message ("Transition clone state for %.8s from [%s] to [%s].\n",
                  task->repo_id,
                  state_str[task->state], state_str[new_state]);

    if (new_state == CLONE_STATE_DONE ||
        new_state == CLONE_STATE_CANCELED) {
        /* Remove from db but leave in memory. */
        remove_task_from_db (task->manager, task->repo_id);
    }

    task->state = new_state;
}

static void
transition_to_error (CloneTask *task, int error)
{
    seaf_message ("Transition clone state for %.8s from [%s] to [error]: %s.\n",
                  task->repo_id,
                  state_str[task->state], 
                  sync_error_id_to_str(error));

    task->state = CLONE_STATE_ERROR;
    task->error = error;
}

static int
add_transfer_task (CloneTask *task, GError **error)
{
    int ret = http_tx_manager_add_download (seaf->http_tx_mgr,
                                            task->repo_id,
                                            task->repo_version,
                                            task->effective_url,
                                            task->token,
                                            task->server_head_id,
                                            TRUE,
                                            task->passwd,
                                            task->worktree,
                                            task->http_protocol_version,
                                            task->email,
                                            task->use_fileserver_port,
                                            task->repo_name,
                                            error);
    if (ret < 0)
        return -1;
    task->tx_id = g_strdup(task->repo_id);
    return 0;
}

static gboolean
is_duplicate_task (SeafCloneManager *mgr, const char *repo_id)
{
    CloneTask *task = g_hash_table_lookup (mgr->tasks, repo_id);
    if (task != NULL &&
        task->state != CLONE_STATE_DONE &&
        task->state != CLONE_STATE_CANCELED)
        return TRUE;
    return FALSE;
}

static gboolean
is_worktree_of_repo (SeafCloneManager *mgr, const char *path)
{
    GList *repos, *ptr;
    SeafRepo *repo;
    GHashTableIter iter;
    gpointer key, value;
    CloneTask *task;

    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    for (ptr = repos; ptr != NULL; ptr = ptr->next) {
        repo = ptr->data;
        if (g_strcmp0 (path, repo->worktree) == 0) {
            g_list_free (repos);
            return TRUE;
        }
    }
    g_list_free (repos);

    g_hash_table_iter_init (&iter, mgr->tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        if (task->state == CLONE_STATE_DONE ||
            task->state == CLONE_STATE_CANCELED)
            continue;
        if (g_strcmp0 (path, task->worktree) == 0)
            return TRUE;
    }

    return FALSE;
}

static char *
try_worktree (const char *worktree)
{
    char *tmp;
    unsigned int cnt;

    /* There is a repo name conflict, so we try to add a postfix */
    cnt = 1;
    while (1) {
        tmp = g_strdup_printf("%s-%d", worktree, cnt++);
        if (g_access(tmp, F_OK) < 0) {
            return tmp;
        }

        if (cnt == -1U) {
            /* we have tried too much times, so give up */
            g_free(tmp);
            return NULL;
        }

        g_free(tmp);
    }

    /* XXX: never reach here */
}

static inline void
remove_trail_slash (char *path)
{
    int tail = strlen (path) - 1;
    while (tail >= 0 && (path[tail] == '/' || path[tail] == '\\'))
        path[tail--] = '\0';
}

static char *
make_worktree (SeafCloneManager *mgr,
               const char *worktree,
               gboolean dry_run,
               GError **error)
{
    char *wt = g_strdup (worktree);
    SeafStat st;
    int rc;
    char *ret;

    remove_trail_slash (wt);

    rc = seaf_stat (wt, &st);
    if (rc < 0) {
        ret = wt;
        return ret;
    } else if (!S_ISDIR(st.st_mode)) {
        if (!dry_run) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Invalid local directory");
            g_free (wt);
            return NULL;
        }
        ret = try_worktree (wt);
        g_free (wt);
        return ret;
    }

    /* OK, wt is an existing dir. Let's see if it's the worktree for
     * another repo. */
    if (is_worktree_of_repo (mgr, wt)) {
        if (!dry_run) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Already in sync");
            g_free (wt);
            return NULL;
        }
        ret = try_worktree (wt);
        g_free (wt);
    } else {
        return wt;
    }

    return ret;
}

/*
 * Generate a conflict-free path to be used as worktree.
 * This worktree path can be used as the @worktree parameter
 * for seaf_clone_manager_add_task().
 */
char *
seaf_clone_manager_gen_default_worktree (SeafCloneManager *mgr,
                                         const char *worktree_parent,
                                         const char *repo_name)
{
    char *wt = g_build_filename (worktree_parent, repo_name, NULL);
    char *worktree;

    worktree = make_worktree (mgr, wt, TRUE, NULL);
    if (!worktree)
        return wt;

    g_free (wt);
    return worktree;
}

inline static gboolean is_separator (char c)
{
    return (c == '/' || c == '\\');
}

/*
 * Returns < 0 if dira includes dirb or dira == dirb;
 * Returns 0 if no inclusive relationship;
 * Returns > 0 if dirb includes dira.
 */
static int
check_dir_inclusiveness (const char *dira, const char *dirb)
{
    char *a, *b;
    char *p1, *p2;
    int ret = 0;

    a = g_strdup(dira);
    b = g_strdup(dirb);
    remove_trail_slash (a);
    remove_trail_slash (b);

    p1 = a;
    p2 = b;
    while (*p1 != 0 && *p2 != 0) {
        /* Go to the last one in a path separator sequence. */
        while (is_separator(*p1) && is_separator(p1[1]))
            ++p1;
        while (is_separator(*p2) && is_separator(p2[1]))
            ++p2;

        if (!(is_separator(*p1) && is_separator(*p2)) && *p1 != *p2)
            goto out;

        ++p1;
        ++p2;
    }

    /* Example:
     *            p1
     * a: /abc/def/ghi
     *            p2
     * b: /abc/def
     */
    if (*p1 == 0 && *p2 == 0)
        ret = -1;
    else if (*p1 != 0 && is_separator(*p1))
        ret = 1;
    else if (*p2 != 0 && is_separator(*p2))
        ret = -1;

out:
    g_free (a);
    g_free (b);
    return ret;
}

gboolean
seaf_clone_manager_check_worktree_path (SeafCloneManager *mgr, const char *path, GError **error)
{
    GList *repos, *ptr;
    SeafRepo *repo;
    GHashTableIter iter;
    gpointer key, value;
    CloneTask *task;

    if (check_dir_inclusiveness (path, seaf->seaf_dir) != 0 ||
        /* It's OK if path is included by the default worktree parent. */
        check_dir_inclusiveness (path, seaf->worktree_dir) < 0 ||
        check_dir_inclusiveness (path, seaf->ccnet_dir) != 0) {
        seaf_warning ("Worktree path conflicts with seafile system path.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Worktree conflicts system path");
        return FALSE;
    }

    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    for (ptr = repos; ptr != NULL; ptr = ptr->next) {
        repo = ptr->data;
        if (repo->worktree != NULL &&
            check_dir_inclusiveness (path, repo->worktree) != 0) {
            seaf_warning ("Worktree path conflict with repo %s.\n", repo->name);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Worktree conflicts existing repo");
            g_list_free (repos);
            return FALSE;
        }
    }
    g_list_free (repos);

    g_hash_table_iter_init (&iter, mgr->tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        if (task->state == CLONE_STATE_DONE ||
            task->state == CLONE_STATE_CANCELED)
            continue;
        if (check_dir_inclusiveness (path, task->worktree) != 0) {
            seaf_warning ("Worktree path conflict with clone %.8s.\n",
                          task->repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Worktree conflicts existing repo");
            return FALSE;
        }
    }

    return TRUE;
}

static char *
add_task_common (SeafCloneManager *mgr, 
                 const char *repo_id,
                 int repo_version,
                 const char *repo_name,
                 const char *token,
                 const char *passwd,
                 int enc_version,
                 const char *random_key,
                 const char *worktree,
                 const char *email,
                 const char *more_info,
                 gboolean sync_wt_name,
                 GError **error)
{
    CloneTask *task;

    task = clone_task_new (repo_id, repo_name,
                           token, worktree,
                           passwd, email);
    task->manager = mgr;
    task->enc_version = enc_version;
    task->random_key = g_strdup (random_key);
    task->repo_version = repo_version;
    task->sync_wt_name = sync_wt_name;
    if (more_info) {
        json_error_t jerror;
        json_t *object = NULL;

        object = json_loads (more_info, 0, &jerror);
        if (!object) {
            seaf_warning ("Failed to load more sync info from json: %s.\n", jerror.text);
            clone_task_free (task);
            return NULL;
        }
        
        json_t *integer = json_object_get (object, "is_readonly");
        task->is_readonly = json_integer_value (integer);
        json_t *string = json_object_get (object, "server_url");
        if (string)
            task->server_url = canonical_server_url (json_string_value (string));
        json_t *repo_salt = json_object_get (object, "repo_salt");
        if (repo_salt)
            task->repo_salt = g_strdup (json_string_value (repo_salt));
        json_decref (object);
    }

    if (save_task_to_db (mgr, task) < 0) {
        seaf_warning ("[Clone mgr] failed to save task.\n");
        clone_task_free (task);
        return NULL;
    }

    if (task->repo_version > 0) {
        if (task->server_url) {
            check_http_protocol (task);
        } else {
            clone_task_free (task);
            return NULL;
        }
    } 

    /* The old task for this repo will be freed. */
    g_hash_table_insert (mgr->tasks, g_strdup(task->repo_id), task);

    return g_strdup(repo_id);
}

static gboolean
check_encryption_args (const char *magic, int enc_version, const char *random_key,
                       const char *repo_salt,
                       GError **error)
{
    if (!magic) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Magic must be specified");
        return FALSE;
    }

    if (enc_version != 1 && enc_version != 2 && enc_version != 3 && enc_version != 4) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Unsupported enc version");
        return FALSE;
    }

    if (enc_version >= 2) {
        if (!random_key || strlen(random_key) != 96) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Random key not specified");
            return FALSE;
        }
        if (enc_version >= 3 && (!(repo_salt) || strlen(repo_salt) != 64) ) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Repo salt not specified");
            return FALSE;
        }
    }

    return TRUE;
}

static gboolean
is_wt_repo_name_same (const char *worktree, const char *repo_name)
{
    char *basename = g_path_get_basename (worktree);
    gboolean ret = FALSE;
    ret = (strcmp (basename, repo_name) == 0);
    g_free (basename);
    return ret;
}

char *
seaf_clone_manager_add_task (SeafCloneManager *mgr, 
                             const char *repo_id,
                             int repo_version,
                             const char *repo_name,
                             const char *token,
                             const char *passwd,
                             const char *magic,
                             int enc_version,
                             const char *random_key,
                             const char *worktree_in,
                             const char *email,
                             const char *more_info,
                             GError **error)
{
    SeafRepo *repo = NULL;
    char *worktree = NULL;
    char *ret = NULL;
    gboolean sync_wt_name = FALSE;
    char *repo_salt = NULL;

    if (!seaf->started) {
        seaf_message ("System not started, skip adding clone task.\n");
        goto out;
    }

#ifdef USE_GPL_CRYPTO
    if (repo_version == 0 || (passwd && enc_version < 2)) {
        seaf_warning ("Don't support syncing old version libraries.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Don't support syncing old version libraries");
        goto out;
    }
#endif

    if (more_info) {
        json_error_t jerror;
        json_t *object;

        object = json_loads (more_info, 0, &jerror);
        if (!object) {
            seaf_warning ("Failed to load more sync info from json: %s.\n", jerror.text);
            goto out;
        }
        json_t *string = json_object_get (object, "repo_salt");
        if (string)
            repo_salt = g_strdup (json_string_value (string));
        json_decref (object);
    }

    if (passwd &&
        !check_encryption_args (magic, enc_version, random_key, repo_salt, error)) {
        goto out;
    }
    /* After a repo was unsynced, the sync task may still be blocked in the
     * network, so the repo is not actually deleted yet.
     * In this case just return an error to the user.
     */
    SyncInfo *sync_info = seaf_sync_manager_get_sync_info (seaf->sync_mgr,
                                                           repo_id);
    if (sync_info && sync_info->in_sync) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Repo already exists");
        goto out;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);

    if (repo != NULL && repo->head != NULL) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Repo already exists");
        goto out;
    }   

    if (is_duplicate_task (mgr, repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, 
                     "Task is already in progress");
        goto out;
    }

    if (passwd &&
        seafile_verify_repo_passwd(repo_id, passwd, magic, enc_version, repo_salt) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Incorrect password");
        goto out;
    }

    if (!seaf_clone_manager_check_worktree_path (mgr, worktree_in, error))
        goto out;

    /* Return error if worktree_in conflicts with another repo or
     * is not a directory.
     */
    worktree = make_worktree (mgr, worktree_in, FALSE, error);
    if (!worktree) {
        goto out;
    }

    /* Don't sync worktree folder name with library name later if they're not the same
     * at the beginning.
     */
    sync_wt_name = is_wt_repo_name_same (worktree, repo_name);

    /* If a repo was unsynced and then downloaded again, there may be
     * a garbage record for this repo. We don't want the downloaded blocks
     * be removed by GC.
     */
    if (repo_version > 0)
        seaf_repo_manager_remove_garbage_repo (seaf->repo_mgr, repo_id);

    /* Delete orphan information in the db in case the repo was corrupt. */
    if (!repo)
        seaf_repo_manager_remove_repo_ondisk (seaf->repo_mgr, repo_id, FALSE);

    ret = add_task_common (mgr, repo_id, repo_version,
                           repo_name, token, passwd,
                           enc_version, random_key,
                           worktree, email, more_info,
                           sync_wt_name,
                           error);

out:
    g_free (worktree);
    g_free (repo_salt);

    return ret;
}

static char *
make_worktree_for_download (SeafCloneManager *mgr,
                            const char *wt_tmp,
                            GError **error)
{
    char *worktree;

    if (g_access (wt_tmp, F_OK) == 0) {
        worktree = try_worktree (wt_tmp);
    } else {
        worktree = g_strdup(wt_tmp);
    }

    if (!seaf_clone_manager_check_worktree_path (mgr, worktree, error)) {
        g_free (worktree);
        return NULL;
    }

    return worktree;
}

char *
seaf_clone_manager_add_download_task (SeafCloneManager *mgr, 
                                      const char *repo_id,
                                      int repo_version,
                                      const char *repo_name,
                                      const char *token,
                                      const char *passwd,
                                      const char *magic,
                                      int enc_version,
                                      const char *random_key,
                                      const char *wt_parent,
                                      const char *email,
                                      const char *more_info,
                                      GError **error)
{
    SeafRepo *repo = NULL;
    char *wt_tmp = NULL;
    char *worktree = NULL;
    char *ret = NULL;
    char *repo_salt = NULL;

    if (!seaf->started) {
        seaf_message ("System not started, skip adding clone task.\n");
        goto out;
    }

#ifdef USE_GPL_CRYPTO
    if (repo_version == 0 || (passwd && enc_version < 2)) {
        seaf_warning ("Don't support syncing old version libraries.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Don't support syncing old version libraries");
        goto out;
    }
#endif

    if (more_info) {
         json_error_t jerror;
         json_t *object;
 
         object = json_loads (more_info, 0, &jerror);
         if (!object) {
             seaf_warning ("Failed to load more sync info from json: %s.\n", jerror.text);
             goto out;
         }
         json_t *string = json_object_get (object, "repo_salt");
         if (string)
             repo_salt = g_strdup (json_string_value (string));
         json_decref (object);
     }

    if (passwd &&
        !check_encryption_args (magic, enc_version, random_key, repo_salt, error)) {
        goto out;
    }

    /* After a repo was unsynced, the sync task may still be blocked in the
     * network, so the repo is not actually deleted yet.
     * In this case just return an error to the user.
     */
    SyncInfo *sync_info = seaf_sync_manager_get_sync_info (seaf->sync_mgr,
                                                           repo_id);
    if (sync_info && sync_info->in_sync) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Repo already exists");
        goto out;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);

    if (repo != NULL && repo->head != NULL) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Repo already exists");
        goto out;
    }

    if (is_duplicate_task (mgr, repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, 
                     "Task is already in progress");
        goto out;
    }

    if (passwd &&
        seafile_verify_repo_passwd(repo_id, passwd, magic, enc_version, repo_salt) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Incorrect password");
        goto out;
    }

    IgnoreReason reason;
    if (should_ignore_on_checkout (repo_name, &reason)) {
        if (reason == IGNORE_REASON_END_SPACE_PERIOD)
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Library name ends with space or period character");
        else
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Library name contains invalid characters such as ':', '*', '|', '?'");
        goto out;
    }

    wt_tmp = g_build_filename (wt_parent, repo_name, NULL);

    worktree = make_worktree_for_download (mgr, wt_tmp, error);
    if (!worktree) {
        goto out;
    }

    /* If a repo was unsynced and then downloaded again, there may be
     * a garbage record for this repo. We don't want the downloaded blocks
     * be removed by GC.
     */
    if (repo_version > 0)
        seaf_repo_manager_remove_garbage_repo (seaf->repo_mgr, repo_id);

    /* Delete orphan information in the db in case the repo was corrupt. */
    if (!repo)
        seaf_repo_manager_remove_repo_ondisk (seaf->repo_mgr, repo_id, FALSE);

    ret = add_task_common (mgr, repo_id, repo_version,
                           repo_name, token, passwd,
                           enc_version, random_key,
                           worktree, email, more_info,
                           TRUE, error);

out:
    g_free (worktree);
    g_free (wt_tmp);
    g_free (repo_salt);

    return ret;
}

int
seaf_clone_manager_cancel_task (SeafCloneManager *mgr,
                                const char *repo_id)
{
    CloneTask *task;

    if (!seaf->started) {
        seaf_message ("System not started, skip canceling clone task.\n");
        return -1;
    }

    task = g_hash_table_lookup (mgr->tasks, repo_id);
    if (!task)
        return -1;

    switch (task->state) {
    case CLONE_STATE_INIT:
    case CLONE_STATE_CONNECT:
    case CLONE_STATE_ERROR:
        transition_state (task, CLONE_STATE_CANCELED);
        break;
    case CLONE_STATE_CHECK_SERVER:
        transition_state (task, CLONE_STATE_CANCEL_PENDING);
    case CLONE_STATE_FETCH:
        http_tx_manager_cancel_task (seaf->http_tx_mgr,
                                     task->repo_id,
                                     HTTP_TASK_TYPE_DOWNLOAD);
        transition_state (task, CLONE_STATE_CANCEL_PENDING);
        break;
    case CLONE_STATE_INDEX:
    case CLONE_STATE_CHECKOUT:
    case CLONE_STATE_MERGE:
    case CLONE_STATE_CHECK_PROTOCOL:
        /* We cannot cancel an in-progress checkout, just
         * wait until it finishes.
         */
        transition_state (task, CLONE_STATE_CANCEL_PENDING);
        break;
    case CLONE_STATE_CANCEL_PENDING:
        break;
    default:
        seaf_warning ("[Clone mgr] cannot cancel a not-running task.\n");
        return -1;
    }

    return 0;
}

CloneTask *
seaf_clone_manager_get_task (SeafCloneManager *mgr,
                             const char *repo_id)
{
    return (CloneTask *) g_hash_table_lookup (mgr->tasks, repo_id);
}

GList *
seaf_clone_manager_get_tasks (SeafCloneManager *mgr)
{
    return g_hash_table_get_values (mgr->tasks);
}

static void
check_folder_permissions (CloneTask *task);

static void
on_repo_http_fetched (SeafileSession *seaf,
                      HttpTxTask *tx_task,
                      SeafCloneManager *mgr)
{
    CloneTask *task;

    /* Only handle clone task. */
    if (!tx_task->is_clone)
        return;

    task = g_hash_table_lookup (mgr->tasks, tx_task->repo_id);
    g_return_if_fail (task != NULL);

    if (tx_task->state == HTTP_TASK_STATE_CANCELED) {
        /* g_assert (task->state == CLONE_STATE_CANCEL_PENDING); */
        transition_state (task, CLONE_STATE_CANCELED);
        return;
    } else if (tx_task->state == HTTP_TASK_STATE_ERROR) {
        transition_to_error (task, tx_task->error);
        return;
    }

    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr,
                                                 tx_task->repo_id);
    if (repo == NULL) {
        seaf_warning ("[Clone mgr] cannot find repo %s after fetched.\n", 
                   tx_task->repo_id);
        transition_to_error (task, SYNC_ERROR_ID_LOCAL_DATA_CORRUPT);
        return;
    }

    seaf_repo_manager_set_repo_token (seaf->repo_mgr, repo, task->token);
    seaf_repo_manager_set_repo_email (seaf->repo_mgr, repo, task->email);
    seaf_repo_manager_set_repo_relay_info (seaf->repo_mgr, repo->id,
                                           task->peer_addr, task->peer_port);
    if (task->server_url) {
        seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                             repo->id,
                                             REPO_PROP_SERVER_URL,
                                             task->server_url);
    }

    check_folder_permissions (task);
}

static void
check_folder_perms_done (HttpFolderPerms *result, void *user_data)
{
    CloneTask *task = user_data;
    GList *ptr;
    HttpFolderPermRes *res;

    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr,
                                                 task->repo_id);
    if (repo == NULL) {
        seaf_warning ("[Clone mgr] cannot find repo %s after fetched.\n", 
                   task->repo_id);
        transition_to_error (task, SYNC_ERROR_ID_LOCAL_DATA_CORRUPT);
        return;
    }

    if (!result->success) {
        goto out;
    }

    for (ptr = result->results; ptr; ptr = ptr->next) {
        res = ptr->data;

        seaf_repo_manager_update_folder_perms (seaf->repo_mgr, res->repo_id,
                                               FOLDER_PERM_TYPE_USER,
                                               res->user_perms);
        seaf_repo_manager_update_folder_perms (seaf->repo_mgr, res->repo_id,
                                               FOLDER_PERM_TYPE_GROUP,
                                               res->group_perms);
        seaf_repo_manager_update_folder_perm_timestamp (seaf->repo_mgr,
                                                        res->repo_id,
                                                        res->timestamp);
    }

out:
    mark_clone_done_v2 (repo, task);
}

static void
check_folder_permissions (CloneTask *task)
{
    SeafRepo *repo = NULL;
    HttpFolderPermReq *req;
    GList *requests = NULL;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, task->repo_id);
    if (repo == NULL) {
        seaf_warning ("[Clone mgr] cannot find repo %s after fetched.\n", 
                      task->repo_id);
        transition_to_error (task, SYNC_ERROR_ID_LOCAL_DATA_CORRUPT);
        return;
    }

    if (!seaf_repo_manager_server_is_pro (seaf->repo_mgr, task->server_url)) {
        mark_clone_done_v2 (repo, task);
        return;
    }

    req = g_new0 (HttpFolderPermReq, 1);
    memcpy (req->repo_id, task->repo_id, 36);
    req->token = g_strdup(task->token);
    req->timestamp = 0;

    requests = g_list_append (requests, req);

    /* The requests list will be freed in http tx manager. */
    if (http_tx_manager_get_folder_perms (seaf->http_tx_mgr,
                                          task->effective_url,
                                          task->use_fileserver_port,
                                          requests,
                                          check_folder_perms_done,
                                          task) < 0)
        transition_to_error (task, SYNC_ERROR_ID_NOT_ENOUGH_MEMORY);
}
