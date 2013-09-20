#include "common.h"

#include <ccnet.h>

#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
#include "log.h"

#include "seafile-error.h"
#include "seafile-session.h"
#include "index/index.h"
#include "merge-recursive.h"
#include "unpack-trees.h"
#include "vc-utils.h"

#include "utils.h"

#define CLONE_DB "clone.db"

#define CHECK_CONNECT_INTERVAL 5 /* 5s */

static void
on_repo_fetched (SeafileSession *seaf,
                 TransferTask *tx_task,
                 SeafCloneManager *mgr);

static void
on_checkout_done (CheckoutTask *task, SeafRepo *repo, void *data);

static int
start_index_or_transfer (SeafCloneManager *mgr, CloneTask *task, GError **error);

static void
start_connect_task_relay (CloneTask *task, GError **error);

static void
start_checkout (SeafRepo *repo, CloneTask *task);

static void
transition_state (CloneTask *task, int new_state);

static void
transition_to_error (CloneTask *task, int error);

static const char *state_str[] = {
    "init",
    "connect",
    "index",
    "fetch",
    "checkout",
    "merge",
    "done",
    "error",
    "canceling",
    "canceled",
};

static const char *error_str[] = {
    "ok",
    "connect",
    "index",
    "fetch",
    "password",
    "checkout",
    "merge",
    "internal",
};

static CloneTask *
clone_task_new (const char *repo_id,
                const char *peer_id,
                const char *repo_name,
                const char *token,
                const char *worktree,
                const char *passwd,
                const char *peer_addr,
                const char *peer_port,
                const char *email)
{
    CloneTask *task = g_new0 (CloneTask, 1);

    memcpy (task->repo_id, repo_id, 37);
    memcpy (task->peer_id, peer_id, 41);
    task->token = g_strdup (token);
    task->worktree = g_strdup(worktree);
    task->peer_addr = g_strdup(peer_addr);
    task->peer_port = g_strdup(peer_port);
    task->email = g_strdup(email);
    if (repo_name)
        task->repo_name = g_strdup(repo_name);
    if (passwd)
        task->passwd = g_strdup (passwd);

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

    g_free (task);
}

const char *
clone_task_state_to_str (int state)
{
    if (state < 0 || state >= N_CLONE_STATES)
        return NULL;
    return state_str[state];
}

const char *
clone_task_error_to_str (int error)
{
    if (error < 0 || error >= N_CLONE_ERRORS)
        return NULL;
    return error_str[error];
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
restart_task (sqlite3_stmt *stmt, void *data)
{
    SeafCloneManager *mgr = data;
    const char *repo_id, *repo_name, *token, *peer_id, *worktree, *passwd;
    const char *peer_addr, *peer_port, *email;
    CloneTask *task;
    SeafRepo *repo;

    repo_id = (const char *)sqlite3_column_text (stmt, 0);
    repo_name = (const char *)sqlite3_column_text (stmt, 1);
    token = (const char *)sqlite3_column_text (stmt, 2);
    peer_id = (const char *)sqlite3_column_text (stmt, 3);
    worktree = (const char *)sqlite3_column_text (stmt, 4);
    passwd = (const char *)sqlite3_column_text (stmt, 5);
    peer_addr = (const char *)sqlite3_column_text (stmt, 6);
    peer_port = (const char *)sqlite3_column_text (stmt, 7);
    email = (const char *)sqlite3_column_text (stmt, 8);

    task = clone_task_new (repo_id, peer_id, repo_name, 
                           token, worktree, passwd,
                           peer_addr, peer_port, email);
    task->manager = mgr;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (repo != NULL) {
        if (repo->head != NULL) {
            /* If repo exists and its head is set, we are done actually.
             * The task will be removed from db but still left in memory.
             */
            transition_state (task, CLONE_STATE_DONE);
            g_hash_table_insert (mgr->tasks, g_strdup(task->repo_id), task);
        } else {
            /* If head is not set, we haven't finished checkout.
             */
            g_hash_table_insert (mgr->tasks, g_strdup(task->repo_id), task);
            start_checkout (repo, task);
        }
    } else {
        /* Repo was not created last time. In this case, we just
         * restart from the very beginning.
         */
        if (!ccnet_peer_is_ready (seaf->ccnetrpc_client, task->peer_id)) {
            /* the relay is not ready yet */
            start_connect_task_relay (task, NULL);
        } else {
            start_index_or_transfer (mgr, task, NULL);
        }
        g_hash_table_insert (mgr->tasks, g_strdup(task->repo_id), task);
    }

    return TRUE;
}

int
seaf_clone_manager_init (SeafCloneManager *mgr)
{
    const char *sql;

    sql = "CREATE TABLE IF NOT EXISTS CloneTasks "
        "(repo_id TEXT, repo_name TEXT, "
        "token TEXT, dest_id TEXT,"
        "worktree_parent TEXT, passwd TEXT, "
        "server_addr TEXT, server_port TEXT, email TEXT);";
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    return 0;
}

static void
continue_task_when_peer_connected (CloneTask *task)
{
    if (ccnet_peer_is_ready (seaf->ccnetrpc_client, task->peer_id)) {
        start_index_or_transfer (task->manager, task, NULL);
    }
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
        if (task->state == CLONE_STATE_CONNECT) {
            continue_task_when_peer_connected (task);
        }
    }

    return TRUE;
}

int
seaf_clone_manager_start (SeafCloneManager *mgr)
{
    mgr->check_timer = ccnet_timer_new (check_connect_pulse, mgr,
                                        CHECK_CONNECT_INTERVAL * 1000);

    char *sql = "SELECT * FROM CloneTasks";
    if (sqlite_foreach_selected_row (mgr->db, sql, restart_task, mgr) < 0)
        return -1;

    g_signal_connect (seaf, "repo-fetched",
                      (GCallback)on_repo_fetched, mgr);

    return 0;
}

static int
save_task_to_db (SeafCloneManager *mgr, CloneTask *task)
{
    char *sql;

    if (task->passwd)
        sql = sqlite3_mprintf ("REPLACE INTO CloneTasks VALUES "
            "('%q', '%q', '%q', '%q', '%q', '%q', '%q', '%q', '%q')",
                                task->repo_id, task->repo_name,
                                task->token, task->peer_id,
                                task->worktree, task->passwd,
                                task->peer_addr, task->peer_port, task->email);
    else
        sql = sqlite3_mprintf ("REPLACE INTO CloneTasks VALUES "
            "('%q', '%q', '%q', '%q', '%q', NULL, '%q', '%q', '%q')",
                                task->repo_id, task->repo_name,
                                task->token, task->peer_id,
                                task->worktree, task->peer_addr,
                                task->peer_port, task->email);

    if (sqlite_query_exec (mgr->db, sql) < 0) {
        sqlite3_free (sql);
        return -1;
    }

    sqlite3_free (sql);
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

    return 0;
}

static void
transition_state (CloneTask *task, int new_state)
{
    seaf_message ("Transition clone state for %.8s from [%s] to [%s].\n",
                  task->repo_id,
                  state_str[task->state], state_str[new_state]);

    if (new_state == CLONE_STATE_DONE ||
        new_state == CLONE_STATE_ERROR ||
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
                  error_str[error]);

    /* Remove from db but leave in memory. */
    remove_task_from_db (task->manager, task->repo_id);

    task->state = CLONE_STATE_ERROR;
    task->error = error;
}

static int
add_transfer_task (SeafCloneManager *mgr, CloneTask *task, GError **error)
{
    task->tx_id = seaf_transfer_manager_add_download (seaf->transfer_mgr,
                                                      task->repo_id,
                                                      task->peer_id,
                                                      "fetch_head",
                                                      "master",
                                                      task->token,
                                                      error);
    if (!task->tx_id)
        return -1;

    return 0;
}

typedef struct {
    SeafCloneManager *mgr;
    CloneTask *task;
    gboolean success;
} IndexAux;

static void *
index_files_job (void *data)
{
    IndexAux *aux = data;
    CloneTask *task = aux->task;

    if (seaf_repo_index_worktree_files (task->repo_id, task->worktree,
                                        task->passwd, task->root_id) == 0)
        aux->success = TRUE;

    return data;
}

static void
index_files_done (void *result)
{
    IndexAux *aux = result;
    CloneTask *task = aux->task;

    if (!aux->success) {
        transition_to_error (task, CLONE_ERROR_INDEX);
        goto out;
    }

    if (task->state == CLONE_STATE_CANCEL_PENDING) {
        transition_state (task, CLONE_STATE_CANCELED);
        goto out;
    }

    if (add_transfer_task (aux->mgr, task, NULL) < 0) {
        transition_to_error (task, CLONE_ERROR_FETCH);
        goto out;
    }

    transition_state (task, CLONE_STATE_FETCH);

out:
    g_free (aux);
    return;
}

static gboolean
is_non_empty_directory (const char *path)
{
    GDir *dir;
    GError *error = NULL;
    gboolean ret = FALSE;

    dir = g_dir_open (path, 0, &error);
    if (dir != NULL && g_dir_read_name (dir) != NULL)
        ret = TRUE;
    if (dir)
        g_dir_close (dir);

    return ret;
}

static int
start_index_or_transfer (SeafCloneManager *mgr, CloneTask *task, GError **error)
{
    IndexAux *aux;
    int ret = 0;

    if (is_non_empty_directory (task->worktree)) {
        transition_state (task, CLONE_STATE_INDEX);

        aux = g_new0 (IndexAux, 1);
        aux->mgr = mgr;
        aux->task = task;

        ccnet_job_manager_schedule_job (seaf->job_mgr,
                                        index_files_job,
                                        index_files_done,
                                        aux);
    } else {
        ret = add_transfer_task (mgr, task, error);
        if (ret == 0)
            transition_state (task, CLONE_STATE_FETCH);
        else
            transition_to_error (task, CLONE_ERROR_FETCH);
    }

    return ret;
}

static void
start_connect_task_relay (CloneTask *task, GError **error)
{
    CcnetPeer *peer = ccnet_get_peer (seaf->ccnetrpc_client, task->peer_id);
    if (!peer) {
        /* clone from a new relay */
        GString *buf = NULL; 
        seaf_message ("add relay before clone, %s:%s\n",
                      task->peer_addr, task->peer_port);
        buf = g_string_new(NULL);
        g_string_append_printf (buf, "add-relay --id %s --addr %s:%s",
                                task->peer_id, task->peer_addr, task->peer_port);
        ccnet_send_command (seaf->session, buf->str, NULL, NULL);
        transition_state (task, CLONE_STATE_CONNECT);
        g_string_free (buf, TRUE);
    } else {
        /* The peer is added to ccnet already and will be connected,
         * only need to transition the state
         */
        transition_state (task, CLONE_STATE_CONNECT);
    }

    if (peer)
        g_object_unref (peer);
}

static gboolean
is_duplicate_task (SeafCloneManager *mgr, const char *repo_id)
{
    CloneTask *task = g_hash_table_lookup (mgr->tasks, repo_id);
    if (task != NULL &&
        task->state != CLONE_STATE_DONE &&
        task->state != CLONE_STATE_ERROR &&
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
            task->state == CLONE_STATE_ERROR ||
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
    if (rc < 0 && errno == ENOENT) {
        ret = wt;
        return ret;
    } else if (rc < 0 || !S_ISDIR(st.st_mode)) {
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

static gboolean
check_worktree_path (SeafCloneManager *mgr, const char *path, GError **error)
{
    GList *repos, *ptr;
    SeafRepo *repo;
    GHashTableIter iter;
    gpointer key, value;
    CloneTask *task;

    if (check_dir_inclusiveness (path, seaf->seaf_dir) != 0 ||
        /* It's OK if path is included by the default worktree parent. */
        check_dir_inclusiveness (path, seaf->worktree_dir) < 0 ||
        check_dir_inclusiveness (path, seaf->session->config_dir) != 0) {
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
            task->state == CLONE_STATE_ERROR ||
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
                 SeafRepo *repo,
                 const char *repo_id,
                 const char *peer_id,
                 const char *repo_name,
                 const char *token,
                 const char *passwd,
                 const char *worktree,
                 const char *peer_addr,
                 const char *peer_port,
                 const char *email,
                 GError **error)
{
    CloneTask *task;    

    task = clone_task_new (repo_id, peer_id, repo_name,
                           token, worktree, passwd,
                           peer_addr, peer_port, email);
    task->manager = mgr;

    if (save_task_to_db (mgr, task) < 0) {
        seaf_warning ("[Clone mgr] failed to save task.\n");
        clone_task_free (task);
        return NULL;
    }

    if (repo != NULL && repo->head == NULL) {
        /* Repo was downloaded but not checked out.
         * This can happen when the last checkout failed, the user
         * can then clone the repo again.
         */
        start_checkout (repo, task);
    } else if (!ccnet_peer_is_ready(seaf->ccnetrpc_client, task->peer_id)) {
        /* the relay is not connected yet */
        start_connect_task_relay (task, error);
        
    } else {
        start_index_or_transfer (mgr, task, error);
    }

    /* The old task for this repo will be freed. */
    g_hash_table_insert (mgr->tasks, g_strdup(task->repo_id), task);

    return g_strdup(repo_id);
}

char *
seaf_clone_manager_add_task (SeafCloneManager *mgr, 
                             const char *repo_id,
                             const char *peer_id,
                             const char *repo_name,
                             const char *token,
                             const char *passwd,
                             const char *magic,
                             const char *worktree_in,
                             const char *peer_addr,
                             const char *peer_port,
                             const char *email,
                             GError **error)
{
    SeafRepo *repo;
    char *worktree;
    char *ret;

    if (!seaf->started) {
        seaf_message ("System not started, skip adding clone task.\n");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);

    if (repo != NULL && repo->head != NULL) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Repo already exists");
        return NULL;
    }   

    if (is_duplicate_task (mgr, repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, 
                     "Task is already in progress");
        return NULL;
    }

    /* If magic is not given, check password before checkout. */
    if (passwd && magic && seaf_repo_verify_passwd(repo_id, passwd, magic) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Incorrect password");
        return NULL;
    }

    if (!check_worktree_path (mgr, worktree_in, error))
        return NULL;

    /* Return error if worktree_in conflicts with another repo or
     * is not a directory.
     */
    worktree = make_worktree (mgr, worktree_in, FALSE, error);
    if (!worktree) {
        return NULL;
    }

    ret = add_task_common (mgr, repo, repo_id, peer_id, repo_name, token, passwd,
                           worktree, peer_addr, peer_port, email, error);
    g_free (worktree);

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

    if (!check_worktree_path (mgr, worktree, error)) {
        g_free (worktree);
        return NULL;
    }

    return worktree;
}

char *
seaf_clone_manager_add_download_task (SeafCloneManager *mgr, 
                                      const char *repo_id,
                                      const char *peer_id,
                                      const char *repo_name,
                                      const char *token,
                                      const char *passwd,
                                      const char *magic,
                                      const char *wt_parent,
                                      const char *peer_addr,
                                      const char *peer_port,
                                      const char *email,
                                      GError **error)
{
    SeafRepo *repo;
    char *wt_tmp, *worktree;
    char *ret;

    if (!seaf->started) {
        seaf_message ("System not started, skip adding clone task.\n");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);

    if (repo != NULL && repo->head != NULL) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Repo already exists");
        return NULL;
    }   

    if (is_duplicate_task (mgr, repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, 
                     "Task is already in progress");
        return NULL;
    }

    /* If magic is not given, check password before checkout. */
    if (passwd && magic && seaf_repo_verify_passwd(repo_id, passwd, magic) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Incorrect password");
        return NULL;
    }

    wt_tmp = g_build_filename (wt_parent, repo_name, NULL);

    worktree = make_worktree_for_download (mgr, wt_tmp, error);
    if (!worktree) {
        g_free (wt_tmp);
        return NULL;
    }

    ret = add_task_common (mgr, repo, repo_id, peer_id, repo_name, token, passwd,
                           worktree, peer_addr, peer_port, email, error);
    g_free (worktree);
    g_free (wt_tmp);

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
        transition_state (task, CLONE_STATE_CANCELED);
        break;
    case CLONE_STATE_FETCH:
        seaf_transfer_manager_cancel_task (seaf->transfer_mgr,
                                           task->tx_id,
                                           TASK_TYPE_DOWNLOAD);
        transition_state (task, CLONE_STATE_CANCEL_PENDING);
        break;
    case CLONE_STATE_INDEX:
    case CLONE_STATE_CHECKOUT:
    case CLONE_STATE_MERGE:
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

int
seaf_clone_manager_remove_task (SeafCloneManager *mgr,
                                const char *repo_id)
{
    CloneTask *task;

    if (!seaf->started) {
        seaf_message ("System not started, skip removing clone task.\n");
        return -1;
    }

    task = g_hash_table_lookup (mgr->tasks, repo_id);
    if (!task)
        return -1;

    if (task->state != CLONE_STATE_DONE &&
        task->state != CLONE_STATE_ERROR &&
        task->state != CLONE_STATE_CANCELED) {
        seaf_warning ("[Clone mgr] cannot remove running task.\n");
        return -1;
    }

    if (task->tx_id)
        seaf_transfer_manager_remove_task (seaf->transfer_mgr,
                                           task->tx_id,
                                           TASK_TYPE_DOWNLOAD);

    /* On-disk task should have been removed. */

    g_hash_table_remove (mgr->tasks, repo_id);

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

typedef struct {
    CloneTask *task;
    SeafRepo *repo;
    gboolean success;
} MergeAux;

typedef struct {
    gboolean fast_forward;
    char root_id[41];
} CompareAux;

static gboolean
compare_root (SeafCommit *commit, void *data, gboolean *stop)
{
    CompareAux *aux = data;

    /* If we've found a match in another branch, stop traversing. */
    if (aux->fast_forward) {
        *stop = TRUE;
        return TRUE;
    }

    if (strcmp (commit->root_id, aux->root_id) == 0) {
        aux->fast_forward = TRUE;
        *stop = TRUE;
    }

    return TRUE;
}

static gboolean
check_fast_forward (SeafCommit *head, const char *root_id)
{
    CompareAux *aux = g_new0 (CompareAux, 1);
    gboolean ret;

    memcpy (aux->root_id, root_id, 41);
    if (!seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                   head->commit_id,
                                                   compare_root,
                                                   aux, FALSE)) {
        g_free (aux);
        return FALSE;
    }

    ret = aux->fast_forward;
    g_free (aux);
    return ret;
}

static int
real_merge (SeafRepo *repo, SeafCommit *head, CloneTask *task)
{
    struct merge_options opts;
    char index_path[SEAF_PATH_MAX];
    struct index_state istate;
    char *root_id = NULL;
    int clean;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", repo->manager->index_dir, repo->id);
    if (read_index_from (&istate, index_path) < 0) {
        seaf_warning ("Failed to load index.\n");
        return -1;
    }

    init_merge_options (&opts);
    opts.index = &istate;
    opts.worktree = task->worktree;
    opts.ancestor = "common ancestor";
    opts.branch1 = seaf->session->base.user_name;
    opts.branch2 = head->creator_name;
    opts.remote_head = head->commit_id;
    /* Don't need to check locked files on windows. */
    opts.force_merge = TRUE;
    if (repo->encrypted) {
        opts.crypt = seafile_crypt_new (repo->enc_version, 
                                        repo->enc_key, 
                                        repo->enc_iv);
    }

    /* Merge the downloaded branch with the current worktree contents.
     * EMPTY_SHA1 represents an empty common ancestor tree.
     */
    merge_recursive (&opts,
                     task->root_id, head->root_id, EMPTY_SHA1,
                     &clean, &root_id);
    g_free (root_id);

    /* Don't update index. If it was an unclean merge, updating the index
     * will generate a merge commit later. We don't want a merge commit.
     * We just want to "apply" the local changes to the remote head.
     */

    discard_index (&istate);
    g_free (opts.crypt);
    clear_merge_options (&opts);

    return 0;
}

static int
fast_forward_checkout (SeafRepo *repo, SeafCommit *head, CloneTask *task)
{
    SeafRepoManager *mgr = repo->manager;
    char index_path[SEAF_PATH_MAX];
    struct tree_desc trees[2];
    struct unpack_trees_options topts;
    struct index_state istate;
    int ret = 0;

    if (strcmp (head->root_id, task->root_id) == 0)
        return 0;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path) < 0) {
        seaf_warning ("Failed to load index.\n");
        return -1;
    }
    repo->index_corrupted = FALSE;

    fill_tree_descriptor (&trees[0], task->root_id);
    fill_tree_descriptor (&trees[1], head->root_id);

    memset(&topts, 0, sizeof(topts));
    topts.base = task->worktree;
    topts.head_idx = -1;
    topts.src_index = &istate;
    topts.update = 1;
    topts.merge = 1;
    topts.fn = twoway_merge;
    if (repo->encrypted) {
        topts.crypt = seafile_crypt_new (repo->enc_version, 
                                         repo->enc_key, 
                                         repo->enc_iv);
    }

    if (unpack_trees (2, trees, &topts) < 0) {
        seaf_warning ("Failed to merge commit %s with work tree.\n", head->commit_id);
        ret = -1;
        goto out;
    }

    if (update_worktree (&topts, FALSE,
                         head->commit_id,
                         head->creator_name,
                         NULL) < 0) {
        seaf_warning ("Failed to update worktree.\n");
        /* Still finishe checkout even have I/O errors. */
    }

    discard_index (&istate);
    istate = topts.result;

    if (update_index (&istate, index_path) < 0) {
        seaf_warning ("Failed to update index.\n");
        ret = -1;
    }

out:
    tree_desc_free (&trees[0]);
    tree_desc_free (&trees[1]);

    g_free (topts.crypt);

    discard_index (&istate);

    return ret;
}

static int
create_index_branch (SeafRepo *repo, const char *root_id)
{
    SeafCommit *commit = NULL;
    SeafBranch *branch = NULL;
    int ret = 0;

    commit = seaf_commit_new (NULL, repo->id, root_id,
                              repo->email ? repo->email
                              : seaf->session->base.user_name,
                              seaf->session->base.id,
                              "Temp commit for index", 0);
    seaf_repo_to_commit (repo, commit);
    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0) {
        seaf_warning ("Failed to add commit.\n");
        ret = -1;
        goto out;
    }

    branch = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "index");
    if (!branch) {
        branch = seaf_branch_new ("index", repo->id, commit->commit_id);
        if (seaf_branch_manager_add_branch (seaf->branch_mgr, branch) < 0) {
            seaf_warning ("Failed to add branch.\n");
            ret = -1;
            goto out;
        }
    } else {
        seaf_branch_set_commit (branch, commit->commit_id);
        seaf_branch_manager_update_branch (seaf->branch_mgr, branch);
    }

out:
    seaf_commit_unref (commit);
    seaf_branch_unref (branch);
    return ret;
}

static void *
merge_job (void *data)
{
    MergeAux *aux = data;
    CloneTask *task = aux->task;
    SeafRepo *repo = aux->repo;
    SeafBranch *local = NULL;
    SeafCommit *head = NULL;

    /* If we haven't indexed files in the worktree, index them now. */
    if (task->root_id[0] == 0) {
        if (seaf_repo_index_worktree_files (task->repo_id,
                                            task->worktree,
                                            task->passwd,
                                            task->root_id) < 0)
            return aux;
    }

    local = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "local");
    if (!local) {
        aux->success = FALSE;
        goto out;
    }

    head = seaf_commit_manager_get_commit (seaf->commit_mgr, local->commit_id);
    if (!head) {
        aux->success = FALSE;
        goto out;
    }

    if (check_fast_forward (head, task->root_id)) {
        seaf_debug ("[clone mgr] Fast forward.\n");
        if (fast_forward_checkout (repo, head, task) < 0)
            goto out;
    } else {
        if (real_merge (repo, head, task) < 0)
            goto out;

        /* Create a temp branch "index" which references to task->root_id,
         * so that new changes from the worktree won't be removed by GC.
         * This branch should be deleted on the first commit operation of
         * the repo.
         */
        if (create_index_branch (repo, task->root_id) < 0)
            goto out;
    }

    /* Save head id for GC. */
    seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                         repo->id,
                                         REPO_REMOTE_HEAD,
                                         head->commit_id);
    seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                         repo->id,
                                         REPO_LOCAL_HEAD,
                                         head->commit_id);

    aux->success = TRUE;

out:
    seaf_branch_unref (local);
    seaf_commit_unref (head);
    return aux;
}

static void
merge_job_done (void *data)
{
    MergeAux *aux = data;
    CloneTask *task = aux->task;
    SeafRepo *repo = aux->repo;
    SeafBranch *local = NULL;

    if (!aux->success) {
        goto error;
    }

    seaf_repo_manager_set_repo_worktree (repo->manager,
                                         repo,
                                         task->worktree);

    local = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "local");
    if (!local) {
        seaf_warning ("Cannot get branch local for repo %s(%.10s).\n",
                      repo->name, repo->id);
        goto error;
    }
    /* Set repo head to mark checkout done. */
    seaf_repo_set_head (repo, local);
    seaf_branch_unref (local);

    if (repo->auto_sync) {
        if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id) < 0) {
            seaf_warning ("failed to watch repo %s(%.10s).\n", repo->name, repo->id);
            goto error;
        }
    }

    if (task->state == CLONE_STATE_CANCEL_PENDING)
        transition_state (task, CLONE_STATE_CANCELED);
    else if (task->state == CLONE_STATE_MERGE) {
        transition_state (task, CLONE_STATE_DONE);
    }

    g_free (aux);
    return;

error:
    g_free (aux);
    transition_to_error (task, CLONE_ERROR_MERGE);
    return;
}

static void
start_checkout (SeafRepo *repo, CloneTask *task)
{
    if (repo->encrypted && task->passwd != NULL) {
        /* keep this password check to be compatible with old servers. */
        if (repo->enc_version >= 1 && 
            seaf_repo_verify_passwd (repo->id, task->passwd, repo->magic) < 0) {
            seaf_warning ("[Clone mgr] incorrect password.\n");
            transition_to_error (task, CLONE_ERROR_PASSWD);
            return;
        }

        if (seaf_repo_manager_set_repo_passwd (seaf->repo_mgr,
                                               repo,
                                               task->passwd) < 0) {
            seaf_warning ("[Clone mgr] failed to set passwd for %s.\n", repo->id);
            transition_to_error (task, CLONE_ERROR_INTERNAL);
            return;
        }
    } else if (repo->encrypted) {
        seaf_warning ("[Clone mgr] Password is empty for encrypted repo %s.\n",
                   repo->id);
        transition_to_error (task, CLONE_ERROR_PASSWD);
        return;
    }

    if (g_access (task->worktree, F_OK) != 0 &&
        g_mkdir_with_parents (task->worktree, 0777) < 0) {
        seaf_warning ("[clone mgr] Failed to create worktree %s.\n",
                      task->worktree);
        transition_to_error (task, CLONE_ERROR_CHECKOUT);
        return;
    }

    if (!is_non_empty_directory (task->worktree)) {
        transition_state (task, CLONE_STATE_CHECKOUT);
        seaf_repo_manager_add_checkout_task (seaf->repo_mgr,
                                             repo,
                                             task->worktree,
                                             on_checkout_done,
                                             task->manager);
    } else {
        MergeAux *aux = g_new0 (MergeAux, 1);
        aux->task = task;
        aux->repo = repo;

        transition_state (task, CLONE_STATE_MERGE);
        ccnet_job_manager_schedule_job (seaf->job_mgr,
                                        merge_job,
                                        merge_job_done,
                                        aux);
    }
}

static void
on_repo_fetched (SeafileSession *seaf,
                 TransferTask *tx_task,
                 SeafCloneManager *mgr)
{
    CloneTask *task;

    /* Only handle clone task. */
    if (!tx_task->is_clone)
        return;

    task = g_hash_table_lookup (mgr->tasks, tx_task->repo_id);
    g_return_if_fail (task != NULL);

    if (tx_task->state == TASK_STATE_CANCELED) {
        /* g_assert (task->state == CLONE_STATE_CANCEL_PENDING); */
        transition_state (task, CLONE_STATE_CANCELED);
        return;
    } else if (tx_task->state == TASK_STATE_ERROR) {
        transition_to_error (task, CLONE_ERROR_FETCH);
        return;
    }

    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr,
                                                 tx_task->repo_id);
    if (repo == NULL) {
        seaf_warning ("[Clone mgr] cannot find repo %s after fetched.\n", 
                   tx_task->repo_id);
        transition_to_error (task, CLONE_ERROR_INTERNAL);
        return;
    }

    seaf_repo_manager_set_repo_token (seaf->repo_mgr, repo, task->token);
    seaf_repo_manager_set_repo_email (seaf->repo_mgr, repo, task->email);
    seaf_repo_manager_set_repo_relay_info (seaf->repo_mgr, repo->id,
                                           task->peer_addr, task->peer_port);

    start_checkout (repo, task);
}

static void
on_checkout_done (CheckoutTask *ctask, SeafRepo *repo, void *data)
{
    SeafCloneManager *mgr = data;
    CloneTask *task = g_hash_table_lookup (mgr->tasks, repo->id);
    g_return_if_fail (task != NULL);

    if (!ctask->success) {
        transition_to_error (task, CLONE_ERROR_CHECKOUT);
        return;
    }

    if (task->state == CLONE_STATE_CANCEL_PENDING)
        transition_state (task, CLONE_STATE_CANCELED);
    else if (task->state == CLONE_STATE_CHECKOUT) {
        /* Save repo head if for GC. */
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
}
