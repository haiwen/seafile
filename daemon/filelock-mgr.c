/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <pthread.h>

#include "seafile-session.h"
#include "filelock-mgr.h"
#include "set-perm.h"
#include "log.h"

#include "db.h"

struct _FilelockMgrPriv {
    GHashTable *repo_locked_files;
    pthread_mutex_t hash_lock;
    sqlite3 *db;
    pthread_mutex_t db_lock;
};
typedef struct _FilelockMgrPriv FilelockMgrPriv;

typedef struct _LockInfo {
    int locked_by_me;
} LockInfo;

/* When a file is locked by me, it can have two reasons:
 * - Locked by the user manually
 * - Auto-Locked by Seafile when it detects Office opens the file.
 */
#define _LOCKED_MANUAL 1
#define _LOCKED_AUTO 2

struct _SeafFilelockManager *
seaf_filelock_manager_new (struct _SeafileSession *session)
{
    SeafFilelockManager *mgr = g_new0 (SeafFilelockManager, 1);
    FilelockMgrPriv *priv = g_new0 (FilelockMgrPriv, 1);

    mgr->session = session;
    mgr->priv = priv;

    priv->repo_locked_files = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                     g_free,
                                                     (GDestroyNotify)g_hash_table_destroy);

    pthread_mutex_init (&priv->hash_lock, NULL);
    pthread_mutex_init (&priv->db_lock, NULL);

    return mgr;
}

static void
lock_info_free (LockInfo *info)
{
    g_free (info);
}

static gboolean
load_locked_files (sqlite3_stmt *stmt, void *data)
{
    GHashTable *repo_locked_files = data, *files;
    const char *repo_id, *path;
    int locked_by_me;

    repo_id = (const char *)sqlite3_column_text (stmt, 0);
    path = (const char *)sqlite3_column_text (stmt, 1);
    locked_by_me = sqlite3_column_int (stmt, 2);

    files = g_hash_table_lookup (repo_locked_files, repo_id);
    if (!files) {
        files = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, (GDestroyNotify)lock_info_free);
        g_hash_table_insert (repo_locked_files, g_strdup(repo_id), files);
    }

    char *key = g_strdup(path);
    LockInfo *info = g_new0 (LockInfo, 1);
    info->locked_by_me = locked_by_me;
    g_hash_table_replace (files, key, info);

    return TRUE;
}

int
seaf_filelock_manager_init (SeafFilelockManager *mgr)
{
    char *db_path;
    sqlite3 *db;
    char *sql;

    db_path = g_build_filename (seaf->seaf_dir, "filelocks.db", NULL);
    if (sqlite_open_db (db_path, &db) < 0)
        return -1;
    g_free (db_path);
    mgr->priv->db = db;

    sql = "CREATE TABLE IF NOT EXISTS ServerLockedFiles ("
        "repo_id TEXT, path TEXT, locked_by_me INTEGER);";
    sqlite_query_exec (db, sql);

    sql = "CREATE INDEX IF NOT EXISTS server_locked_files_repo_id_idx "
        "ON ServerLockedFiles (repo_id);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS ServerLockedFilesTimestamp ("
        "repo_id TEXT, timestamp INTEGER, PRIMARY KEY (repo_id));";
    sqlite_query_exec (db, sql);

    sql = "SELECT repo_id, path, locked_by_me FROM ServerLockedFiles";

    pthread_mutex_lock (&mgr->priv->db_lock);
    pthread_mutex_lock (&mgr->priv->hash_lock);

    if (sqlite_foreach_selected_row (mgr->priv->db, sql,
                                     load_locked_files,
                                     mgr->priv->repo_locked_files) < 0) {
        pthread_mutex_unlock (&mgr->priv->db_lock);
        pthread_mutex_unlock (&mgr->priv->hash_lock);
        g_hash_table_destroy (mgr->priv->repo_locked_files);
        return -1;
    }

    pthread_mutex_unlock (&mgr->priv->hash_lock);
    pthread_mutex_unlock (&mgr->priv->db_lock);

    return 0;
}

static void
init_locks (gpointer key, gpointer value, gpointer user_data)
{
    char *repo_id = user_data;
    char *path = key;
    LockInfo *info = value;

    if (!info->locked_by_me) {
        seaf_filelock_manager_lock_wt_file (seaf->filelock_mgr,
                                            repo_id,
                                            path);
    }
}

int
seaf_filelock_manager_start (SeafFilelockManager *mgr)
{
    GHashTableIter iter;
    gpointer key, value;
    char *repo_id;
    GHashTable *locks;

    pthread_mutex_lock (&mgr->priv->hash_lock);

    g_hash_table_iter_init (&iter, mgr->priv->repo_locked_files);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        repo_id = key;
        locks = value;
        g_hash_table_foreach (locks, init_locks, repo_id);
    }

    pthread_mutex_unlock (&mgr->priv->hash_lock);

    return 0;
}

gboolean
seaf_filelock_manager_is_file_locked (SeafFilelockManager *mgr,
                                      const char *repo_id,
                                      const char *path)
{
    gboolean ret;

    pthread_mutex_lock (&mgr->priv->hash_lock);

    GHashTable *locks = g_hash_table_lookup (mgr->priv->repo_locked_files, repo_id);
    if (!locks) {
        pthread_mutex_unlock (&mgr->priv->hash_lock);
        return FALSE;
    }

    LockInfo *info = g_hash_table_lookup (locks, path);
    if (!info) {
        pthread_mutex_unlock (&mgr->priv->hash_lock);
        return FALSE;
    }
    ret = !info->locked_by_me;

    pthread_mutex_unlock (&mgr->priv->hash_lock);
    return ret;
}

gboolean
seaf_filelock_manager_is_file_locked_by_me (SeafFilelockManager *mgr,
                                            const char *repo_id,
                                            const char *path)
{
    gboolean ret;

    pthread_mutex_lock (&mgr->priv->hash_lock);

    GHashTable *locks = g_hash_table_lookup (mgr->priv->repo_locked_files, repo_id);
    if (!locks) {
        pthread_mutex_unlock (&mgr->priv->hash_lock);
        return FALSE;
    }

    LockInfo *info = g_hash_table_lookup (locks, path);
    if (!info) {
        pthread_mutex_unlock (&mgr->priv->hash_lock);
        return FALSE;
    }
    ret = (info->locked_by_me > 0);

    pthread_mutex_unlock (&mgr->priv->hash_lock);
    return ret;
}

int
seaf_filelock_manager_get_lock_status (SeafFilelockManager *mgr,
                                       const char *repo_id,
                                       const char *path)
{
    int ret;

    pthread_mutex_lock (&mgr->priv->hash_lock);

    GHashTable *locks = g_hash_table_lookup (mgr->priv->repo_locked_files, repo_id);
    if (!locks) {
        pthread_mutex_unlock (&mgr->priv->hash_lock);
        return FILE_NOT_LOCKED;
    }

    LockInfo *info = g_hash_table_lookup (locks, path);
    if (!info) {
        pthread_mutex_unlock (&mgr->priv->hash_lock);
        return FILE_NOT_LOCKED;
    }

    if (info->locked_by_me == _LOCKED_MANUAL)
        ret = FILE_LOCKED_BY_ME_MANUAL;
    else if (info->locked_by_me == _LOCKED_AUTO)
        ret = FILE_LOCKED_BY_ME_AUTO;
    else
        ret = FILE_LOCKED_BY_OTHERS;

    pthread_mutex_unlock (&mgr->priv->hash_lock);
    return ret;
}

void
seaf_filelock_manager_lock_wt_file (SeafFilelockManager *mgr,
                                    const char *repo_id,
                                    const char *path)
{
    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo)
        return;

    char *fullpath = g_build_filename (repo->worktree, path, NULL);
    if (seaf_util_exists (fullpath))
        seaf_set_path_permission (fullpath, SEAF_PATH_PERM_RO, FALSE);
    g_free (fullpath);
}

void
seaf_filelock_manager_unlock_wt_file (SeafFilelockManager *mgr,
                                      const char *repo_id,
                                      const char *path)
{
    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo)
        return;

    char *fullpath = g_build_filename (repo->worktree, path, NULL);

#ifdef WIN32
    if (seaf_util_exists (fullpath))
        seaf_unset_path_permission (fullpath, FALSE);
#else
    if (seaf_util_exists (fullpath))
        seaf_set_path_permission (fullpath, SEAF_PATH_PERM_RW, FALSE);
#endif
    g_free (fullpath);
}

static void
update_in_memory (SeafFilelockManager *mgr, const char *repo_id, GHashTable *new_locks)
{
    GHashTable *repo_hash = mgr->priv->repo_locked_files;

    pthread_mutex_lock (&mgr->priv->hash_lock);

    GHashTable *locks = g_hash_table_lookup (repo_hash, repo_id);

    if (!locks) {
        if (g_hash_table_size (new_locks) == 0) {
            pthread_mutex_unlock (&mgr->priv->hash_lock);
            return;
        }
        locks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                       g_free, (GDestroyNotify)lock_info_free);
        g_hash_table_insert (repo_hash, g_strdup(repo_id), locks);
    }

    GHashTableIter iter;
    gpointer key, value;
    gpointer new_key, new_val;
    char *path;
#ifdef WIN32
    char *fullpath;
#endif
    LockInfo *info;
    gboolean exists;
    int locked_by_me;
    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to find repo %s\n", repo_id);
        return;
    }

    g_hash_table_iter_init (&iter, locks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        path = key;
        info = value;

        exists = g_hash_table_lookup_extended (new_locks, path, &new_key, &new_val);
        if (!exists) {
#ifdef WIN32
            fullpath = g_build_path ("/", repo->worktree, path, NULL);
            seaf_sync_manager_add_refresh_path (seaf->sync_mgr, fullpath);
            g_free (fullpath);
#endif
            seaf_filelock_manager_unlock_wt_file (mgr, repo_id, path);
            g_hash_table_iter_remove (&iter);
        } else {
            locked_by_me = (int)(long)new_val;
            if (!info->locked_by_me && locked_by_me) {
#ifdef WIN32
                fullpath = g_build_path ("/", repo->worktree, path, NULL);
                seaf_sync_manager_add_refresh_path (seaf->sync_mgr, fullpath);
                g_free (fullpath);
#endif
                seaf_filelock_manager_unlock_wt_file (mgr, repo_id, path);
                info->locked_by_me = locked_by_me;
            } else if (info->locked_by_me && !locked_by_me) {
#ifdef WIN32
                fullpath = g_build_path ("/", repo->worktree, path, NULL);
                seaf_sync_manager_add_refresh_path (seaf->sync_mgr, fullpath);
                g_free (fullpath);
#endif
                seaf_filelock_manager_lock_wt_file (mgr, repo_id, path);
                info->locked_by_me = locked_by_me;
            }
        }
    }

    g_hash_table_iter_init (&iter, new_locks);
    while (g_hash_table_iter_next (&iter, &new_key, &new_val)) {
        path = new_key;
        locked_by_me = (int)(long)new_val;
        if (!g_hash_table_lookup (locks, path)) {
            info = g_new0 (LockInfo, 1);
            info->locked_by_me = locked_by_me;
            g_hash_table_insert (locks, g_strdup(path), info);
#ifdef WIN32
            fullpath = g_build_path ("/", repo->worktree, path, NULL);
            seaf_sync_manager_add_refresh_path (seaf->sync_mgr, fullpath);
            g_free (fullpath);
#endif
            if (!locked_by_me) {
                seaf_filelock_manager_lock_wt_file (mgr, repo_id, path);
            }
        }
    }

    pthread_mutex_unlock (&mgr->priv->hash_lock);
}

static gint
compare_paths (gconstpointer a, gconstpointer b)
{
    const char *patha = a, *pathb = b;

    return strcmp (patha, pathb);
}

static int
update_db (SeafFilelockManager *mgr, const char *repo_id)
{
    char *sql;
    sqlite3_stmt *stmt;
    GHashTable *locks;
    GList *paths, *ptr;
    char *path;
    LockInfo *info;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = "DELETE FROM ServerLockedFiles WHERE repo_id = ?";
    stmt = sqlite_query_prepare (mgr->priv->db, sql);
    sqlite3_bind_text (stmt, 1, repo_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step (stmt) != SQLITE_DONE) {
        seaf_warning ("Failed to remove server locked files for %.8s: %s.\n",
                      repo_id, sqlite3_errmsg (mgr->priv->db));
        sqlite3_finalize (stmt);
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return -1;
    }
    sqlite3_finalize (stmt);

    locks = g_hash_table_lookup (mgr->priv->repo_locked_files, repo_id);
    if (!locks || g_hash_table_size (locks) == 0) {
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return 0;
    }

    paths = g_hash_table_get_keys (locks);
    paths = g_list_sort (paths, compare_paths);

    sql = "INSERT INTO ServerLockedFiles (repo_id, path, locked_by_me) VALUES (?, ?, ?)";
    stmt = sqlite_query_prepare (mgr->priv->db, sql);

    for (ptr = paths; ptr; ptr = ptr->next) {
        path = ptr->data;
        info = g_hash_table_lookup (locks, path);

        sqlite3_bind_text (stmt, 1, repo_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 2, path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 3, info->locked_by_me);

        if (sqlite3_step (stmt) != SQLITE_DONE) {
            seaf_warning ("Failed to insert server file lock for %.8s: %s.\n",
                          repo_id, sqlite3_errmsg (mgr->priv->db));
            sqlite3_finalize (stmt);
            pthread_mutex_unlock (&mgr->priv->db_lock);
            return -1;
        }

        sqlite3_reset (stmt);
        sqlite3_clear_bindings (stmt);
    }

    sqlite3_finalize (stmt);
    g_list_free (paths);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return 0;
}

int
seaf_filelock_manager_update (SeafFilelockManager *mgr,
                              const char *repo_id,
                              GHashTable *new_locked_files)
{
    update_in_memory (mgr, repo_id, new_locked_files);

    int ret = update_db (mgr, repo_id);

    return ret;
}

int
seaf_filelock_manager_update_timestamp (SeafFilelockManager *mgr,
                                        const char *repo_id,
                                        gint64 timestamp)
{
    char sql[256];
    int ret;

    snprintf (sql, sizeof(sql),
              "REPLACE INTO ServerLockedFilesTimestamp VALUES ('%s', %"G_GINT64_FORMAT")",
              repo_id, timestamp);

    pthread_mutex_lock (&mgr->priv->db_lock);

    ret = sqlite_query_exec (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return ret;
}

gint64
seaf_filelock_manager_get_timestamp (SeafFilelockManager *mgr,
                                     const char *repo_id)
{
    char sql[256];
    gint64 ret;

    sqlite3_snprintf (sizeof(sql), sql,
                      "SELECT timestamp FROM ServerLockedFilesTimestamp WHERE repo_id = '%q'",
                      repo_id);

    pthread_mutex_lock (&mgr->priv->db_lock);

    ret = sqlite_get_int64 (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return ret;
}

int
seaf_filelock_manager_remove (SeafFilelockManager *mgr,
                              const char *repo_id)
{
    char *sql;
    sqlite3_stmt *stmt;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = "DELETE FROM ServerLockedFiles WHERE repo_id = ?";
    stmt = sqlite_query_prepare (mgr->priv->db, sql);
    sqlite3_bind_text (stmt, 1, repo_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step (stmt) != SQLITE_DONE) {
        seaf_warning ("Failed to remove server locked files for %.8s: %s.\n",
                      repo_id, sqlite3_errmsg (mgr->priv->db));
        sqlite3_finalize (stmt);
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return -1;
    }
    sqlite3_finalize (stmt);

    sql = "DELETE FROM ServerLockedFilesTimestamp WHERE repo_id = ?";
    stmt = sqlite_query_prepare (mgr->priv->db, sql);
    sqlite3_bind_text (stmt, 1, repo_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step (stmt) != SQLITE_DONE) {
        seaf_warning ("Failed to remove server locked files timestamp for %.8s: %s.\n",
                      repo_id, sqlite3_errmsg (mgr->priv->db));
        sqlite3_finalize (stmt);
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return -1;
    }
    sqlite3_finalize (stmt);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    pthread_mutex_lock (&mgr->priv->hash_lock);
    g_hash_table_remove (mgr->priv->repo_locked_files, repo_id);
    pthread_mutex_unlock (&mgr->priv->hash_lock);

    return 0;
}

#ifdef WIN32

static void
refresh_locked_path_status (const char *repo_id, const char *path)
{
    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo)
        return;

    char *fullpath = g_build_path ("/", repo->worktree, path, NULL);
    seaf_sync_manager_refresh_path (seaf->sync_mgr, fullpath);
    g_free (fullpath);
}

#endif

static int
mark_file_locked_in_db (SeafFilelockManager *mgr,
                        const char *repo_id,
                        const char *path,
                        int locked_by_me)
{
    char *sql;
    sqlite3_stmt *stmt;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = "REPLACE INTO ServerLockedFiles (repo_id, path, locked_by_me) VALUES (?, ?, ?)";
    stmt = sqlite_query_prepare (mgr->priv->db, sql);
    sqlite3_bind_text (stmt, 1, repo_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 2, path, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int (stmt, 3, locked_by_me);
    if (sqlite3_step (stmt) != SQLITE_DONE) {
        seaf_warning ("Failed to update server locked files for %.8s: %s.\n",
                      repo_id, sqlite3_errmsg (mgr->priv->db));
        sqlite3_finalize (stmt);
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return -1;
    }
    sqlite3_finalize (stmt);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return 0;
}

int
seaf_filelock_manager_mark_file_locked (SeafFilelockManager *mgr,
                                        const char *repo_id,
                                        const char *path,
                                        gboolean is_auto_lock)
{
    GHashTable *locks;
    LockInfo *info;

    pthread_mutex_lock (&mgr->priv->hash_lock);

    locks = g_hash_table_lookup (mgr->priv->repo_locked_files, repo_id);
    if (!locks) {
        locks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                       g_free, (GDestroyNotify)lock_info_free);
        g_hash_table_insert (mgr->priv->repo_locked_files,
                             g_strdup(repo_id), locks);
    }

    info = g_hash_table_lookup (locks, path);
    if (!info) {
        info = g_new0 (LockInfo, 1);
        g_hash_table_insert (locks, g_strdup(path), info);
    }

    if (!is_auto_lock)
        info->locked_by_me = _LOCKED_MANUAL;
    else
        info->locked_by_me = _LOCKED_AUTO;

    pthread_mutex_unlock (&mgr->priv->hash_lock);

#ifdef WIN32
    refresh_locked_path_status (repo_id, path);
#endif

    return mark_file_locked_in_db (mgr, repo_id, path, info->locked_by_me);
}

static int
remove_locked_file_from_db (SeafFilelockManager *mgr,
                            const char *repo_id,
                            const char *path)
{
    char *sql;
    sqlite3_stmt *stmt;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = "DELETE FROM ServerLockedFiles WHERE repo_id = ? AND path = ?";
    stmt = sqlite_query_prepare (mgr->priv->db, sql);
    sqlite3_bind_text (stmt, 1, repo_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 2, path, -1, SQLITE_TRANSIENT);
    if (sqlite3_step (stmt) != SQLITE_DONE) {
        seaf_warning ("Failed to remove locked file %s from %.8s: %s.\n",
                      path, repo_id, sqlite3_errmsg (mgr->priv->db));
        sqlite3_finalize (stmt);
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return -1;
    }
    sqlite3_finalize (stmt);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return 0;
}

int
seaf_filelock_manager_mark_file_unlocked (SeafFilelockManager *mgr,
                                          const char *repo_id,
                                          const char *path)
{
    GHashTable *locks;

    pthread_mutex_lock (&mgr->priv->hash_lock);

    locks = g_hash_table_lookup (mgr->priv->repo_locked_files, repo_id);
    if (!locks) {
        pthread_mutex_unlock (&mgr->priv->hash_lock);
        return 0;
    }

    g_hash_table_remove (locks, path);

    pthread_mutex_unlock (&mgr->priv->hash_lock);

#ifdef WIN32
    refresh_locked_path_status (repo_id, path);
#endif

    return remove_locked_file_from_db (mgr, repo_id, path);
}

void file_lock_info_free (FileLockInfo *info)
{
    if (!info)
        return;
    g_free (info->path);
    g_free (info);
}

static gboolean
collect_auto_locked_files (sqlite3_stmt *stmt, void *vret)
{
    GList **pret = vret;
    const char *repo_id, *path;
    FileLockInfo *info;

    repo_id = (const char *)sqlite3_column_text (stmt, 0);
    path = (const char *)sqlite3_column_text (stmt, 1);

    info = g_new0 (FileLockInfo, 1);
    memcpy (info->repo_id, repo_id, 36);
    info->path = g_strdup(path);

    *pret = g_list_prepend (*pret, info);

    return TRUE;
}

GList *
seaf_filelock_manager_get_auto_locked_files (SeafFilelockManager *mgr)
{
    char *sql;
    GList *ret = NULL;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = sqlite3_mprintf ("SELECT repo_id, path FROM ServerLockedFiles "
                           "WHERE locked_by_me = %d", _LOCKED_AUTO);
    sqlite_foreach_selected_row (mgr->priv->db, sql,
                                 collect_auto_locked_files,
                                 &ret);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    ret = g_list_reverse (ret);

    sqlite3_free (sql);
    return ret;
}
