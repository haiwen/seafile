/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <glib/gstdio.h>

#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#endif

#include <pthread.h>

#include "utils.h"
#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
#include "log.h"

#include "vc-utils.h"

#include "seafile-session.h"
#include "seafile-config.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "fs-mgr.h"
#include "seafile-error.h"
#include "seafile-crypt.h"
#include "index/index.h"
#include "index/cache-tree.h"
#include "diff-simple.h"
#include "change-set.h"

#include "db.h"

#include "seafile-object.h"

#define INDEX_DIR "index"
#define IGNORE_FILE "seafile-ignore.txt"

#ifdef HAVE_KEYSTORAGE_GK
#include "repokey/seafile-gnome-keyring.h"
#endif // HAVE_KEYSTORAGE_GK

#ifndef SEAFILE_CLIENT_VERSION
#define SEAFILE_CLIENT_VERSION PACKAGE_VERSION
#endif

struct _SeafRepoManagerPriv {
    GHashTable *repo_hash;
    sqlite3    *db;
    pthread_mutex_t db_lock;
    GHashTable *checkout_tasks_hash;
    pthread_rwlock_t lock;

    GHashTable *user_perms;     /* repo_id -> folder user perms */
    GHashTable *group_perms;    /* repo_id -> folder group perms */
    pthread_mutex_t perm_lock;

    GAsyncQueue *lock_office_job_queue;
};

static const char *ignore_table[] = {
    /* tmp files under Linux */
    "*~",
    /* Seafile's backup file */
    "*.sbak",
    /* Emacs tmp files */
    "#*#",
    /* windows image cache */
    "Thumbs.db",
    /* For Mac */
    ".DS_Store",
    "._*",
    NULL,
};

#define CONFLICT_PATTERN " \\(SFConflict .+\\)"

#define OFFICE_LOCK_PATTERN "~\\$(.+)$"

static GPatternSpec** ignore_patterns;
static GPatternSpec* office_temp_ignore_patterns[4];
static GRegex *conflict_pattern = NULL;
static GRegex *office_lock_pattern = NULL;

static SeafRepo *
load_repo (SeafRepoManager *manager, const char *repo_id);

static void load_repos (SeafRepoManager *manager, const char *seaf_dir);
static void seaf_repo_manager_del_repo_property (SeafRepoManager *manager,
                                                 const char *repo_id);

static int save_branch_repo_map (SeafRepoManager *manager, SeafBranch *branch);
static void save_repo_property (SeafRepoManager *manager,
                                const char *repo_id,
                                const char *key, const char *value);

static void
locked_file_free (LockedFile *file)
{
    if (!file)
        return;
    g_free (file->operation);
    g_free (file);
}

static gboolean
load_locked_file (sqlite3_stmt *stmt, void *data)
{
    GHashTable *ret = data;
    LockedFile *file;
    const char *path, *operation, *file_id;
    gint64 old_mtime;

    path = (const char *)sqlite3_column_text (stmt, 0);
    operation = (const char *)sqlite3_column_text (stmt, 1);
    old_mtime = sqlite3_column_int64 (stmt, 2);
    file_id = (const char *)sqlite3_column_text (stmt, 3);

    file = g_new0 (LockedFile, 1);
    file->operation = g_strdup(operation);
    file->old_mtime = old_mtime;
    if (file_id)
        memcpy (file->file_id, file_id, 40);

    g_hash_table_insert (ret, g_strdup(path), file);

    return TRUE;
}

LockedFileSet *
seaf_repo_manager_get_locked_file_set (SeafRepoManager *mgr, const char *repo_id)
{
    GHashTable *locked_files = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                      g_free,
                                                      (GDestroyNotify)locked_file_free);
    char sql[256];

    sqlite3_snprintf (sizeof(sql), sql,
                      "SELECT path, operation, old_mtime, file_id FROM LockedFiles "
                      "WHERE repo_id = '%q'",
                      repo_id);

    pthread_mutex_lock (&mgr->priv->db_lock);

    /* Ingore database error. We return an empty set on error. */
    sqlite_foreach_selected_row (mgr->priv->db, sql,
                                 load_locked_file, locked_files);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    LockedFileSet *ret = g_new0 (LockedFileSet, 1);
    ret->mgr = mgr;
    memcpy (ret->repo_id, repo_id, 36);
    ret->locked_files = locked_files;

    return ret;
}

void
locked_file_set_free (LockedFileSet *fset)
{
    if (!fset)
        return;
    g_hash_table_destroy (fset->locked_files);
    g_free (fset);
}

int
locked_file_set_add_update (LockedFileSet *fset,
                            const char *path,
                            const char *operation,
                            gint64 old_mtime,
                            const char *file_id)
{
    SeafRepoManager *mgr = fset->mgr;
    char *sql;
    sqlite3_stmt *stmt;
    LockedFile *file;
    gboolean exists;

    exists = (g_hash_table_lookup (fset->locked_files, path) != NULL);

    pthread_mutex_lock (&mgr->priv->db_lock);

    if (!exists) {
        seaf_debug ("New locked file record %.8s, %s, %s, %"
                    G_GINT64_FORMAT".\n",
                    fset->repo_id, path, operation, old_mtime);

        sql = "INSERT INTO LockedFiles VALUES (?, ?, ?, ?, ?, NULL)";
        stmt = sqlite_query_prepare (mgr->priv->db, sql);
        sqlite3_bind_text (stmt, 1, fset->repo_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 2, path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 3, operation, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64 (stmt, 4, old_mtime);
        sqlite3_bind_text (stmt, 5, file_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step (stmt) != SQLITE_DONE) {
            seaf_warning ("Failed to insert locked file %s to db: %s.\n",
                          path, sqlite3_errmsg (mgr->priv->db));
            sqlite3_finalize (stmt);
            pthread_mutex_unlock (&mgr->priv->db_lock);
            return -1;
        }
        sqlite3_finalize (stmt);

        file = g_new0 (LockedFile, 1);
        file->operation = g_strdup(operation);
        file->old_mtime = old_mtime;
        if (file_id)
            memcpy (file->file_id, file_id, 40);

        g_hash_table_insert (fset->locked_files, g_strdup(path), file);
    } else {
        seaf_debug ("Update locked file record %.8s, %s, %s.\n",
                    fset->repo_id, path, operation);

        /* If a UPDATE record exists, don't update the old_mtime.
         * We need to keep the old mtime when the locked file was first detected.
         */

        sql = "UPDATE LockedFiles SET operation = ?, file_id = ? "
            "WHERE repo_id = ? AND path = ?";
        stmt = sqlite_query_prepare (mgr->priv->db, sql);
        sqlite3_bind_text (stmt, 1, operation, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 2, file_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 3, fset->repo_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 4, path, -1, SQLITE_TRANSIENT);
        if (sqlite3_step (stmt) != SQLITE_DONE) {
            seaf_warning ("Failed to update locked file %s to db: %s.\n",
                          path, sqlite3_errmsg (mgr->priv->db));
            sqlite3_finalize (stmt);
            pthread_mutex_unlock (&mgr->priv->db_lock);
            return -1;
        }
        sqlite3_finalize (stmt);

        file = g_hash_table_lookup (fset->locked_files, path);
        g_free (file->operation);
        file->operation = g_strdup(operation);
        if (file_id)
            memcpy (file->file_id, file_id, 40);
    }

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return 0;
}

int
locked_file_set_remove (LockedFileSet *fset, const char *path, gboolean db_only)
{
    SeafRepoManager *mgr = fset->mgr;
    char *sql;
    sqlite3_stmt *stmt;

    if (g_hash_table_lookup (fset->locked_files, path) == NULL)
        return 0;

    seaf_debug ("Remove locked file record %.8s, %s.\n",
                fset->repo_id, path);

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = "DELETE FROM LockedFiles WHERE repo_id = ? AND path = ?";
    stmt = sqlite_query_prepare (mgr->priv->db, sql);
    sqlite3_bind_text (stmt, 1, fset->repo_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text (stmt, 2, path, -1, SQLITE_TRANSIENT);
    if (sqlite3_step (stmt) != SQLITE_DONE) {
        seaf_warning ("Failed to remove locked file %s from db: %s.\n",
                      path, sqlite3_errmsg (mgr->priv->db));
        sqlite3_finalize (stmt);
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return -1;
    }
    sqlite3_finalize (stmt);
    pthread_mutex_unlock (&mgr->priv->db_lock);

    if (!db_only)
        g_hash_table_remove (fset->locked_files, path);

    return 0;
}

LockedFile *
locked_file_set_lookup (LockedFileSet *fset, const char *path)
{
    return (LockedFile *) g_hash_table_lookup (fset->locked_files, path);
}

/* Folder permissions. */

FolderPerm *
folder_perm_new (const char *path, const char *permission)
{
    FolderPerm *perm = g_new0 (FolderPerm, 1);

    perm->path = g_strdup(path);
    perm->permission = g_strdup(permission);

    return perm;
}

void
folder_perm_free (FolderPerm *perm)
{
    if (!perm)
        return;

    g_free (perm->path);
    g_free (perm->permission);
    g_free (perm);
}

static GList *
folder_perm_list_copy (GList *perms)
{
    GList *ret = NULL, *ptr;
    FolderPerm *perm, *new_perm;

    for (ptr = perms; ptr; ptr = ptr->next) {
        perm = ptr->data;
        new_perm = folder_perm_new (perm->path, perm->permission);
        ret = g_list_append (ret, new_perm);
    }

    return ret;
}

static gint
comp_folder_perms (gconstpointer a, gconstpointer b)
{
    const FolderPerm *perm_a = a, *perm_b = b;

    return (strcmp (perm_b->path, perm_a->path));
}

int
seaf_repo_manager_update_folder_perms (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       FolderPermType type,
                                       GList *folder_perms)
{
    char *sql;
    sqlite3_stmt *stmt;
    GList *ptr;
    FolderPerm *perm;

    g_return_val_if_fail ((type == FOLDER_PERM_TYPE_USER ||
                           type == FOLDER_PERM_TYPE_GROUP),
                          -1);

    /* Update db. */

    pthread_mutex_lock (&mgr->priv->db_lock);

    if (type == FOLDER_PERM_TYPE_USER)
        sql = "DELETE FROM FolderUserPerms WHERE repo_id = ?";
    else
        sql = "DELETE FROM FolderGroupPerms WHERE repo_id = ?";
    stmt = sqlite_query_prepare (mgr->priv->db, sql);
    sqlite3_bind_text (stmt, 1, repo_id, -1, SQLITE_TRANSIENT);
    if (sqlite3_step (stmt) != SQLITE_DONE) {
        seaf_warning ("Failed to remove folder perms for %.8s: %s.\n",
                      repo_id, sqlite3_errmsg (mgr->priv->db));
        sqlite3_finalize (stmt);
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return -1;
    }
    sqlite3_finalize (stmt);

    if (!folder_perms) {
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return 0;
    }

    if (type == FOLDER_PERM_TYPE_USER)
        sql = "INSERT INTO FolderUserPerms VALUES (?, ?, ?)";
    else
        sql = "INSERT INTO FolderGroupPerms VALUES (?, ?, ?)";
    stmt = sqlite_query_prepare (mgr->priv->db, sql);

    for (ptr = folder_perms; ptr; ptr = ptr->next) {
        perm = ptr->data;

        sqlite3_bind_text (stmt, 1, repo_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 2, perm->path, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text (stmt, 3, perm->permission, -1, SQLITE_TRANSIENT);

        if (sqlite3_step (stmt) != SQLITE_DONE) {
            seaf_warning ("Failed to insert folder perms for %.8s: %s.\n",
                          repo_id, sqlite3_errmsg (mgr->priv->db));
            sqlite3_finalize (stmt);
            pthread_mutex_unlock (&mgr->priv->db_lock);
            return -1;
        }

        sqlite3_reset (stmt);
        sqlite3_clear_bindings (stmt);
    }

    sqlite3_finalize (stmt);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    /* Update in memory */
    GList *new, *old;
    new = folder_perm_list_copy (folder_perms);
    new = g_list_sort (new, comp_folder_perms);

    pthread_mutex_lock (&mgr->priv->perm_lock);
    if (type == FOLDER_PERM_TYPE_USER) {
        old = g_hash_table_lookup (mgr->priv->user_perms, repo_id);
        if (old)
            g_list_free_full (old, (GDestroyNotify)folder_perm_free);
        g_hash_table_insert (mgr->priv->user_perms, g_strdup(repo_id), new);
    } else if (type == FOLDER_PERM_TYPE_GROUP) {
        old = g_hash_table_lookup (mgr->priv->group_perms, repo_id);
        if (old)
            g_list_free_full (old, (GDestroyNotify)folder_perm_free);
        g_hash_table_insert (mgr->priv->group_perms, g_strdup(repo_id), new);
    }
    pthread_mutex_unlock (&mgr->priv->perm_lock);

    return 0;
}

static gboolean
load_folder_perm (sqlite3_stmt *stmt, void *data)
{
    GList **p_perms = data;
    const char *path, *permission;

    path = (const char *)sqlite3_column_text (stmt, 0);
    permission = (const char *)sqlite3_column_text (stmt, 1);

    FolderPerm *perm = folder_perm_new (path, permission);
    *p_perms = g_list_prepend (*p_perms, perm);

    return TRUE;
}

static GList *
load_folder_perms_for_repo (SeafRepoManager *mgr,
                            const char *repo_id,
                            FolderPermType type)
{
    GList *perms = NULL;
    char sql[256];

    g_return_val_if_fail ((type == FOLDER_PERM_TYPE_USER ||
                           type == FOLDER_PERM_TYPE_GROUP),
                          NULL);

    if (type == FOLDER_PERM_TYPE_USER)
        sqlite3_snprintf (sizeof(sql), sql,
                          "SELECT path, permission FROM FolderUserPerms "
                          "WHERE repo_id = '%q'",
                          repo_id);
    else
        sqlite3_snprintf (sizeof(sql), sql,
                          "SELECT path, permission FROM FolderGroupPerms "
                          "WHERE repo_id = '%q'",
                          repo_id);

    pthread_mutex_lock (&mgr->priv->db_lock);

    if (sqlite_foreach_selected_row (mgr->priv->db, sql,
                                     load_folder_perm, &perms) < 0) {
        pthread_mutex_unlock (&mgr->priv->db_lock);
        GList *ptr;
        for (ptr = perms; ptr; ptr = ptr->next)
            folder_perm_free ((FolderPerm *)ptr->data);
        g_list_free (perms);
        return NULL;
    }

    pthread_mutex_unlock (&mgr->priv->db_lock);

    /* Sort list in descending order by perm->path (longer path first). */
    perms = g_list_sort (perms, comp_folder_perms);

    return perms;
}

static void
init_folder_perms (SeafRepoManager *mgr)
{
    SeafRepoManagerPriv *priv = mgr->priv;
    GList *repo_ids = g_hash_table_get_keys (priv->repo_hash);
    GList *ptr;
    GList *perms;
    char *repo_id;

    priv->user_perms = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    priv->group_perms = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    pthread_mutex_init (&priv->perm_lock, NULL);

    for (ptr = repo_ids; ptr; ptr = ptr->next) {
        repo_id = ptr->data;
        perms = load_folder_perms_for_repo (mgr, repo_id, FOLDER_PERM_TYPE_USER);
        if (perms) {
            pthread_mutex_lock (&priv->perm_lock);
            g_hash_table_insert (priv->user_perms, g_strdup(repo_id), perms);
            pthread_mutex_unlock (&priv->perm_lock);
        }
        perms = load_folder_perms_for_repo (mgr, repo_id, FOLDER_PERM_TYPE_GROUP);
        if (perms) {
            pthread_mutex_lock (&priv->perm_lock);
            g_hash_table_insert (priv->group_perms, g_strdup(repo_id), perms);
            pthread_mutex_unlock (&priv->perm_lock);
        }
    }

    g_list_free (repo_ids);
}

static void
remove_folder_perms (SeafRepoManager *mgr, const char *repo_id)
{
    GList *perms = NULL;

    pthread_mutex_lock (&mgr->priv->perm_lock);

    perms = g_hash_table_lookup (mgr->priv->user_perms, repo_id);
    if (perms) {
        g_list_free_full (perms, (GDestroyNotify)folder_perm_free);
        g_hash_table_remove (mgr->priv->user_perms, repo_id);
    }

    perms = g_hash_table_lookup (mgr->priv->group_perms, repo_id);
    if (perms) {
        g_list_free_full (perms, (GDestroyNotify)folder_perm_free);
        g_hash_table_remove (mgr->priv->group_perms, repo_id);
    }

    pthread_mutex_unlock (&mgr->priv->perm_lock);
}

int
seaf_repo_manager_update_folder_perm_timestamp (SeafRepoManager *mgr,
                                                const char *repo_id,
                                                gint64 timestamp)
{
    char sql[256];
    int ret;

    snprintf (sql, sizeof(sql),
              "REPLACE INTO FolderPermTimestamp VALUES ('%s', %"G_GINT64_FORMAT")",
              repo_id, timestamp);

    pthread_mutex_lock (&mgr->priv->db_lock);

    ret = sqlite_query_exec (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return ret;
}

gint64
seaf_repo_manager_get_folder_perm_timestamp (SeafRepoManager *mgr,
                                             const char *repo_id)
{
    char sql[256];
    gint64 ret;

    sqlite3_snprintf (sizeof(sql), sql,
                      "SELECT timestamp FROM FolderPermTimestamp WHERE repo_id = '%q'",
                      repo_id);

    pthread_mutex_lock (&mgr->priv->db_lock);

    ret = sqlite_get_int64 (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return ret;
}

static char *
lookup_folder_perm (GList *perms, const char *path)
{
    GList *ptr;
    FolderPerm *perm;
    char *folder;
    int len;
    char *permission = NULL;

    for (ptr = perms; ptr; ptr = ptr->next) {
        perm = ptr->data;

        if (strcmp (perm->path, "/") != 0)
            folder = g_strconcat (perm->path, "/", NULL);
        else
            folder = g_strdup(perm->path);

        len = strlen(folder);
        if (strcmp (perm->path, path) == 0 || strncmp(folder, path, len) == 0) {
            permission = perm->permission;
            g_free (folder);
            break;
        }
        g_free (folder);
    }

    return permission;
}

static gboolean
is_path_writable (const char *repo_id,
                  gboolean is_repo_readonly,
                  const char *path)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *user_perms = NULL, *group_perms = NULL;
    char *permission = NULL;
    char *abs_path = NULL;

    pthread_mutex_lock (&mgr->priv->perm_lock);

    user_perms = g_hash_table_lookup (mgr->priv->user_perms, repo_id);
    group_perms = g_hash_table_lookup (mgr->priv->group_perms, repo_id);

    if (user_perms || group_perms)
        abs_path = g_strconcat ("/", path, NULL);

    if (user_perms)
        permission = lookup_folder_perm (user_perms, abs_path);
    if (!permission && group_perms)
        permission = lookup_folder_perm (group_perms, abs_path);

    pthread_mutex_unlock (&mgr->priv->perm_lock);

    g_free (abs_path);

    if (!permission)
        return !is_repo_readonly;

    if (strcmp (permission, "rw") == 0)
        return TRUE;
    else
        return FALSE;
}

gboolean
seaf_repo_manager_is_path_writable (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *path)
{
    SeafRepo *repo = seaf_repo_manager_get_repo (mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", repo_id);
        return FALSE;
    }

    return is_path_writable (repo_id, repo->is_readonly, path);
}

gboolean
is_repo_id_valid (const char *id)
{
    if (!id)
        return FALSE;

    return is_uuid_valid (id);
}

/*
 * Sync error related. These functions should belong to the sync-mgr module.
 * But since we have to store the errors in repo database, we have to put the code here.
 */

int
seaf_repo_manager_record_sync_error (const char *repo_id,
                                     const char *repo_name,
                                     const char *path,
                                     int error_id)
{
    char *sql;
    int ret;

    pthread_mutex_lock (&seaf->repo_mgr->priv->db_lock);

    if (path != NULL)
        sql = sqlite3_mprintf ("DELETE FROM FileSyncError WHERE repo_id='%q' AND path='%q'",
                               repo_id, path);
    else
        sql = sqlite3_mprintf ("DELETE FROM FileSyncError WHERE repo_id='%q' AND path IS NULL",
                               repo_id);
    ret = sqlite_query_exec (seaf->repo_mgr->priv->db, sql);
    sqlite3_free (sql);
    if (ret < 0)
        goto out;

    /* REPLACE INTO will update the primary key id automatically.
     * So new errors are always on top.
     */
    if (path != NULL)
        sql = sqlite3_mprintf ("INSERT INTO FileSyncError "
                               "(repo_id, repo_name, path, err_id, timestamp) "
                               "VALUES ('%q', '%q', '%q', %d, %lld)",
                               repo_id, repo_name, path, error_id, (gint64)time(NULL));
    else
        sql = sqlite3_mprintf ("INSERT INTO FileSyncError "
                               "(repo_id, repo_name, err_id, timestamp) "
                               "VALUES ('%q', '%q', %d, %lld)",
                               repo_id, repo_name, error_id, (gint64)time(NULL));
        
    ret = sqlite_query_exec (seaf->repo_mgr->priv->db, sql);
    sqlite3_free (sql);

out:
    pthread_mutex_unlock (&seaf->repo_mgr->priv->db_lock);
    return ret;
}

static gboolean
collect_file_sync_errors (sqlite3_stmt *stmt, void *data)
{
    GList **pret = data;
    const char *repo_id, *repo_name, *path;
    int id, err_id;
    gint64 timestamp;
    SeafileFileSyncError *error;

    id = sqlite3_column_int (stmt, 0);
    repo_id = (const char *)sqlite3_column_text (stmt, 1);
    repo_name = (const char *)sqlite3_column_text (stmt, 2);
    path = (const char *)sqlite3_column_text (stmt, 3);
    err_id = sqlite3_column_int (stmt, 4);
    timestamp = sqlite3_column_int64 (stmt, 5);

    error = g_object_new (SEAFILE_TYPE_FILE_SYNC_ERROR,
                          "id", id,
                          "repo_id", repo_id,
                          "repo_name", repo_name,
                          "path", path,
                          "err_id", err_id,
                          "timestamp", timestamp,
                          NULL);
    *pret = g_list_prepend (*pret, error);

    return TRUE;
}

int
seaf_repo_manager_del_file_sync_error_by_id (SeafRepoManager *mgr, int id)
{
    int ret = 0;    
    char *sql = NULL;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = sqlite3_mprintf ("DELETE FROM FileSyncError WHERE id=%d",
                           id);
    ret = sqlite_query_exec (mgr->priv->db, sql);
    sqlite3_free (sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return ret;
}

GList *
seaf_repo_manager_get_file_sync_errors (SeafRepoManager *mgr, int offset, int limit)
{
    GList *ret = NULL;
    char *sql;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = sqlite3_mprintf ("SELECT id, repo_id, repo_name, path, err_id, timestamp FROM "
                           "FileSyncError ORDER BY id DESC LIMIT %d OFFSET %d",
                           limit, offset);
    sqlite_foreach_selected_row (mgr->priv->db, sql,
                                 collect_file_sync_errors, &ret);
    sqlite3_free (sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    ret = g_list_reverse (ret);

    return ret;
}

/*
 * Record file-level sync errors and send system notification.
 */
void
send_file_sync_error_notification (const char *repo_id,
                                   const char *repo_name,
                                   const char *path,
                                   int err_id)
{
    if (!repo_name) {
        SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!repo)
            return;
        repo_name = repo->name;
    }

    seaf_repo_manager_record_sync_error (repo_id, repo_name, path, err_id);

    seaf_sync_manager_set_task_error_code (seaf->sync_mgr, repo_id, err_id);

    json_t *object;
    char *str;

    object = json_object ();
    json_object_set_new (object, "repo_id", json_string(repo_id));
    json_object_set_new (object, "repo_name", json_string(repo_name));
    json_object_set_new (object, "path", json_string(path));
    json_object_set_new (object, "err_id", json_integer(err_id));

    str = json_dumps (object, 0);

    seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                          "sync.error",
                                          str);

    free (str);
    json_decref (object);
}

SeafRepo*
seaf_repo_new (const char *id, const char *name, const char *desc)
{
    SeafRepo* repo;

    /* valid check */
  
    
    repo = g_new0 (SeafRepo, 1);
    memcpy (repo->id, id, 36);
    repo->id[36] = '\0';

    repo->name = g_strdup(name);
    repo->desc = g_strdup(desc);

    repo->worktree_invalid = TRUE;
    repo->auto_sync = 1;
    pthread_mutex_init (&repo->lock, NULL);

    return repo;
}

int
seaf_repo_check_worktree (SeafRepo *repo)
{
    SeafStat st;

    if (repo->worktree == NULL) {
        seaf_warning ("Worktree for repo '%s'(%.8s) is not set.\n",
                      repo->name, repo->id);
        return -1;
    }

    /* check repo worktree */
    if (g_access(repo->worktree, F_OK) < 0) {
        if (!repo->worktree_invalid) {
            seaf_warning ("Failed to access worktree %s for repo '%s'(%.8s)\n",
                          repo->worktree, repo->name, repo->id);
        }

        return -1;
    }

    if (seaf_stat(repo->worktree, &st) < 0) {
        seaf_warning ("Failed to stat worktree %s for repo '%s'(%.8s)\n",
                      repo->worktree, repo->name, repo->id);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        seaf_warning ("Worktree %s for repo '%s'(%.8s) is not a directory.\n",
                      repo->worktree, repo->name, repo->id);
        return -1;
    }

    return 0;
}


static gboolean
check_worktree_common (SeafRepo *repo)
{
    if (!repo->head) {
        seaf_warning ("Head for repo '%s'(%.8s) is not set.\n",
                      repo->name, repo->id);
        return FALSE;
    }

    if (seaf_repo_check_worktree (repo) < 0) {
        return FALSE;
    }

    return TRUE;
}

void
seaf_repo_free (SeafRepo *repo)
{
    if (repo->head) seaf_branch_unref (repo->head);

    g_free (repo->name);
    g_free (repo->desc);
    g_free (repo->category);
    g_free (repo->worktree);
    g_free (repo->relay_id);
    g_free (repo->email);
    g_free (repo->token);
    g_free (repo);
}

static void
set_head_common (SeafRepo *repo, SeafBranch *branch)
{
    if (repo->head)
        seaf_branch_unref (repo->head);
    repo->head = branch;
    seaf_branch_ref(branch);
}

int
seaf_repo_set_head (SeafRepo *repo, SeafBranch *branch)
{
    if (save_branch_repo_map (repo->manager, branch) < 0)
        return -1;
    set_head_common (repo, branch);
    return 0;
}

SeafCommit *
seaf_repo_get_head_commit (const char *repo_id)
{
    SeafRepo *repo;
    SeafCommit *head;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", repo_id);
        return NULL;
    }

    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo_id, repo->version,
                                           repo->head->commit_id);
    if (!head) {
        seaf_warning ("Failed to get head for repo %s.\n", repo_id);
        return NULL;
    }

    return head;
}

void
seaf_repo_from_commit (SeafRepo *repo, SeafCommit *commit)
{
    repo->name = g_strdup (commit->repo_name);
    repo->desc = g_strdup (commit->repo_desc);
    repo->encrypted = commit->encrypted;
    repo->last_modify = commit->ctime;
    memcpy (repo->root_id, commit->root_id, 40);
    if (repo->encrypted) {
        repo->enc_version = commit->enc_version;
        if (repo->enc_version == 1)
            memcpy (repo->magic, commit->magic, 32);
        else if (repo->enc_version == 2) {
            memcpy (repo->magic, commit->magic, 64);
            memcpy (repo->random_key, commit->random_key, 96);
        }
        else if (repo->enc_version == 3) {
            memcpy (repo->magic, commit->magic, 64);
            memcpy (repo->random_key, commit->random_key, 96);
            memcpy (repo->salt, commit->salt, 64);
        }
        else if (repo->enc_version == 4) {
            memcpy (repo->magic, commit->magic, 64);
            memcpy (repo->random_key, commit->random_key, 96);
            memcpy (repo->salt, commit->salt, 64);
        }
    }
    repo->no_local_history = commit->no_local_history;
    repo->version = commit->version;
}

void
seaf_repo_to_commit (SeafRepo *repo, SeafCommit *commit)
{
    commit->repo_name = g_strdup (repo->name);
    commit->repo_desc = g_strdup (repo->desc);
    commit->encrypted = repo->encrypted;
    if (commit->encrypted) {
        commit->enc_version = repo->enc_version;
        if (commit->enc_version == 1)
            commit->magic = g_strdup (repo->magic);
        else if (commit->enc_version == 2) {
            commit->magic = g_strdup (repo->magic);
            commit->random_key = g_strdup (repo->random_key);
        }
        else if (commit->enc_version == 3) {
            commit->magic = g_strdup (repo->magic);
            commit->random_key = g_strdup (repo->random_key);
            commit->salt = g_strdup (repo->salt);
        }
        else if (commit->enc_version == 4) {
            commit->magic = g_strdup (repo->magic);
            commit->random_key = g_strdup (repo->random_key);
            commit->salt = g_strdup (repo->salt);
        }
    }
    commit->no_local_history = repo->no_local_history;
    commit->version = repo->version;
}

static gboolean
need_to_sync_worktree_name (const char *repo_id)
{
    char *need_sync_wt_name = seaf_repo_manager_get_repo_property (seaf->repo_mgr,
                                                                   repo_id,
                                                                   REPO_SYNC_WORKTREE_NAME);
    gboolean ret = (g_strcmp0(need_sync_wt_name, "true") == 0);
    g_free (need_sync_wt_name);
    return ret;
}

static void
update_repo_worktree_name (SeafRepo *repo, const char *new_name, gboolean rewatch)
{
    char *dirname = NULL, *basename = NULL;
    char *new_worktree = NULL;

    seaf_message ("Update worktree folder name of repo %s to %s.\n",
                  repo->id, new_name);

    dirname = g_path_get_dirname (repo->worktree);
    if (g_strcmp0 (dirname, ".") == 0)
        return;
    basename = g_path_get_basename (repo->worktree);

    new_worktree = g_build_filename (dirname, new_name, NULL);

    /* This can possibly fail on Windows if some files are opened under the worktree.
     * The rename operation will be retried on next restart.
     */
    if (seaf_util_rename (repo->worktree, new_worktree) < 0) {
        seaf_warning ("Failed to rename worktree from %s to %s: %s.\n",
                      repo->worktree, new_worktree, strerror(errno));
        goto out;
    }

    if (seaf_repo_manager_set_repo_worktree (seaf->repo_mgr, repo, new_worktree) < 0) {
        goto out;
    }

    if (rewatch) {
        if (seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo->id) < 0) {
            seaf_warning ("Failed to unwatch repo %s old worktree.\n", repo->id);
            goto out;
        }

        if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree) < 0) {
            seaf_warning ("Failed to watch repo %s new worktree.\n", repo->id);
        }
    }

out:
    g_free (dirname);
    g_free (basename);
    g_free (new_worktree);
}

void
seaf_repo_set_name (SeafRepo *repo, const char *new_name)
{
    char *old_name = repo->name;
    repo->name = g_strdup(new_name);
    g_free (old_name);

    if (need_to_sync_worktree_name (repo->id))
        update_repo_worktree_name (repo, new_name, TRUE);
}

static gboolean
collect_commit (SeafCommit *commit, void *vlist, gboolean *stop)
{
    GList **commits = vlist;

    /* The traverse function will unref the commit, so we need to ref it.
     */
    seaf_commit_ref (commit);
    *commits = g_list_prepend (*commits, commit);
    return TRUE;
}

GList *
seaf_repo_get_commits (SeafRepo *repo)
{
    GList *branches;
    GList *ptr;
    SeafBranch *branch;
    GList *commits = NULL;

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        seaf_warning ("Failed to get branch list of repo %s.\n", repo->id);
        return NULL;
    }

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 repo->id,
                                                                 repo->version,
                                                                 branch->commit_id,
                                                                 collect_commit,
                                                                 &commits, FALSE);
        if (!res) {
            for (ptr = commits; ptr != NULL; ptr = ptr->next)
                seaf_commit_unref ((SeafCommit *)(ptr->data));
            g_list_free (commits);
            goto out;
        }
    }

    commits = g_list_reverse (commits);

out:
    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        seaf_branch_unref ((SeafBranch *)ptr->data);
    }
    return commits;
}

void
seaf_repo_set_readonly (SeafRepo *repo)
{
    repo->is_readonly = TRUE;
    save_repo_property (repo->manager, repo->id, REPO_PROP_IS_READONLY, "true");
}

void
seaf_repo_unset_readonly (SeafRepo *repo)
{
    repo->is_readonly = FALSE;
    save_repo_property (repo->manager, repo->id, REPO_PROP_IS_READONLY, "false");
}

gboolean
seaf_repo_manager_is_ignored_hidden_file (const char *filename)
{
    GPatternSpec **spec = ignore_patterns;

    while (*spec) {
        if (g_pattern_match_string(*spec, filename))
            return TRUE;
        spec++;
    }

    return FALSE;
}

static gboolean
should_ignore(const char *basepath, const char *filename, void *data)
{
    GPatternSpec **spec = ignore_patterns;
    GList *ignore_list = (GList *)data;

    if (!g_utf8_validate (filename, -1, NULL)) {
        seaf_warning ("File name %s contains non-UTF8 characters, skip.\n", filename);
        return TRUE;
    }

    /* Ignore file/dir if its name is too long. */
    if (strlen(filename) >= SEAF_DIR_NAME_LEN)
        return TRUE;

    if (strchr (filename, '/'))
        return TRUE;

    while (*spec) {
        if (g_pattern_match_string(*spec, filename))
            return TRUE;
        spec++;
    }

    if (!seaf->sync_extra_temp_file) {
        spec = office_temp_ignore_patterns;
        while (*spec) {
            if (g_pattern_match_string(*spec, filename))
                return TRUE;
            spec++;
        }
    }

    if (basepath) {
        char *fullpath = g_build_path ("/", basepath, filename, NULL);
        if (seaf_repo_check_ignore_file (ignore_list, fullpath)) {
            g_free (fullpath);
            return TRUE;
        }
        g_free (fullpath);
    }

    return FALSE;
}

#ifndef WIN32
static inline gboolean
has_trailing_space_or_period (const char *path)
{
    int len = strlen(path);
    if (path[len - 1] == ' ' || path[len - 1] == '.') {
        return TRUE;
    }

    return FALSE;
}

static gboolean
check_path_ignore_on_windows (const char *file_path)
{
    gboolean ret = FALSE;
    static char illegals[] = {'\\', ':', '*', '?', '"', '<', '>', '|', '\b', '\t'};
    char **components = g_strsplit (file_path, "/", -1);
    int n_comps = g_strv_length (components);
    int j = 0;
    char *file_name;
    int i;
    char c;

    for (; j < n_comps; ++j) {
        file_name = components[j];

        if (has_trailing_space_or_period (file_name)) {
            /* Ignore files/dir whose path has trailing spaces. It would cause
             * problem on windows. */
            /* g_debug ("ignore '%s' which contains trailing space in path\n", path); */
            ret = TRUE;
            goto out;
        }

        for (i = 0; i < G_N_ELEMENTS(illegals); i++) {
            if (strchr (file_name, illegals[i])) {
                ret = TRUE;
                goto out;
            }
        }

        for (c = 1; c <= 31; c++) {
            if (strchr (file_name, c)) {
                ret = TRUE;
                goto out;
            }
        }
    }

out:
    g_strfreev (components);

    return ret;
}
#endif

static int
index_cb (const char *repo_id,
          int version,
          const char *path,
          unsigned char sha1[],
          SeafileCrypt *crypt,
          gboolean write_data)
{
    gint64 size;

    /* Check in blocks and get object ID. */
    if (seaf_fs_manager_index_blocks (seaf->fs_mgr, repo_id, version,
                                      path, sha1, &size, crypt, write_data, !seaf->disable_block_hash) < 0) {
        seaf_warning ("Failed to index file %s.\n", path);
        return -1;
    }
    return 0;
}

#define MAX_COMMIT_SIZE 100 * (1 << 20) /* 100MB */

typedef struct _AddOptions {
    LockedFileSet *fset;
    ChangeSet *changeset;
    gboolean is_repo_ro;
    gboolean startup_scan;
} AddOptions;

static int
add_file (const char *repo_id,
          int version,
          const char *modifier,
          struct index_state *istate, 
          const char *path,
          const char *full_path,
          SeafStat *st,
          SeafileCrypt *crypt,
          gint64 *total_size,
          GQueue **remain_files,
          AddOptions *options)
{
    gboolean added = FALSE;
    int ret = 0;
    gboolean is_writable = TRUE, is_locked = FALSE;
    struct cache_entry *ce;
    char *base_name = NULL;

    if (options)
        is_writable = is_path_writable(repo_id,
                                       options->is_repo_ro, path);

    is_locked = seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                      repo_id, path);
    if (is_locked && options && !(options->startup_scan)) {
        /* send_sync_error_notification (repo_id, NULL, path, */
        /*                               SYNC_ERROR_ID_FILE_LOCKED); */
    }

    if (options && options->startup_scan) {
        SyncStatus status;

        ce = index_name_exists (istate, path, strlen(path), 0);
        if (!ce || ie_match_stat(ce, st, 0) != 0)
            status = SYNC_STATUS_SYNCING;
        else
            status = SYNC_STATUS_SYNCED;

        /* Don't set "syncing" status for read-only path. */
        if (status == SYNC_STATUS_SYNCED || (is_writable && !is_locked))
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  repo_id,
                                                  path,
                                                  S_IFREG,
                                                  status,
                                                  FALSE);
        /* send an error notification for read-only repo when modifying a file. */
        if (status == SYNC_STATUS_SYNCING && !is_writable)
            send_file_sync_error_notification (repo_id, NULL, path,
                                               SYNC_ERROR_ID_UPDATE_TO_READ_ONLY_REPO);
    }

    if (!is_writable || is_locked)
        return ret;

#if defined WIN32 || defined __APPLE__
    if (options && options->fset) {
        LockedFile *file = locked_file_set_lookup (options->fset, path);
        if (file) {
            if (strcmp (file->operation, LOCKED_OP_DELETE) == 0) {
                /* Only remove the lock record if the file is changed. */
                if (st->st_mtime == file->old_mtime) {
                    return ret;
                }
                locked_file_set_remove (options->fset, path, FALSE);
            } else if (strcmp (file->operation, LOCKED_OP_UPDATE) == 0) {
                return ret;
            }
        }
    }
#endif

#ifndef WIN32
    base_name = g_path_get_basename(full_path);
    if (!seaf->hide_windows_incompatible_path_notification &&
        check_path_ignore_on_windows (base_name)) {

        send_file_sync_error_notification (repo_id, NULL, path,
                                           SYNC_ERROR_ID_INVALID_PATH_ON_WINDOWS);
    }
    g_free (base_name);
#endif

    if (!remain_files) {
        ret = add_to_index (repo_id, version, istate, path, full_path,
                            st, 0, crypt, index_cb, modifier, &added);
        if (!added) {
            /* If the contents of the file doesn't change, move it to
               synced status.
            */
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  repo_id,
                                                  path,
                                                  S_IFREG,
                                                  SYNC_STATUS_SYNCED,
                                                  FALSE);
        } else {
            if (total_size)
                *total_size += (gint64)(st->st_size);
            if (options && options->changeset) {
                /* ce may be updated. */
                ce = index_name_exists (istate, path, strlen(path), 0);
                add_to_changeset (options->changeset,
                                  DIFF_STATUS_ADDED,
                                  ce->sha1,
                                  st,
                                  modifier,
                                  path,
                                  NULL);
            }
        }
    } else if (*remain_files == NULL) {
        ret = add_to_index (repo_id, version, istate, path, full_path,
                            st, 0, crypt, index_cb, modifier, &added);
        if (added) {
            *total_size += (gint64)(st->st_size);
            if (*total_size >= MAX_COMMIT_SIZE)
                *remain_files = g_queue_new ();
        } else {
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  repo_id,
                                                  path,
                                                  S_IFREG,
                                                  SYNC_STATUS_SYNCED,
                                                  FALSE);
        }
        if (added && options && options->changeset) {
            /* ce may be updated. */
            ce = index_name_exists (istate, path, strlen(path), 0);
            add_to_changeset (options->changeset,
                              DIFF_STATUS_ADDED,
                              ce->sha1,
                              st,
                              modifier,
                              path,
                              NULL);
        }
    } else {
        *total_size += (gint64)(st->st_size);
        g_queue_push_tail (*remain_files, g_strdup(path));
    }

    if (ret < 0) {
        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              repo_id,
                                              path,
                                              S_IFREG,
                                              SYNC_STATUS_ERROR,
                                              TRUE);
        send_file_sync_error_notification (repo_id, NULL, path,
                                           SYNC_ERROR_ID_INDEX_ERROR);
    }

    return ret;
}

typedef struct AddParams {
    const char *repo_id;
    int version;
    const char *modifier;
    struct index_state *istate;
    const char *worktree;
    SeafileCrypt *crypt;
    gboolean ignore_empty_dir;
    GList *ignore_list;
    gint64 *total_size;
    GQueue **remain_files;
    AddOptions *options;
} AddParams;

#ifndef WIN32

static int
add_dir_recursive (const char *path, const char *full_path, SeafStat *st,
                   AddParams *params, gboolean ignored)
{
    AddOptions *options = params->options;
    GDir *dir;
    const char *dname;
    char *subpath, *full_subpath;
    int n, total;
    gboolean is_writable = TRUE;
    struct stat sub_st;
    char *base_name = NULL;

    dir = g_dir_open (full_path, 0, NULL);
    if (!dir) {
        seaf_warning ("Failed to open dir %s: %s.\n", full_path, strerror(errno));

        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              params->repo_id,
                                              path,
                                              S_IFDIR,
                                              SYNC_STATUS_ERROR,
                                              TRUE);

        return 0;
    }

    base_name = g_path_get_basename(full_path);
    if (!seaf->hide_windows_incompatible_path_notification &&
        check_path_ignore_on_windows (base_name)) {

        send_file_sync_error_notification (params->repo_id, NULL, path,
                                           SYNC_ERROR_ID_INVALID_PATH_ON_WINDOWS);
    }
    g_free (base_name);

    n = 0;
    total = 0;
    while ((dname = g_dir_read_name(dir)) != NULL) {
        ++total;

#ifdef __APPLE__
        char *norm_dname = g_utf8_normalize (dname, -1, G_NORMALIZE_NFC);
        subpath = g_build_path (PATH_SEPERATOR, path, norm_dname, NULL);
        g_free (norm_dname);
#else
        subpath = g_build_path (PATH_SEPERATOR, path, dname, NULL);
#endif
        full_subpath = g_build_filename (params->worktree, subpath, NULL);

        if (stat (full_subpath, &sub_st) < 0) {
            seaf_warning ("Failed to stat %s: %s.\n", full_subpath, strerror(errno));
            g_free (subpath);
            g_free (full_subpath);
            continue;
        }

        if (ignored || should_ignore(full_path, dname, params->ignore_list)) {
            if (options && options->startup_scan) {
                if (S_ISDIR(sub_st.st_mode))
                    add_dir_recursive (subpath, full_subpath, &sub_st, params, TRUE);
                else
                    seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                          params->repo_id,
                                                          subpath,
                                                          S_IFREG,
                                                          SYNC_STATUS_IGNORED,
                                                          TRUE);
            }
            g_free (subpath);
            g_free (full_subpath);
            continue;
        }

        ++n;

        if (S_ISDIR(sub_st.st_mode))
            add_dir_recursive (subpath, full_subpath, &sub_st, params, FALSE);
        else if (S_ISREG(sub_st.st_mode))
            add_file (params->repo_id,
                      params->version,
                      params->modifier,
                      params->istate,
                      subpath,
                      full_subpath,
                      &sub_st,
                      params->crypt,
                      params->total_size,
                      params->remain_files,
                      params->options);

        g_free (subpath);
        g_free (full_subpath);
    }
    g_dir_close (dir);

    if (ignored) {
        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              params->repo_id,
                                              path,
                                              S_IFDIR,
                                              SYNC_STATUS_IGNORED,
                                              TRUE);
        return 0;
    }

    if (options)
        is_writable = is_path_writable(params->repo_id,
                                       options->is_repo_ro, path);

    /* Update active path status for empty dir */
    if (options && options->startup_scan && total == 0) {
        SyncStatus status;
        struct cache_entry *ce = index_name_exists (params->istate, path,
                                                    strlen(path), 0);
        if (!ce)
            status = SYNC_STATUS_SYNCING;
        else
            status = SYNC_STATUS_SYNCED;


        if (status == SYNC_STATUS_SYNCED || is_writable)
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  params->repo_id,
                                                  path,
                                                  S_IFDIR,
                                                  status,
                                                  FALSE);
    }

    if (n == 0 && path[0] != 0 && is_writable) {
        if (!params->remain_files || *(params->remain_files) == NULL) {
            int rc = add_empty_dir_to_index (params->istate, path, st);
            if (rc == 1 && options && options->changeset) {
                unsigned char allzero[20] = {0};
                add_to_changeset (options->changeset,
                                  DIFF_STATUS_DIR_ADDED,
                                  allzero,
                                  st,
                                  NULL,
                                  path,
                                  NULL);
            }
        } else
            g_queue_push_tail (*(params->remain_files), g_strdup(path));
    }

    return 0;
}

/*
 * @remain_files: returns the files haven't been added under this path.
 *                If it's set to NULL, no partial commit will be created.
 */
static int
add_recursive (const char *repo_id,
               int version,
               const char *modifier,
               struct index_state *istate, 
               const char *worktree,
               const char *path,
               SeafileCrypt *crypt,
               gboolean ignore_empty_dir,
               GList *ignore_list,
               gint64 *total_size,
               GQueue **remain_files,
               AddOptions *options)
{
    char *full_path;
    SeafStat st;

    full_path = g_build_path (PATH_SEPERATOR, worktree, path, NULL);
    if (seaf_stat (full_path, &st) < 0) {
        /* Ignore broken symlinks on Linux and Mac OS X */
        if (lstat (full_path, &st) == 0 && S_ISLNK(st.st_mode)) {
            g_free (full_path);
            return 0;
        }
        seaf_warning ("Failed to stat %s.\n", full_path);
        g_free (full_path);
        /* Ignore error. */

        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              repo_id,
                                              path,
                                              0,
                                              SYNC_STATUS_ERROR,
                                              TRUE);

        return 0;
    }

    if (S_ISREG(st.st_mode)) {
        add_file (repo_id,
                  version,
                  modifier,
                  istate,
                  path,
                  full_path,
                  &st,
                  crypt,
                  total_size,
                  remain_files,
                  options);
    } else if (S_ISDIR(st.st_mode)) {
        AddParams params = {
            .repo_id = repo_id,
            .version = version,
            .modifier = modifier,
            .istate = istate,
            .worktree = worktree,
            .crypt = crypt,
            .ignore_empty_dir = ignore_empty_dir,
            .ignore_list = ignore_list,
            .total_size = total_size,
            .remain_files = remain_files,
            .options = options,
        };

        add_dir_recursive (path, full_path, &st, &params, FALSE);
    }

    g_free (full_path);
    return 0;
}

static gboolean
is_empty_dir (const char *path, GList *ignore_list)
{
    GDir *dir;
    const char *dname;
    gboolean ret = TRUE;

    dir = g_dir_open (path, 0, NULL);
    if (!dir) {
        return FALSE;
    }

    while ((dname = g_dir_read_name(dir)) != NULL) {
        if (!should_ignore(path, dname, ignore_list)) {
            ret = FALSE;
            break;
        }
    }
    g_dir_close (dir);

    return ret;
}

#else

typedef struct IterCBData {
    AddParams *add_params;
    const char *parent;
    const char *full_parent;
    int n;

    /* If parent dir is ignored, all children are ignored too. */
    gboolean ignored;
} IterCBData;

static int
add_dir_recursive (const char *path, const char *full_path, SeafStat *st,
                   AddParams *params, gboolean ignored);

static int
iter_dir_cb (wchar_t *full_parent_w,
             WIN32_FIND_DATAW *fdata,
             void *user_data,
             gboolean *stop)
{
    IterCBData *data = user_data;
    AddParams *params = data->add_params;
    AddOptions *options = params->options;
    char *dname = NULL, *path = NULL, *full_path = NULL;
    SeafStat st;
    int ret = 0;

    dname = g_utf16_to_utf8 (fdata->cFileName, -1, NULL, NULL, NULL);
    if (!dname) {
        goto out;
    }

    path = g_build_path ("/", data->parent, dname, NULL);
    full_path = g_build_path ("/", params->worktree, path, NULL);

    seaf_stat_from_find_data (fdata, &st);

    if (data->ignored ||
        should_ignore(data->full_parent, dname, params->ignore_list)) {
        if (options && options->startup_scan) {
            if (fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                add_dir_recursive (path, full_path, &st, params, TRUE);
            else
                seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                      params->repo_id,
                                                      path,
                                                      S_IFREG,
                                                      SYNC_STATUS_IGNORED,
                                                      TRUE);
        }
        goto out;
    }

    if (fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        ret = add_dir_recursive (path, full_path, &st, params, FALSE);
    else
        ret = add_file (params->repo_id,
                        params->version,
                        params->modifier,
                        params->istate,
                        path,
                        full_path,
                        &st,
                        params->crypt,
                        params->total_size,
                        params->remain_files,
                        params->options);

    ++(data->n);

out:
    g_free (dname);
    g_free (path);
    g_free (full_path);

    return 0;
}

static int
add_dir_recursive (const char *path, const char *full_path, SeafStat *st,
                   AddParams *params, gboolean ignored)
{
    AddOptions *options = params->options;
    IterCBData data;
    wchar_t *full_path_w;
    int ret = 0;
    gboolean is_writable = TRUE;

    memset (&data, 0, sizeof(data));
    data.add_params = params;
    data.parent = path;
    data.full_parent = full_path;
    data.ignored = ignored;

    full_path_w = win32_long_path (full_path);
    ret = traverse_directory_win32 (full_path_w, iter_dir_cb, &data);
    g_free (full_path_w);

    /* Ignore traverse dir error. */
    if (ret < 0) {
        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              params->repo_id,
                                              path,
                                              S_IFDIR,
                                              SYNC_STATUS_ERROR,
                                              TRUE);
        return 0;
    }

    if (ignored) {
        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              params->repo_id,
                                              path,
                                              S_IFDIR,
                                              SYNC_STATUS_IGNORED,
                                              TRUE);
        return 0;
    }

    if (options)
        is_writable = is_path_writable(params->repo_id,
                                        options->is_repo_ro, path);

    /* Update active path status for empty dir */
    if (options && options->startup_scan && ret == 0) {
        SyncStatus status;
        struct cache_entry *ce = index_name_exists (params->istate, path,
                                                    strlen(path), 0);
        if (!ce)
            status = SYNC_STATUS_SYNCING;
        else
            status = SYNC_STATUS_SYNCED;


        if (status == SYNC_STATUS_SYNCED || is_writable)
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  params->repo_id,
                                                  path,
                                                  S_IFDIR,
                                                  status,
                                                  FALSE);
    }

    if (data.n == 0 && path[0] != 0 && !params->ignore_empty_dir && is_writable) {
        if (!params->remain_files || *(params->remain_files) == NULL) {
            int rc = add_empty_dir_to_index (params->istate, path, st);
            if (rc == 1 && options && options->changeset) {
                unsigned char allzero[20] = {0};
                add_to_changeset (options->changeset,
                                  DIFF_STATUS_DIR_ADDED,
                                  allzero,
                                  st,
                                  NULL,
                                  path,
                                  NULL);
            }
        } else
            g_queue_push_tail (*(params->remain_files), g_strdup(path));
    }

    return ret;
}

static int
add_recursive (const char *repo_id,
               int version,
               const char *modifier,
               struct index_state *istate, 
               const char *worktree,
               const char *path,
               SeafileCrypt *crypt,
               gboolean ignore_empty_dir,
               GList *ignore_list,
               gint64 *total_size,
               GQueue **remain_files,
               AddOptions *options)
{
    char *full_path;
    SeafStat st;
    int ret = 0;

    full_path = g_build_path (PATH_SEPERATOR, worktree, path, NULL);
    if (seaf_stat (full_path, &st) < 0) {
        seaf_warning ("Failed to stat %s.\n", full_path);
        g_free (full_path);
        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              repo_id,
                                              path,
                                              0,
                                              SYNC_STATUS_ERROR,
                                              TRUE);
        /* Ignore error */
        return 0;
    }

    if (S_ISREG(st.st_mode)) {
        ret = add_file (repo_id,
                        version,
                        modifier,
                        istate, 
                        path,
                        full_path,
                        &st,
                        crypt,
                        total_size,
                        remain_files,
                        options);
    } else if (S_ISDIR(st.st_mode)) {
        AddParams params = {
            .repo_id = repo_id,
            .version = version,
            .modifier = modifier,
            .istate = istate,
            .worktree = worktree,
            .crypt = crypt,
            .ignore_empty_dir = ignore_empty_dir,
            .ignore_list = ignore_list,
            .total_size = total_size,
            .remain_files = remain_files,
            .options = options,
        };

        ret = add_dir_recursive (path, full_path, &st, &params, FALSE);
    }

    g_free (full_path);
    return ret;
}

static gboolean
is_empty_dir (const char *path, GList *ignore_list)
{
    WIN32_FIND_DATAW fdata;
    HANDLE handle;
    wchar_t *pattern;
    wchar_t *path_w;
    char *dname;
    int path_len_w;
    DWORD error;
    gboolean ret = TRUE;

    path_w = win32_long_path (path);

    path_len_w = wcslen(path_w);

    pattern = g_new0 (wchar_t, (path_len_w + 3));
    wcscpy (pattern, path_w);
    wcscat (pattern, L"\\*");

    handle = FindFirstFileW (pattern, &fdata);
    if (handle == INVALID_HANDLE_VALUE) {
        seaf_warning ("FindFirstFile failed %s: %lu.\n",
                      path, GetLastError());
        ret = FALSE;
        goto out;
    }

    do {
        if (wcscmp (fdata.cFileName, L".") == 0 ||
            wcscmp (fdata.cFileName, L"..") == 0)
            continue;

        dname = g_utf16_to_utf8 (fdata.cFileName, -1, NULL, NULL, NULL);
        if (!dname || !should_ignore (path, dname, ignore_list)) {
            ret = FALSE;
            g_free (dname);
            FindClose (handle);
            goto out;
        }
        g_free (dname);
    } while (FindNextFileW (handle, &fdata) != 0);

    error = GetLastError();
    if (error != ERROR_NO_MORE_FILES) {
        seaf_warning ("FindNextFile failed %s: %lu.\n",
                      path, error);
    }

    FindClose (handle);

out:
    g_free (path_w);
    g_free (pattern);
    return ret;
}

#endif  /* WIN32 */

/* Returns whether the file should be removed from index. */
static gboolean
check_locked_file_before_remove (LockedFileSet *fset, const char *path)
{
#if defined WIN32 || defined __APPLE__
    if (!fset)
        return TRUE;

    LockedFile *file = locked_file_set_lookup (fset, path);
    gboolean ret = TRUE;

    if (file)
        ret = FALSE;

    return ret;
#else
    return TRUE;
#endif
}

static void
remove_deleted (struct index_state *istate, const char *worktree, const char *prefix,
                GList *ignore_list, LockedFileSet *fset,
                const char *repo_id, gboolean is_repo_ro,
                ChangeSet *changeset)
{
    struct cache_entry **ce_array = istate->cache;
    struct cache_entry *ce;
    char path[SEAF_PATH_MAX];
    unsigned int i;
    SeafStat st;
    int ret;
    gboolean not_exist;

    char *full_prefix = g_strconcat (prefix, "/", NULL);
    int len = strlen(full_prefix);

    for (i = 0; i < istate->cache_nr; ++i) {
        ce = ce_array[i];

        if (!is_path_writable (repo_id, is_repo_ro, ce->name))
            continue;

        if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                  repo_id, ce->name)) {
            seaf_debug ("Remove deleted: %s is locked on server, ignore.\n", ce->name);
            continue;
        }

        if (prefix[0] != 0 && strcmp (ce->name, prefix) != 0 &&
            strncmp (ce->name, full_prefix, len) != 0)
            continue;

        snprintf (path, SEAF_PATH_MAX, "%s/%s", worktree, ce->name);
        not_exist = FALSE;
        ret = seaf_stat (path, &st);
        if (ret < 0 && errno == ENOENT)
            not_exist = TRUE;

        if (S_ISDIR (ce->ce_mode)) {
            if (ce->ce_ctime.sec != 0 || ce_stage(ce) != 0) {
                if (not_exist || (ret == 0 && !S_ISDIR (st.st_mode))) {
                    /* Add to changeset only if dir is removed. */
                    ce->ce_flags |= CE_REMOVE;
                    if (changeset)
                        /* Remove the parent dir from change set if it becomes
                         * empty. If in the work tree the empty dir still exist,
                         * we'll add it back to changeset in add_recursive() later.
                         */
                        remove_from_changeset (changeset,
                                               DIFF_STATUS_DIR_DELETED,
                                               ce->name,
                                               TRUE,
                                               prefix);
                } else if (!is_empty_dir (path, ignore_list)) {
                    /* Don't add to changeset if empty dir became non-empty. */
                    ce->ce_flags |= CE_REMOVE;
                }
            }
        } else {
            /* If ce->ctime is 0 and stage is 0, it was not successfully checked out.
             * In this case we don't want to mistakenly remove the file
             * from the repo.
             */
            if ((not_exist || (ret == 0 && !S_ISREG (st.st_mode))) &&
                (ce->ce_ctime.sec != 0 || ce_stage(ce) != 0) &&
                check_locked_file_before_remove (fset, ce->name))
            {
                ce_array[i]->ce_flags |= CE_REMOVE;
                if (changeset)
                    remove_from_changeset (changeset,
                                           DIFF_STATUS_DELETED,
                                           ce->name,
                                           TRUE,
                                           prefix);
            }
        }
    }

    remove_marked_cache_entries (istate);

    g_free (full_prefix);
}

static int
scan_worktree_for_changes (struct index_state *istate, SeafRepo *repo,
                           SeafileCrypt *crypt, GList *ignore_list,
                           LockedFileSet *fset)
{
    remove_deleted (istate, repo->worktree, "", ignore_list, fset,
                    repo->id, repo->is_readonly, repo->changeset);

    AddOptions options;
    memset (&options, 0, sizeof(options));
    options.fset = fset;
    options.is_repo_ro = repo->is_readonly;
    options.changeset = repo->changeset;

    if (add_recursive (repo->id, repo->version, repo->email,
                       istate, repo->worktree, "", crypt, FALSE, ignore_list,
                       NULL, NULL, &options) < 0)
        return -1;

    return 0;
}

static gboolean
check_full_path_ignore (const char *worktree, const char *path, GList *ignore_list)
{
    char **tokens;
    guint i;
    guint n;
    gboolean ret = FALSE;

    tokens = g_strsplit (path, "/", 0);
    n = g_strv_length (tokens);
    for (i = 0; i < n; ++i) {
        /* don't check ignore_list */
        if (should_ignore (NULL, tokens[i], ignore_list)) {
            ret = TRUE;
            goto out;
        }
    }

    char *full_path = g_build_path ("/", worktree, path, NULL);
    if (seaf_repo_check_ignore_file (ignore_list, full_path))
        ret = TRUE;
    g_free (full_path);

out:
    g_strfreev (tokens);
    return ret;
}

static int
add_path_to_index (SeafRepo *repo, struct index_state *istate,
                   SeafileCrypt *crypt, const char *path, GList *ignore_list,
                   GList **scanned_dirs, gint64 *total_size, GQueue **remain_files,
                   LockedFileSet *fset)
{
    char *full_path;
    SeafStat st;
    AddOptions options;

    /* When a repo is initially added, a SCAN_DIR event will be created
     * for the worktree root "".
     */
    if (path[0] == 0) {
        remove_deleted (istate, repo->worktree, "", ignore_list, fset,
                        repo->id, repo->is_readonly, repo->changeset);

        memset (&options, 0, sizeof(options));
        options.fset = fset;
        options.is_repo_ro = repo->is_readonly;
        options.startup_scan = TRUE;
        options.changeset = repo->changeset;

        add_recursive (repo->id, repo->version, repo->email, istate,
                       repo->worktree, path,
                       crypt, FALSE, ignore_list,
                       total_size, remain_files, &options);

        return 0;
    }

    /* If we've recursively scanned the parent directory, don't need to scan
     * any files under it any more.
     */
    GList *ptr;
    char *dir, *full_dir;
    for (ptr = *scanned_dirs; ptr; ptr = ptr->next) {
        dir = ptr->data;
        /* exact match */
        if (strcmp (dir, path) == 0) {
            seaf_debug ("%s has been scanned before, skip adding.\n", path);
            return 0;
        }

        /* prefix match. */
        full_dir = g_strconcat (dir, "/", NULL);
        if (strncmp (full_dir, path, strlen(full_dir)) == 0) {
            g_free (full_dir);
            seaf_debug ("%s has been scanned before, skip adding.\n", path);
            return 0;
        }
        g_free (full_dir);
    }

    if (check_full_path_ignore (repo->worktree, path, ignore_list))
        return 0;

    full_path = g_build_filename (repo->worktree, path, NULL);

    if (seaf_stat (full_path, &st) < 0) {
        if (errno != ENOENT)
            send_file_sync_error_notification (repo->id, repo->name, path,
                                               SYNC_ERROR_ID_INDEX_ERROR);
        seaf_warning ("Failed to stat %s: %s.\n", path, strerror(errno));
        g_free (full_path);
        return -1;
    }

    if (S_ISDIR(st.st_mode))
        *scanned_dirs = g_list_prepend (*scanned_dirs, g_strdup(path));

    memset (&options, 0, sizeof(options));
    options.fset = fset;
    options.is_repo_ro = repo->is_readonly;
    options.changeset = repo->changeset;

    /* Add is always recursive */
    add_recursive (repo->id, repo->version, repo->email, istate, repo->worktree, path,
                   crypt, FALSE, ignore_list, total_size, remain_files, &options);

    g_free (full_path);
    return 0;
}

#if 0

static int
add_path_to_index (SeafRepo *repo, struct index_state *istate,
                   SeafileCrypt *crypt, const char *path, GList *ignore_list,
                   GList **scanned_dirs, gint64 *total_size, GQueue **remain_files,
                   LockedFileSet *fset)
{
    /* If we've recursively scanned the parent directory, don't need to scan
     * any files under it any more.
     */
    GList *ptr;
    char *dir, *full_dir;
    for (ptr = *scanned_dirs; ptr; ptr = ptr->next) {
        dir = ptr->data;

        /* Have scanned from root directory. */
        if (dir[0] == 0) {
            seaf_debug ("%s has been scanned before, skip adding.\n", path);
            return 0;
        }

        /* exact match */
        if (strcmp (dir, path) == 0) {
            seaf_debug ("%s has been scanned before, skip adding.\n", path);
            return 0;
        }

        /* prefix match. */
        full_dir = g_strconcat (dir, "/", NULL);
        if (strncmp (full_dir, path, strlen(full_dir)) == 0) {
            g_free (full_dir);
            seaf_debug ("%s has been scanned before, skip adding.\n", path);
            return 0;
        }
        g_free (full_dir);
    }

    if (path[0] != 0 && check_full_path_ignore (repo->worktree, path, ignore_list))
        return 0;

    remove_deleted (istate, repo->worktree, path, ignore_list, NULL,
                    repo->id, repo->is_readonly, repo->changeset);

    *scanned_dirs = g_list_prepend (*scanned_dirs, g_strdup(path));

    AddOptions options;
    memset (&options, 0, sizeof(options));
    options.fset = fset;
    options.is_repo_ro = repo->is_readonly;
    options.changeset = repo->changeset;
    /* When something is changed in the root directory, update active path
     * sync status when scanning the worktree. This is inaccurate. This will
     * be changed after we process fs events on Mac more precisely.
     */
    if (path[0] == 0)
        options.startup_scan = TRUE;

    /* Add is always recursive */
    add_recursive (repo->id, repo->version, repo->email, istate, repo->worktree, path,
                   crypt, FALSE, ignore_list, total_size, remain_files, &options);

    return 0;
}

#endif  /* __APPLE__ */

static int
add_remain_files (SeafRepo *repo, struct index_state *istate,
                  SeafileCrypt *crypt, GQueue *remain_files,
                  GList *ignore_list, gint64 *total_size)
{
    char *path;
    char *full_path;
    SeafStat st;
    struct cache_entry *ce;

    while ((path = g_queue_pop_head (remain_files)) != NULL) {
        full_path = g_build_filename (repo->worktree, path, NULL);
        if (seaf_stat (full_path, &st) < 0) {
            seaf_warning ("Failed to stat %s: %s.\n", full_path, strerror(errno));
            g_free (path);
            g_free (full_path);
            continue;
        }

#ifndef WIN32
    char *base_name = g_path_get_basename(full_path);
        if (!seaf->hide_windows_incompatible_path_notification &&
            check_path_ignore_on_windows (base_name)) {

            send_file_sync_error_notification (repo->id, repo->name, path,
                                               SYNC_ERROR_ID_INVALID_PATH_ON_WINDOWS);
        }
    g_free (base_name);
#endif

        if (S_ISREG(st.st_mode)) {
            gboolean added = FALSE;
            int ret = 0;
            ret = add_to_index (repo->id, repo->version, istate, path, full_path,
                                &st, 0, crypt, index_cb, repo->email, &added);
            if (added) {
                ce = index_name_exists (istate, path, strlen(path), 0);
                add_to_changeset (repo->changeset,
                                  DIFF_STATUS_ADDED,
                                  ce->sha1,
                                  &st,
                                  repo->email,
                                  path,
                                  NULL);

                *total_size += (gint64)(st.st_size);
                if (*total_size >= MAX_COMMIT_SIZE) {
                    g_free (path);
                    g_free (full_path);
                    break;
                }
            } else {
                seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                      repo->id,
                                                      path,
                                                      S_IFREG,
                                                      SYNC_STATUS_SYNCED,
                                                      TRUE);
            }
            if (ret < 0) {
                seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                      repo->id,
                                                      path,
                                                      S_IFREG,
                                                      SYNC_STATUS_ERROR,
                                                      TRUE);
                send_file_sync_error_notification (repo->id, NULL, path,
                                                   SYNC_ERROR_ID_INDEX_ERROR);
            }
        } else if (S_ISDIR(st.st_mode)) {
            if (is_empty_dir (full_path, ignore_list)) {
                int rc = add_empty_dir_to_index (istate, path, &st);
                if (rc == 1) {
                    unsigned char allzero[20] = {0};
                    add_to_changeset (repo->changeset,
                                      DIFF_STATUS_DIR_ADDED,
                                      allzero,
                                      &st,
                                      NULL,
                                      path,
                                      NULL);
                }
            }
        }
        g_free (path);
        g_free (full_path);
    }

    return 0;
}

static void
try_add_empty_parent_dir_entry (const char *worktree,
                                struct index_state *istate,
                                const char *path)
{
    if (index_name_exists (istate, path, strlen(path), 0) != NULL)
        return;

    char *parent_dir = g_path_get_dirname (path);

    /* Parent dir is the worktree dir. */
    if (strcmp (parent_dir, ".") == 0) {
        g_free (parent_dir);
        return;
    }

    char *full_dir = g_build_filename (worktree, parent_dir, NULL);
    SeafStat st;
    if (seaf_stat (full_dir, &st) < 0) {
        goto out;
    }

    add_empty_dir_to_index_with_check (istate, parent_dir, &st);

out:
    g_free (parent_dir);
    g_free (full_dir);
}

static void
try_add_empty_parent_dir_entry_from_wt (const char *worktree,
                                        struct index_state *istate,
                                        GList *ignore_list,
                                        const char *path)
{
    if (index_name_exists (istate, path, strlen(path), 0) != NULL)
        return;

    char *parent_dir = g_path_get_dirname (path);

    /* Parent dir is the worktree dir. */
    if (strcmp (parent_dir, ".") == 0) {
        g_free (parent_dir);
        return;
    }

    char *full_dir = g_build_filename (worktree, parent_dir, NULL);
    SeafStat st;
    if (seaf_stat (full_dir, &st) < 0) {
        goto out;
    }

    if (is_empty_dir (full_dir, ignore_list)) {
#ifdef WIN32
        wchar_t *parent_dir_w = g_utf8_to_utf16 (parent_dir, -1, NULL, NULL, NULL);
        wchar_t *pw;
        for (pw = parent_dir_w; *pw != L'\0'; ++pw)
            if (*pw == L'/')
                *pw = L'\\';

        wchar_t *long_path = win32_83_path_to_long_path (worktree,
                                                         parent_dir_w,
                                                         wcslen(parent_dir_w));
        g_free (parent_dir_w);
        if (!long_path) {
            seaf_warning ("Convert %s to long path failed.\n", parent_dir);
            goto out;
        }

        char *utf8_path = g_utf16_to_utf8 (long_path, -1, NULL, NULL, NULL);
        if (!utf8_path) {
            g_free (long_path);
            goto out;
        }

        char *p;
        for (p = utf8_path; *p != 0; ++p)
            if (*p == '\\')
                *p = '/';
        g_free (long_path);

        add_empty_dir_to_index (istate, utf8_path, &st);
#else
        add_empty_dir_to_index (istate, parent_dir, &st);
#endif
    }

out:
    g_free (parent_dir);
    g_free (full_dir);
}

static void
update_attributes (SeafRepo *repo,
                   struct index_state *istate,
                   const char *worktree,
                   const char *path)
{
    ChangeSet *changeset = repo->changeset;
    char *full_path;
    struct cache_entry *ce;
    SeafStat st;

    ce = index_name_exists (istate, path, strlen(path), 0);
    if (!ce)
        return;

    full_path = g_build_filename (worktree, path, NULL);
    if (seaf_stat (full_path, &st) < 0) {
        seaf_warning ("Failed to stat %s: %s.\n", full_path, strerror(errno));
        g_free (full_path);
        return;
    }

    unsigned int new_mode = create_ce_mode (st.st_mode);
    if (new_mode != ce->ce_mode || st.st_mtime != ce->ce_mtime.sec) {
        ce->ce_mode = new_mode;
        ce->ce_mtime.sec = st.st_mtime;
        istate->cache_changed = 1;
        add_to_changeset (changeset,
                          DIFF_STATUS_MODIFIED,
                          ce->sha1,
                          &st,
                          repo->email,
                          path,
                          NULL);
    }
    g_free (full_path);
}

#ifdef WIN32
static void
scan_subtree_for_deletion (const char *repo_id,
                           struct index_state *istate,
                           const char *worktree,
                           const char *path,
                           GList *ignore_list,
                           LockedFileSet *fset,
                           gboolean is_readonly,
                           GList **scanned_dirs,
                           ChangeSet *changeset)
{
    wchar_t *path_w = NULL;
    wchar_t *dir_w = NULL;
    wchar_t *p;
    char *dir = NULL;
    char *p2;

    /* In most file systems, like NTFS, 8.3 format path should contain ~.
     * Also note that *~ files are ignored.
     */
    if (!strchr (path, '~') || path[strlen(path)-1] == '~')
        return;

    path_w = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);

    for (p = path_w; *p != L'\0'; ++p)
        if (*p == L'/')
            *p = L'\\';

    while (1) {
        p = wcsrchr (path_w, L'\\');
        if (p)
            *p = L'\0';
        else
            break;

        dir_w = win32_83_path_to_long_path (worktree, path_w, wcslen(path_w));
        if (dir_w)
            break;
    }

    if (!dir_w)
        dir_w = wcsdup(L"");

    dir = g_utf16_to_utf8 (dir_w, -1, NULL, NULL, NULL);
    if (!dir)
        goto out;

    for (p2 = dir; *p2 != 0; ++p2)
        if (*p2 == '\\')
            *p2 = '/';

    /* If we've recursively scanned the parent directory, don't need to scan
     * any files under it any more.
     */
    GList *ptr;
    char *s, *full_s;
    for (ptr = *scanned_dirs; ptr; ptr = ptr->next) {
        s = ptr->data;

        /* Have scanned from root directory. */
        if (s[0] == 0) {
            goto out;
        }

        /* exact match */
        if (strcmp (s, path) == 0) {
            goto out;
        }

        /* prefix match. */
        full_s = g_strconcat (s, "/", NULL);
        if (strncmp (full_s, dir, strlen(full_s)) == 0) {
            g_free (full_s);
            goto out;
        }
        g_free (full_s);
    }

    *scanned_dirs = g_list_prepend (*scanned_dirs, g_strdup(dir));

    remove_deleted (istate, worktree, dir, ignore_list, fset,
                    repo_id, is_readonly, changeset);

    /* After remove_deleted(), empty dirs are left not removed in changeset.
     * This can be fixed by removing the accurate deleted path. In most cases,
     * basename doesn't contain ~, so we can always get the accurate path.
     */
    /* if (!convertion_failed) { */
    /*     char *basename = strrchr (path, '/'); */
    /*     char *deleted_path = NULL; */
    /*     if (basename) { */
    /*         deleted_path = g_build_path ("/", dir, basename, NULL); */
    /*         add_to_changeset (changeset, */
    /*                           DIFF_STATUS_DELETED, */
    /*                           NULL, */
    /*                           NULL, */
    /*                           NULL, */
    /*                           deleted_path, */
    /*                           NULL, */
    /*                           FALSE); */
    /*         g_free (deleted_path); */
    /*     } */
    /* } */

out:
    g_free (path_w);
    g_free (dir_w);
    g_free (dir);
}
#else
static void
scan_subtree_for_deletion (const char *repo_id,
                           struct index_state *istate,
                           const char *worktree,
                           const char *path,
                           GList *ignore_list,
                           LockedFileSet *fset,
                           gboolean is_readonly,
                           GList **scanned_dirs,
                           ChangeSet *changeset)
{
}
#endif

/* Return TRUE if the caller should stop processing next event. */
static gboolean
handle_add_files (SeafRepo *repo, struct index_state *istate,
                  SeafileCrypt *crypt, GList *ignore_list,
                  LockedFileSet *fset,
                  WTStatus *status, WTEvent *event,
                  GList **scanned_dirs, gint64 *total_size)
{
    SyncInfo *info;

    if (!repo->create_partial_commit) {
        /* XXX: We now use remain_files = NULL to signify not creating
         * partial commits. It's better to use total_size = NULL for
         * that purpose.
         */
        add_path_to_index (repo, istate, crypt, event->path,
                           ignore_list, scanned_dirs,
                           total_size, NULL, NULL);
    } else if (!event->remain_files) {
        GQueue *remain_files = NULL;
        add_path_to_index (repo, istate, crypt, event->path,
                           ignore_list, scanned_dirs,
                           total_size, &remain_files, fset);
        if (*total_size >= MAX_COMMIT_SIZE) {
            seaf_message ("Creating partial commit after adding %s.\n",
                          event->path);

            status->partial_commit = TRUE;

            /* An event for a new folder may contain many files.
             * If the total_size become larger than 100MB after adding
             * some of these files, the remaining file paths will be
             * cached in remain files. This way we don't need to scan
             * the folder again next time.
             */
            if (remain_files) {
                if (g_queue_get_length (remain_files) == 0) {
                    g_queue_free (remain_files);
                    return TRUE;
                }

                seaf_message ("Remain files for %s.\n", event->path);

                /* Cache remaining files in the event structure. */
                event->remain_files = remain_files;

                pthread_mutex_lock (&status->q_lock);
                g_queue_push_head (status->event_q, event);
                pthread_mutex_unlock (&status->q_lock);

                info = seaf_sync_manager_get_sync_info (seaf->sync_mgr, repo->id);
                if (!info->multipart_upload) {
                    info->multipart_upload = TRUE;
                    info->total_bytes = *total_size;
                }
            }

            return TRUE;
        }
    } else {
        seaf_message ("Adding remaining files for %s.\n", event->path);

        add_remain_files (repo, istate, crypt, event->remain_files,
                          ignore_list, total_size);
        if (g_queue_get_length (event->remain_files) != 0) {
            pthread_mutex_lock (&status->q_lock);
            g_queue_push_head (status->event_q, event);
            pthread_mutex_unlock (&status->q_lock);
            return TRUE;
        } else {
            info = seaf_sync_manager_get_sync_info (seaf->sync_mgr, repo->id);
            info->end_multipart_upload = TRUE;
            return TRUE;
        }
        if (*total_size >= MAX_COMMIT_SIZE)
            return TRUE;
    }

    return FALSE;
}

#ifdef __APPLE__

/* struct _WTDirent { */
/*     char *dname; */
/*     struct stat st; */
/* }; */
/* typedef struct _WTDirent WTDirent; */

/* static gint */
/* compare_wt_dirents (gconstpointer a, gconstpointer b) */
/* { */
/*     const WTDirent *dent_a = a, *dent_b = b; */

/*     return (strcmp (dent_a->dname, dent_b->dname)); */
/* } */

/* static GList * */
/* get_sorted_wt_dirents (const char *dir_path, const char *full_dir_path, */
/*                        gboolean *error) */
/* { */
/*     GDir *dir; */
/*     GError *err = NULL; */
/*     const char *name; */
/*     char *dname; */
/*     char *full_sub_path, *sub_path; */
/*     WTDirent *dent; */
/*     GList *ret = NULL; */

/*     dir = g_dir_open (full_dir_path, 0, &err); */
/*     if (!dir) { */
/*         seaf_warning ("Failed to open dir %s: %s.\n", full_dir_path, err->message); */
/*         *error = TRUE; */
/*         return NULL; */
/*     } */

/*     while ((name = g_dir_read_name(dir)) != NULL) { */
/*         dname = g_utf8_normalize (name, -1, G_NORMALIZE_NFC); */
/*         sub_path = g_strconcat (dir_path, "/", dname, NULL); */
/*         full_sub_path = g_strconcat (full_dir_path, "/", dname, NULL); */

/*         dent = g_new0 (WTDirent, 1); */
/*         dent->dname = dname; */

/*         if (stat (full_sub_path, &dent->st) < 0) { */
/*             seaf_warning ("Failed to stat %s: %s.\n", full_sub_path, strerror(errno)); */
/*             g_free (dname); */
/*             g_free (sub_path); */
/*             g_free (full_sub_path); */
/*             g_free (dent); */
/*             continue; */
/*         } */

/*         ret = g_list_prepend (ret, dent); */

/*         g_free (sub_path); */
/*         g_free (full_sub_path); */
/*     } */

/*     g_dir_close (dir); */

/*     ret = g_list_sort (ret, compare_wt_dirents); */
/*     return ret; */
/* } */

/* static void */
/* wt_dirent_free (WTDirent *dent) */
/* { */
/*     if (!dent) */
/*         return; */
/*     g_free (dent->dname); */
/*     g_free (dent); */
/* } */

/* inline static char * */
/* concat_sub_path (const char *dir, const char *dname) */
/* { */
/*     if (dir[0] != 0) */
/*         return g_strconcat(dir, "/", dname, NULL); */
/*     else */
/*         return g_strdup(dname); */
/* } */

/* static int */
/* get_changed_paths_in_folder (SeafRepo *repo, struct index_state *istate, */
/*                              const char *dir_path, */
/*                              GList **add, GList **mod, GList **del) */
/* { */
/*     char *full_dir_path; */
/*     GList *wt_dents = NULL, *index_dents = NULL; */
/*     gboolean error = FALSE; */

/*     full_dir_path = g_build_filename(repo->worktree, dir_path, NULL); */

/*     wt_dents = get_sorted_wt_dirents (dir_path, full_dir_path, &error); */
/*     if (error) { */
/*         g_free (full_dir_path); */
/*         return -1; */
/*     } */

/*     index_dents = list_dirents_from_index (istate, dir_path); */

/*     GList *p; */
/*     IndexDirent *dent; */
/*     for (p = index_dents; p; p = p->next) { */
/*         dent = p->data; */
/*     } */

/*     GList *p1 = wt_dents, *p2 = index_dents; */
/*     WTDirent *dent1; */
/*     IndexDirent *dent2; */

/*     while (p1 && p2) { */
/*         dent1 = p1->data; */
/*         dent2 = p2->data; */

/*         int rc = strcmp (dent1->dname, dent2->dname); */
/*         if (rc == 0) { */
/*             if (S_ISREG(dent1->st.st_mode) && !dent2->is_dir) { */
/*                 if (dent1->st.st_mtime != dent2->ce->ce_mtime.sec) */
/*                     *mod = g_list_prepend (*mod, concat_sub_path(dir_path, dent1->dname)); */
/*             } else if ((S_ISREG(dent1->st.st_mode) && dent2->is_dir) || */
/*                        (S_ISDIR(dent1->st.st_mode) && !dent2->is_dir)) { */
/*                 *add = g_list_prepend (*add, concat_sub_path(dir_path, dent1->dname)); */
/*                 *del = g_list_prepend (*del, concat_sub_path(dir_path, dent1->dname)); */
/*             } */
/*             p1 = p1->next; */
/*             p2 = p2->next; */
/*         } else if (rc < 0) { */
/*             *add = g_list_prepend (*add, concat_sub_path(dir_path, dent1->dname)); */
/*             p1 = p1->next; */
/*         } else { */
/*             *del = g_list_prepend (*del, concat_sub_path(dir_path, dent2->dname)); */
/*             p2 = p2->next; */
/*         } */
/*     } */

/*     while (p1) { */
/*         dent1 = p1->data; */
/*         *add = g_list_prepend (*add, concat_sub_path(dir_path, dent1->dname)); */
/*         p1 = p1->next; */
/*     } */

/*     while (p2) { */
/*         dent2 = p2->data; */
/*         *del = g_list_prepend (*del, concat_sub_path(dir_path, dent2->dname)); */
/*         p2 = p2->next; */
/*     } */

/*     g_free (full_dir_path); */
/*     g_list_free_full (wt_dents, (GDestroyNotify)wt_dirent_free); */
/*     g_list_free_full (index_dents, (GDestroyNotify)index_dirent_free); */
/*     return 0; */
/* } */

#endif  /* __APPLE__ */

static void
update_active_file (SeafRepo *repo,
                    const char *path,
                    SeafStat *st,
                    struct index_state *istate,
                    gboolean ignored)
{
    if (ignored) {
        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              repo->id,
                                              path,
                                              S_IFREG,
                                              SYNC_STATUS_IGNORED,
                                              TRUE);
    } else {
        SyncStatus status;
        gboolean is_writable;

        struct cache_entry *ce = index_name_exists(istate, path, strlen(path), 0);
        if (!ce || ie_match_stat(ce, st, 0) != 0)
            status = SYNC_STATUS_SYNCING;
        else
            status = SYNC_STATUS_SYNCED;

        is_writable = is_path_writable (repo->id, repo->is_readonly, path);

        if (!is_writable && status == SYNC_STATUS_SYNCING)
            seaf_sync_manager_delete_active_path (seaf->sync_mgr,
                                                  repo->id,
                                                  path);
        else
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  repo->id,
                                                  path,
                                                  S_IFREG,
                                                  status,
                                                  FALSE);
    }
}

#ifdef WIN32

typedef struct _UpdatePathData {
    SeafRepo *repo;
    struct index_state *istate;
    GList *ignore_list;

    const char *parent;
    const char *full_parent;
    gboolean ignored;
} UpdatePathData;

static void
update_active_path_recursive (SeafRepo *repo,
                              const char *path,
                              struct index_state *istate,
                              GList *ignore_list,
                              gboolean ignored);

static int
update_active_path_cb (wchar_t *full_parent_w,
                       WIN32_FIND_DATAW *fdata,
                       void *user_data,
                       gboolean *stop)
{
    UpdatePathData *upd_data = user_data;
    char *dname;
    char *path;
    gboolean ignored = FALSE;
    SeafStat st;

    dname = g_utf16_to_utf8 (fdata->cFileName, -1, NULL, NULL, NULL);
    if (!dname)
        return 0;

    path = g_build_path ("/", upd_data->parent, dname, NULL);

    if (upd_data->ignored || should_ignore (upd_data->full_parent, dname, upd_data->ignore_list))
        ignored = TRUE;

    seaf_stat_from_find_data (fdata, &st);

    if (fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
        update_active_path_recursive (upd_data->repo,
                                      path,
                                      upd_data->istate,
                                      upd_data->ignore_list,
                                      ignored);
    } else {
        update_active_file (upd_data->repo,
                            path,
                            &st,
                            upd_data->istate,
                            ignored);
    }

    g_free (dname);
    g_free (path);

    return 0;
}

static void
update_active_path_recursive (SeafRepo *repo,
                              const char *path,
                              struct index_state *istate,
                              GList *ignore_list,
                              gboolean ignored)
{
    char *full_path;
    wchar_t *full_path_w;
    int ret = 0;
    UpdatePathData upd_data;

    full_path = g_build_filename (repo->worktree, path, NULL);

    memset (&upd_data, 0, sizeof(upd_data));
    upd_data.repo = repo;
    upd_data.istate = istate;
    upd_data.ignore_list = ignore_list;
    upd_data.parent = path;
    upd_data.full_parent = full_path;
    upd_data.ignored = ignored;

    full_path_w = win32_long_path (full_path);
    ret = traverse_directory_win32 (full_path_w, update_active_path_cb, &upd_data);
    g_free (full_path_w);
    g_free (full_path);

    if (ret < 0)
        return;

    /* Don't set sync status for read-only paths, since changes to read-only
     * files are ignored.
     */
    if (!is_path_writable (repo->id, repo->is_readonly, path))
        return;

    /* traverse_directory_win32() returns number of entries in the directory. */
    if (ret == 0 && path[0] != 0) {
        if (ignored) {
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  repo->id,
                                                  path,
                                                  S_IFDIR,
                                                  SYNC_STATUS_IGNORED,
                                                  FALSE);
        } else {
            /* There is no need to update an empty dir. */
            SyncStatus status;
            struct cache_entry *ce = index_name_exists(istate, path, strlen(path), 0);
            if (!ce)
                status = SYNC_STATUS_SYNCING;
            else
                status = SYNC_STATUS_SYNCED;
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  repo->id,
                                                  path,
                                                  S_IFDIR,
                                                  status,
                                                  FALSE);
        }
    }
}

#else

static void
update_active_path_recursive (SeafRepo *repo,
                              const char *path,
                              struct index_state *istate,
                              GList *ignore_list,
                              gboolean ignored)
{
    GDir *dir;
    GError *error = NULL;
    const char *name;
    char *dname;
    char *full_path, *full_sub_path, *sub_path;
    struct stat st;
    gboolean ignore_sub;

    full_path = g_build_filename(repo->worktree, path, NULL);

    dir = g_dir_open (full_path, 0, &error);
    if (!dir) {
        seaf_warning ("Failed to open dir %s: %s.\n", full_path, error->message);
        g_free (full_path);
        return;
    }

    int n = 0;
    while ((name = g_dir_read_name(dir)) != NULL) {
        ++n;

        dname = g_utf8_normalize (name, -1, G_NORMALIZE_NFC);
        sub_path = g_strconcat (path, "/", dname, NULL);
        full_sub_path = g_strconcat (full_path, "/", dname, NULL);

        ignore_sub = FALSE;
        if (ignored || should_ignore(full_path, dname, ignore_list))
            ignore_sub = TRUE;

        if (stat (full_sub_path, &st) < 0) {
            seaf_warning ("Failed to stat %s: %s.\n", full_sub_path, strerror(errno));
            g_free (dname);
            g_free (sub_path);
            g_free (full_sub_path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            update_active_path_recursive (repo, sub_path, istate, ignore_list,
                                          ignore_sub);
        } else if (S_ISREG(st.st_mode)) {
            update_active_file (repo, sub_path, &st, istate,
                                ignore_sub);
        }

        g_free (dname);
        g_free (sub_path);
        g_free (full_sub_path);
    }

    g_dir_close (dir);

    g_free (full_path);

    /* Don't set sync status for read-only paths, since changes to read-only
     * files are ignored.
     */
    if (!is_path_writable (repo->id, repo->is_readonly, path))
        return;

    if (n == 0 && path[0] != 0) {
        if (ignored) {
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  repo->id,
                                                  path,
                                                  S_IFDIR,
                                                  SYNC_STATUS_IGNORED,
                                                  TRUE);
        } else {
            /* There is no need to update an empty dir. */
            SyncStatus status;
            struct cache_entry *ce = index_name_exists(istate, path, strlen(path), 0);
            if (!ce)
                status = SYNC_STATUS_SYNCING;
            else
                status = SYNC_STATUS_SYNCED;
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  repo->id,
                                                  path,
                                                  S_IFDIR,
                                                  status,
                                                  TRUE);
        }
    }
}

#endif  /* WIN32 */

static void
process_active_path (SeafRepo *repo, const char *path,
                     struct index_state *istate, GList *ignore_list)
{
    SeafStat st;
    gboolean ignored = FALSE;

    char *fullpath = g_build_filename (repo->worktree, path, NULL);
    if (seaf_stat (fullpath, &st) < 0) {
        g_free (fullpath);
        return;
    }

    if (check_full_path_ignore (repo->worktree, path, ignore_list))
        ignored = TRUE;

    if (S_ISREG(st.st_mode)) {
        if (!seaf_filelock_manager_is_file_locked(seaf->filelock_mgr,
                                                  repo->id, path)) {
            update_active_file (repo, path, &st, istate, ignored);
        }
    } else {
        update_active_path_recursive (repo, path, istate, ignore_list, ignored);
    }

    g_free (fullpath);
}

#ifdef __APPLE__

/* static void */
/* process_active_folder (SeafRepo *repo, const char *dir, */
/*                        struct index_state *istate, GList *ignore_list) */
/* { */
/*     GList *add = NULL, *mod = NULL, *del = NULL; */
/*     GList *p; */
/*     char *path; */

/*     /\* Delete event will be triggered on the deleted dir too. *\/ */
/*     if (!g_file_test (dir, G_FILE_TEST_IS_DIR)) */
/*         return; */

/*     if (get_changed_paths_in_folder (repo, istate, dir, &add, &mod, &del) < 0) { */
/*         seaf_warning ("Failed to get changed paths under %s.\n", dir); */
/*         return; */
/*     } */

/*     for (p = add; p; p = p->next) { */
/*         path = p->data; */
/*         process_active_path (repo, path, istate, ignore_list); */
/*     } */

/*     for (p = mod; p; p = p->next) { */
/*         path = p->data; */
/*         process_active_path (repo, path, istate, ignore_list); */
/*     } */

/*     g_list_free_full (add, g_free); */
/*     g_list_free_full (mod, g_free); */
/*     g_list_free_full (del, g_free); */
/* } */

#endif  /* __APPLE__ */

static void
update_path_sync_status (SeafRepo *repo, WTStatus *status,
                         struct index_state *istate, GList *ignore_list)
{
    char *path;

    while (1) {
        pthread_mutex_lock (&status->ap_q_lock);
        path = g_queue_pop_head (status->active_paths);
        pthread_mutex_unlock (&status->ap_q_lock);

        if (!path)
            break;

/* #ifdef __APPLE__ */
/*         process_active_folder (repo, path, istate, ignore_list); */
/* #else */
        process_active_path (repo, path, istate, ignore_list);
/* #endif */

        g_free (path);
    }
}

/* Excel first writes update to a temporary file and then rename the file to
 * xlsx. Unfortunately the temp file dosen't have specific pattern.
 * We can only ignore renaming from non xlsx file to xlsx file.
 */
static gboolean
ignore_xlsx_update (const char *src_path, const char *dst_path)
{
    GPatternSpec *pattern = g_pattern_spec_new ("*.xlsx");
    int ret = FALSE;

    if (!g_pattern_match_string(pattern, src_path) &&
        g_pattern_match_string(pattern, dst_path))
        ret = TRUE;

    g_pattern_spec_free (pattern);
    return ret;
}

static gboolean
is_seafile_backup_file (const char *path)
{
    GPatternSpec *pattern = g_pattern_spec_new ("*.sbak");
    int ret = FALSE;

    if (g_pattern_match_string(pattern, path))
        ret = TRUE;

    g_pattern_spec_free (pattern);
    return ret;
}

static void
handle_rename (SeafRepo *repo, struct index_state *istate,
               SeafileCrypt *crypt, GList *ignore_list,
               LockedFileSet *fset,
               WTEvent *event, GList **scanned_del_dirs,
               gint64 *total_size)
{
    gboolean not_found, src_ignored, dst_ignored;

    seaf_sync_manager_delete_active_path (seaf->sync_mgr, repo->id, event->path);

    if (!is_path_writable(repo->id,
                          repo->is_readonly, event->path) ||
        !is_path_writable(repo->id,
                          repo->is_readonly, event->new_path)) {
        seaf_debug ("Rename: %s or %s is not writable, ignore.\n",
                    event->path, event->new_path);
        return;
    }

    if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                              repo->id, event->path)) {
        seaf_debug ("Rename: %s is locked on server, ignore.\n", event->path);
        /* send_sync_error_notification (repo->id, NULL, event->path, */
        /*                               SYNC_ERROR_ID_FILE_LOCKED); */
        return;
    }

    if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                              repo->id, event->new_path)) {
        seaf_debug ("Rename: %s is locked on server, ignore.\n", event->new_path);
        /* send_sync_error_notification (repo->id, NULL, event->new_path, */
        /*                               SYNC_ERROR_ID_FILE_LOCKED); */
        return;
    }

    src_ignored = check_full_path_ignore(repo->worktree, event->path, ignore_list);
    dst_ignored = check_full_path_ignore(repo->worktree, event->new_path, ignore_list);

    /* If the destination path is ignored, just remove the source path. */
    if (dst_ignored) {
        if (!src_ignored &&
            !is_seafile_backup_file (event->new_path) &&
            check_locked_file_before_remove (fset, event->path)) {
            not_found = FALSE;
            remove_from_index_with_prefix (istate, event->path, &not_found);
            if (not_found)
                scan_subtree_for_deletion (repo->id,
                                           istate,
                                           repo->worktree, event->path,
                                           ignore_list, fset,
                                           repo->is_readonly,
                                           scanned_del_dirs,
                                           repo->changeset);

            remove_from_changeset (repo->changeset,
                                   DIFF_STATUS_DELETED,
                                   event->path,
                                   FALSE,
                                   NULL);
        }
        return;
    }

    /* Now the destination path is not ignored. */

    if (!src_ignored && !ignore_xlsx_update (event->path, event->new_path) &&
        check_locked_file_before_remove (fset, event->path)) {
        not_found = FALSE;
        rename_index_entries (istate, event->path, event->new_path, &not_found,
                              NULL, NULL);
        if (not_found)
            scan_subtree_for_deletion (repo->id,
                                       istate,
                                       repo->worktree, event->path,
                                       ignore_list, fset,
                                       repo->is_readonly,
                                       scanned_del_dirs,
                                       repo->changeset);

        /* Moving files out of a dir may make it empty. */
        try_add_empty_parent_dir_entry_from_wt (repo->worktree,
                                                istate,
                                                ignore_list,
                                                event->path);

        add_to_changeset (repo->changeset,
                          DIFF_STATUS_RENAMED,
                          NULL,
                          NULL,
                          NULL,
                          event->path,
                          event->new_path);
    }

    AddOptions options;
    memset (&options, 0, sizeof(options));
    options.fset = fset;
    options.is_repo_ro = repo->is_readonly;
    options.changeset = repo->changeset;

    /* We should always scan the destination to compare with the renamed
     * index entries. For example, in the following case:
     * 1. file a.txt is updated;
     * 2. a.txt is moved to test/a.txt;
     * If the two operations are executed in a batch, the updated content
     * of a.txt won't be committed if we don't scan the destination, because
     * when we process the update event, a.txt is already not in its original
     * place.
     */
    add_recursive (repo->id, repo->version, repo->email,
                   istate, repo->worktree, event->new_path,
                   crypt, FALSE, ignore_list,
                   total_size, NULL, &options);
}

#ifdef WIN32

typedef struct FindOfficeData {
    const char *lock_file_name;
    char *office_file_name;
} FindOfficeData;

static int
find_office_file_cb (wchar_t *parent,
                     WIN32_FIND_DATAW *fdata,
                     void *user_data,
                     gboolean *stop)
{
    FindOfficeData *data = user_data;
    const wchar_t *dname_w = fdata->cFileName;
    wchar_t *lock_name_w = NULL;

    if (wcslen(dname_w) < 2)
        return 0;
    if (wcsncmp (dname_w, L"~$", 2) == 0)
        return 0;

    lock_name_w = g_utf8_to_utf16 (data->lock_file_name,
                                   -1, NULL, NULL, NULL);
    /* Skip "~$" at the beginning. */
    if (wcscmp (dname_w + 2, lock_name_w) == 0) {
        data->office_file_name = g_utf16_to_utf8 (dname_w, -1, NULL, NULL, NULL);
        *stop = TRUE;
    }
    g_free (lock_name_w);

    return 0;
}

static gboolean
find_office_file_path (const char *worktree,
                       const char *parent_dir,
                       const char *lock_file_name,
                       char **office_path)
{
    char *fullpath = NULL;
    wchar_t *fullpath_w = NULL;
    FindOfficeData data;
    gboolean ret = FALSE;

    fullpath = g_build_path ("/", worktree, parent_dir, NULL);
    fullpath_w = win32_long_path (fullpath);

    data.lock_file_name = lock_file_name;
    data.office_file_name = NULL;

    if (traverse_directory_win32 (fullpath_w, find_office_file_cb, &data) < 0) {
        goto out;
    }

    if (data.office_file_name != NULL) {
        *office_path = g_build_path ("/", parent_dir, data.office_file_name, NULL);
        ret = TRUE;
    }

out:
    g_free (fullpath);
    g_free (fullpath_w);
    return ret;
}

#endif

#ifdef __APPLE__

static gboolean
find_office_file_path (const char *worktree,
                       const char *parent_dir,
                       const char *lock_file_name,
                       char **office_path)
{
    GDir *dir = NULL;
    GError *error = NULL;
    char *fullpath = NULL;
    const char *dname;
    char *dname_nfc = NULL;
    char *dname_skip_head = NULL;
    gboolean ret = FALSE;

    fullpath = g_build_path ("/", worktree, parent_dir, NULL);
    dir = g_dir_open (fullpath, 0, &error);
    if (error) {
        seaf_warning ("Failed to open dir %s: %s.\n", fullpath, error->message);
        g_clear_error (&error);
        g_free (fullpath);
        return ret;
    }

    while ((dname = g_dir_read_name (dir)) != NULL) {
        dname_nfc = g_utf8_normalize (dname, -1, G_NORMALIZE_NFC);
        if (!dname_nfc)
            continue;

        if (g_utf8_strlen(dname_nfc, -1) < 2 || strncmp (dname_nfc, "~$", 2) == 0) {
            g_free (dname_nfc);
            continue;
        }

        dname_skip_head = g_utf8_find_next_char(g_utf8_find_next_char(dname_nfc, NULL), NULL);

        if (g_strcmp0 (dname_skip_head, lock_file_name) == 0) {
            *office_path = g_build_path ("/", parent_dir, dname_nfc, NULL);
            ret = TRUE;
            g_free (dname_nfc);
            break;
        }

        g_free (dname_nfc);
    }

    g_free (fullpath);
    g_dir_close (dir);
    return ret;
}

#endif

#if defined WIN32 || defined __APPLE__

static gboolean
is_office_lock_file (const char *worktree,
                     const char *path,
                     char **office_path)
{
    gboolean ret;

    if (!g_regex_match (office_lock_pattern, path, 0, NULL))
        return FALSE;

    /* Replace ~$abc.docx with abc.docx */
    *office_path = g_regex_replace (office_lock_pattern,
                                    path, -1, 0,
                                    "\\1", 0, NULL);

    /* When the filename is long, sometimes the first two characters
       in the filename will be directly replaced with ~$.
       So if the office_path file doesn't exist, we have to match
       against all filenames in this directory, to find the office
       file's name.
    */
    char *fullpath = g_build_path ("/", worktree, *office_path, NULL);
    if (seaf_util_exists (fullpath)) {
        g_free (fullpath);
        return TRUE;
    }
    g_free (fullpath);

    char *lock_file_name = g_path_get_basename(*office_path);
    char *parent_dir = g_path_get_dirname(*office_path);
    if (strcmp(parent_dir, ".") == 0) {
        g_free (parent_dir);
        parent_dir = g_strdup("");
    }
    g_free (*office_path);
    *office_path = NULL;

    ret = find_office_file_path (worktree, parent_dir, lock_file_name,
                                 office_path);

    g_free (lock_file_name);
    g_free (parent_dir);
    return ret;
}

typedef struct LockOfficeJob {
    char repo_id[37];
    char *path;
    gboolean lock;              /* False if unlock */
} LockOfficeJob;

static void
lock_office_job_free (LockOfficeJob *job)
{
    if (!job)
        return;
    g_free (job->path);
    g_free (job);
}

static void
do_lock_office_file (LockOfficeJob *job)
{
    SeafRepo *repo;
    char *fullpath = NULL;
    SeafStat st;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, job->repo_id);
    if (!repo)
        return;

    fullpath = g_build_path ("/", repo->worktree, job->path, NULL);
    if (seaf_stat (fullpath, &st) < 0 || !S_ISREG(st.st_mode)) {
        g_free (fullpath);
        return;
    }
    g_free (fullpath);

    seaf_message ("Auto lock file %s/%s\n", repo->name, job->path);

    int status = seaf_filelock_manager_get_lock_status (seaf->filelock_mgr,
                                                        repo->id, job->path);
    if (status != FILE_NOT_LOCKED) {
        return;
    }

    if (http_tx_manager_lock_file (seaf->http_tx_mgr,
                                   repo->effective_host,
                                   repo->use_fileserver_port,
                                   repo->token,
                                   repo->id,
                                   job->path) < 0) {
        seaf_warning ("Failed to lock %s in repo %.8s on server.\n",
                      job->path, repo->id);
        return;
    }

    /* Mark file as locked locally so that the user can see the effect immediately. */
    seaf_filelock_manager_mark_file_locked (seaf->filelock_mgr, repo->id, job->path, TRUE);
}

static void
do_unlock_office_file (LockOfficeJob *job)
{
    SeafRepo *repo;
    char *fullpath = NULL;
    SeafStat st;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, job->repo_id);
    if (!repo)
        return;

    fullpath = g_build_path ("/", repo->worktree, job->path, NULL);
    if (seaf_stat (fullpath, &st) < 0 || !S_ISREG(st.st_mode)) {
        g_free (fullpath);
        return;
    }
    g_free (fullpath);

    seaf_message ("Auto unlock file %s/%s\n", repo->name, job->path);

    int status = seaf_filelock_manager_get_lock_status (seaf->filelock_mgr,
                                                        repo->id, job->path);
    if (status != FILE_LOCKED_BY_ME_AUTO) {
        return;
    }

    if (http_tx_manager_unlock_file (seaf->http_tx_mgr,
                                     repo->effective_host,
                                     repo->use_fileserver_port,
                                     repo->token,
                                     repo->id,
                                     job->path) < 0) {
        seaf_warning ("Failed to unlock %s in repo %.8s on server.\n",
                      job->path, repo->id);
        return;
    }

    /* Mark file as unlocked locally so that the user can see the effect immediately. */
    seaf_filelock_manager_mark_file_unlocked (seaf->filelock_mgr, repo->id, job->path);
}

#if 0
static void
unlock_closed_office_files ()
{
    GList *locked_files, *ptr;
    SeafRepo *repo;
    FileLockInfo *info;
    LockOfficeJob *job;

    locked_files = seaf_filelock_manager_get_auto_locked_files (seaf->filelock_mgr);
    for (ptr = locked_files; ptr; ptr = ptr->next) {
        info = ptr->data;

        seaf_message ("%s %s.\n", info->repo_id, info->path);

        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, info->repo_id);
        if (!repo)
            continue;

        seaf_message ("1\n");

        if (!do_check_file_locked (info->path, repo->worktree, FALSE)) {
            seaf_message ("2\n");

            job = g_new0 (LockOfficeJob, 1);
            memcpy (job->repo_id, info->repo_id, 36);
            job->path = g_strdup(info->path);
            do_unlock_office_file (job);
            lock_office_job_free (job);
        }
    }

    g_list_free_full (locked_files, (GDestroyNotify)file_lock_info_free);
}
#endif

static void *
lock_office_file_worker (void *vdata)
{
    GAsyncQueue *queue = (GAsyncQueue *)vdata;
    LockOfficeJob *job;

    /* unlock_closed_office_files (); */

    while (1) {
        job = g_async_queue_pop (queue);
        if (!job)
            break;

        if (job->lock)
            do_lock_office_file (job);
        else
            do_unlock_office_file (job);

        lock_office_job_free (job);
    }

    return NULL;
}

static void
lock_office_file_on_server (SeafRepo *repo, const char *path)
{
    LockOfficeJob *job;
    GAsyncQueue *queue = seaf->repo_mgr->priv->lock_office_job_queue;

    if (!seaf_repo_manager_server_is_pro (seaf->repo_mgr, repo->server_url))
        return;

    job = g_new0 (LockOfficeJob, 1);
    memcpy (job->repo_id, repo->id, 36);
    job->path = g_strdup(path);
    job->lock = TRUE;

    g_async_queue_push (queue, job);
}

static void
unlock_office_file_on_server (SeafRepo *repo, const char *path)
{
    LockOfficeJob *job;
    GAsyncQueue *queue = seaf->repo_mgr->priv->lock_office_job_queue;

    if (!seaf_repo_manager_server_is_pro (seaf->repo_mgr, repo->server_url))
        return;

    job = g_new0 (LockOfficeJob, 1);
    memcpy (job->repo_id, repo->id, 36);
    job->path = g_strdup(path);
    job->lock = FALSE;

    g_async_queue_push (queue, job);
}

#endif

static int
apply_worktree_changes_to_index (SeafRepo *repo, struct index_state *istate,
                                 SeafileCrypt *crypt, GList *ignore_list,
                                 LockedFileSet *fset)
{
    WTStatus *status;
    WTEvent *event, *next_event;
    gboolean not_found;
#if defined WIN32 || defined __APPLE__
    char *office_path = NULL;
#endif

    status = seaf_wt_monitor_get_worktree_status (seaf->wt_monitor, repo->id);
    if (!status) {
        seaf_warning ("Can't find worktree status for repo %s(%.8s).\n",
                      repo->name, repo->id);
        return -1;
    }

    update_path_sync_status (repo, status, istate, ignore_list);

    GList *scanned_dirs = NULL, *scanned_del_dirs = NULL;

    WTEvent *last_event;

    pthread_mutex_lock (&status->q_lock);
    last_event = g_queue_peek_tail (status->event_q);
    pthread_mutex_unlock (&status->q_lock);

    if (!last_event) {
        seaf_message ("All events are processed for repo %s.\n", repo->id);
        status->partial_commit = FALSE;
        goto out;
    }

    gint64 total_size = 0;

    while (1) {
        pthread_mutex_lock (&status->q_lock);
        event = g_queue_pop_head (status->event_q);
        next_event = g_queue_peek_head (status->event_q);
        pthread_mutex_unlock (&status->q_lock);
        if (!event)
            break;

        /* Scanned dirs list is used to avoid redundant scan of consecutive
           CREATE_OR_UPDATE events. When we see other events, we should
           clear the list. Otherwise in some cases we'll get wrong result.
           For example, the following sequence (run with a script):
           1. Add a dir with files
           2. Delete the dir with files
           3. Add back the same dir again.
        */
        if (event->ev_type != WT_EVENT_CREATE_OR_UPDATE) {
            g_list_free_full (scanned_dirs, g_free);
            scanned_dirs = NULL;
        }

        switch (event->ev_type) {
        case WT_EVENT_CREATE_OR_UPDATE:
            /* If consecutive CREATE_OR_UPDATE events present
               in the event queue, only process the last one.
            */
            if (next_event &&
                next_event->ev_type == event->ev_type &&
                strcmp (next_event->path, event->path) == 0)
                break;

            /* CREATE_OR_UPDATE event tells us the exact path of changed file/dir.
             * If the event path is not writable, we don't need to check the paths
             * under the event path.
             */
            if (!is_path_writable(repo->id,
                                  repo->is_readonly, event->path)) {
                char *filename = g_path_get_basename (event->path);
                if (seaf_repo_manager_is_ignored_hidden_file(filename)) {
                    g_free (filename);
                    break;
                }
                g_free (filename);

                char *fullpath = g_build_path(PATH_SEPERATOR, repo->worktree, event->path, NULL);                
                struct cache_entry *ce = index_name_exists(istate, event->path, strlen(event->path), 0);
                SeafStat st;
                if (ce != NULL &&
                    seaf_stat (fullpath, &st) == 0 &&
                    ce->ce_mtime.sec == st.st_mtime &&
                    ce->ce_size == st.st_size) {
                    g_free (fullpath);
                    break;
                }

                send_file_sync_error_notification (repo->id, repo->name, event->path,
                                                   SYNC_ERROR_ID_UPDATE_TO_READ_ONLY_REPO);
                seaf_debug ("%s is not writable, ignore.\n", event->path);

                g_free (fullpath);
                break;
            }

#if defined WIN32 || defined __APPLE__
            office_path = NULL;
            if (is_office_lock_file (repo->worktree, event->path, &office_path))
                lock_office_file_on_server (repo, office_path);
            g_free (office_path);
#endif

            if (handle_add_files (repo, istate, crypt, ignore_list,
                                  fset,
                                  status, event,
                                  &scanned_dirs, &total_size))
                goto out;

            break;
        case WT_EVENT_SCAN_DIR:
            if (handle_add_files (repo, istate, crypt, ignore_list,
                                  fset,
                                  status, event,
                                  &scanned_dirs, &total_size))
                goto out;

            break;
        case WT_EVENT_DELETE:
            seaf_sync_manager_delete_active_path (seaf->sync_mgr,
                                                  repo->id,
                                                  event->path);

#if defined WIN32 || defined __APPLE__
            office_path = NULL;
            if (is_office_lock_file (repo->worktree, event->path, &office_path))
                unlock_office_file_on_server (repo, office_path);
            g_free (office_path);
#endif

            if (check_full_path_ignore(repo->worktree, event->path, ignore_list))
                break;

            if (!is_path_writable(repo->id,
                                  repo->is_readonly, event->path)) {
                seaf_debug ("%s is not writable, ignore.\n", event->path);
                break;
            }

            if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                      repo->id, event->path)) {
                seaf_debug ("Delete: %s is locked on server, ignore.\n", event->path);
                /* send_sync_error_notification (repo->id, NULL, event->path, */
                /*                               SYNC_ERROR_ID_FILE_LOCKED); */
                break;
            }

            if (check_locked_file_before_remove (fset, event->path)) {
                not_found = FALSE;
                remove_from_index_with_prefix (istate, event->path, &not_found);
                if (not_found)
                    scan_subtree_for_deletion (repo->id,
                                               istate,
                                               repo->worktree, event->path,
                                               ignore_list, fset,
                                               repo->is_readonly,
                                               &scanned_del_dirs,
                                               repo->changeset);

                remove_from_changeset (repo->changeset,
                                       DIFF_STATUS_DELETED,
                                       event->path,
                                       FALSE,
                                       NULL);

                try_add_empty_parent_dir_entry_from_wt (repo->worktree,
                                                        istate,
                                                        ignore_list,
                                                        event->path);
            }
            break;
        case WT_EVENT_RENAME:
            handle_rename (repo, istate, crypt, ignore_list, fset, event, &scanned_del_dirs, &total_size);
            break;
        case WT_EVENT_ATTRIB:
            if (!is_path_writable(repo->id,
                                  repo->is_readonly, event->path)) {
                seaf_debug ("%s is not writable, ignore.\n", event->path);
                break;
            }
            update_attributes (repo, istate, repo->worktree, event->path);
            break;
        case WT_EVENT_OVERFLOW:
            seaf_warning ("Kernel event queue overflowed, fall back to scan.\n");
            scan_worktree_for_changes (istate, repo, crypt, ignore_list, fset);
            break;
        }

        if (event == last_event) {
            wt_event_free (event);
            seaf_message ("All events are processed for repo %s.\n", repo->id);
            status->partial_commit = FALSE;
            break;
        } else
            wt_event_free (event);
    }

out:
    wt_status_unref (status);
    string_list_free (scanned_dirs);
    string_list_free (scanned_del_dirs);

    return 0;
}

static int
index_add (SeafRepo *repo, struct index_state *istate, gboolean is_force_commit)
{
    SeafileCrypt *crypt = NULL;
    LockedFileSet *fset = NULL;
    GList *ignore_list = NULL;
    int ret = 0;

    if (repo->encrypted) {
        crypt = seafile_crypt_new (repo->enc_version, repo->enc_key, repo->enc_iv);
    }

#if defined WIN32 || defined __APPLE__
    if (repo->version > 0)
        fset = seaf_repo_manager_get_locked_file_set (seaf->repo_mgr, repo->id);
#endif

    ignore_list = seaf_repo_load_ignore_files (repo->worktree);

    if (!is_force_commit) {
        if (apply_worktree_changes_to_index (repo, istate, crypt, ignore_list, fset) < 0) {
            seaf_warning ("Failed to apply worktree changes to index.\n");
            ret = -1;
        }
    } else if (scan_worktree_for_changes (istate, repo, crypt, ignore_list, fset) < 0) {
        seaf_warning ("Failed to scan worktree for changes.\n");
        ret = -1;
    }

    seaf_repo_free_ignore_files (ignore_list);

#if defined WIN32 || defined __APPLE__
    locked_file_set_free (fset);
#endif

    g_free (crypt);

    return ret;
}

static int
commit_tree (SeafRepo *repo, const char *root_id,
             const char *desc, char commit_id[])
{
    SeafCommit *commit;

    commit = seaf_commit_new (NULL, repo->id, root_id,
                              repo->email ? repo->email
                              : "unknown",
                              seaf->client_id,
                              desc, 0);

    commit->parent_id = g_strdup (repo->head->commit_id);

    /* Add this computer's name to commit. */
    commit->device_name = g_strdup(seaf->client_name);
    commit->client_version = g_strdup (SEAFILE_CLIENT_VERSION);

    seaf_repo_to_commit (repo, commit);

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0)
        return -1;

    seaf_branch_set_commit (repo->head, commit->commit_id);
    seaf_branch_manager_update_branch (seaf->branch_mgr, repo->head);

    strcpy (commit_id, commit->commit_id);
    seaf_commit_unref (commit);

    return 0;
}

static gboolean
compare_index_changeset (struct index_state *istate, ChangeSet *changeset)
{
    struct cache_entry *ce;
    int i;
    gboolean ret = TRUE;

    for (i = 0; i < istate->cache_nr; ++i) {
        ce = istate->cache[i];

        if (!(ce->ce_flags & CE_ADDED))
            continue;

        seaf_message ("checking %s in changeset.\n", ce->name);

        if (!changeset_check_path (changeset, ce->name,
                                   ce->sha1, ce->ce_mode, ce->ce_mtime.sec))
            ret = FALSE;
    }

    return ret;
}

#if 0
static int 
print_index (struct index_state *istate)
{
    int i;
    struct cache_entry *ce;
    char id[41];
    seaf_message ("Totally %u entries in index, version %u.\n",
                  istate->cache_nr, istate->version);
    for (i = 0; i < istate->cache_nr; ++i) {
        ce = istate->cache[i];
        rawdata_to_hex (ce->sha1, id, 20);
        seaf_message ("%s, %s, %o, %"G_GINT64_FORMAT", %s, %"G_GINT64_FORMAT", %d\n",
                      ce->name, id, ce->ce_mode, 
                      ce->ce_mtime.sec, ce->modifier, ce->ce_size, ce_stage(ce));
    }

    return 0;
}
#endif

char *
seaf_repo_index_commit (SeafRepo *repo,
                        gboolean is_force_commit,
                        gboolean is_initial_commit,
                        GError **error)
{
    SeafRepoManager *mgr = repo->manager;
    struct index_state istate;
    char index_path[SEAF_PATH_MAX];
    SeafCommit *head = NULL;
    char *new_root_id = NULL;
    char commit_id[41];
    ChangeSet *changeset = NULL;
    GList *diff_results = NULL;
    char *desc = NULL;
    char *ret = NULL;

    if (!check_worktree_common (repo))
        return NULL;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path, repo->version) < 0) {
        seaf_warning ("Failed to load index.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Internal data structure error");
        return NULL;
    }

    changeset = changeset_new (repo->id);
    if (!changeset) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Internal data structure error");
        goto out;
    }

    repo->changeset = changeset;

    if (index_add (repo, &istate, is_force_commit) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Failed to add");
        goto out;
    }

    if (!istate.cache_changed)
        goto out;

    if (!is_initial_commit && !is_force_commit) {
        new_root_id = commit_tree_from_changeset (changeset);
        if (!new_root_id) {
            seaf_warning ("Create commit tree failed for repo %s\n", repo->id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Failed to generate commit");
            goto out;
        }
    } else {
        char hex[41];
        struct cache_tree *it = cache_tree ();
        if (cache_tree_update (repo->id, repo->version,
                               repo->worktree,
                               it, istate.cache,
                               istate.cache_nr, 0, 0, commit_trees_cb) < 0) {
            seaf_warning ("Failed to build cache tree");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                         "Internal data structure error");
            cache_tree_free (&it);
            goto out;
        }
        rawdata_to_hex (it->sha1, hex, 20);
        new_root_id = g_strdup(hex);
        cache_tree_free (&it);
    }

    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id, repo->version,
                                           repo->head->commit_id);
    if (!head) {
        seaf_warning ("Head commit %s for repo %s not found\n",
                      repo->head->commit_id, repo->id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Data corrupt");
        goto out;
    }

    if (strcmp (head->root_id, new_root_id) == 0) {
        seaf_message ("No change to the fs tree of repo %s\n", repo->id);
        /* If no file modification and addition are missing, and the new root
         * id is the same as the old one, skip commiting.
         */
        if (!is_initial_commit && !is_force_commit)
            compare_index_changeset (&istate, changeset);

        update_index (&istate, index_path);
        goto out;
    }

    diff_commit_roots (repo->id, repo->version, head->root_id, new_root_id, &diff_results, TRUE);
    desc = diff_results_to_description (diff_results);
    if (!desc)
        desc = g_strdup("");

    if (commit_tree (repo, new_root_id, desc, commit_id) < 0) {
        seaf_warning ("Failed to save commit file");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Internal error");
        goto out;
    }

    if (update_index (&istate, index_path) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Internal error");
        goto out;
    }

    g_signal_emit_by_name (seaf, "repo-committed", repo);

    ret = g_strdup(commit_id);

out:
    g_free (desc);
    seaf_commit_unref (head);
    g_free (new_root_id);
    changeset_free (changeset);
    g_list_free_full (diff_results, (GDestroyNotify)diff_entry_free);
    discard_index (&istate);
    return ret;
}

#ifdef DEBUG_UNPACK_TREES
static void
print_unpack_result (struct index_state *result)
{
	int i;
	struct cache_entry *ce;

	for (i = 0; i < result->cache_nr; ++i) {
		ce = result->cache[i];
		printf ("%s\t", ce->name);
		if (ce->ce_flags & CE_UPDATE)
			printf ("update/add\n");
		else if (ce->ce_flags & CE_WT_REMOVE)
			printf ("remove\n");
		else
			printf ("unchange\n");
	}
}

static int 
print_index (struct index_state *istate)
{
    printf ("Index timestamp: %d\n", istate->timestamp.sec);

    int i;
    struct cache_entry *ce;
    char id[41];
    printf ("Totally %u entries in index.\n", istate->cache_nr);
    for (i = 0; i < istate->cache_nr; ++i) {
        ce = istate->cache[i];
        rawdata_to_hex (ce->sha1, id, 20);
        printf ("%s\t%s\t%o\t%d\t%d\n", ce->name, id, ce->ce_mode, 
                ce->ce_ctime.sec, ce->ce_mtime.sec);
    }

    return 0;
}
#endif  /* DEBUG_UNPACK_TREES */

GList *
seaf_repo_diff (SeafRepo *repo, const char *old, const char *new, int fold_dir_diff, char **error)
{
    SeafCommit *c1 = NULL, *c2 = NULL;
    int ret = 0;
    GList *diff_entries = NULL;

    c2 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                         repo->id, repo->version,
                                         new);
    if (!c2) {
        *error = g_strdup("Can't find new commit");
        return NULL;
    }

    if (old == NULL || old[0] == '\0') {
        if (c2->parent_id && c2->second_parent_id) {
            ret = diff_merge (c2, &diff_entries, fold_dir_diff);
            seaf_commit_unref (c2);
            if (ret < 0) {
                *error = g_strdup("Failed to do diff");
                g_list_free_full (diff_entries, (GDestroyNotify)diff_entry_free);
                return NULL;
            }
            return diff_entries;
        }

        if (!c2->parent_id) {
            seaf_commit_unref (c2);
            return NULL;
        }
        c1 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->id, repo->version,
                                             c2->parent_id);
    } else {
        c1 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->id, repo->version, old);
    }

    if (!c1) {
        *error = g_strdup("Can't find old commit");
        seaf_commit_unref (c2);
        return NULL;
    }

    /* do diff */
    ret = diff_commits (c1, c2, &diff_entries, fold_dir_diff);
    if (ret < 0) {
        g_list_free_full (diff_entries, (GDestroyNotify)diff_entry_free);
        diff_entries = NULL;
        *error = g_strdup("Failed to do diff");
    }

    seaf_commit_unref (c1);
    seaf_commit_unref (c2);

    return diff_entries;
}

int
checkout_empty_dir (const char *worktree,
                    const char *name,
                    gint64 mtime,
                    struct cache_entry *ce,
                    GHashTable *conflict_hash,
                    GHashTable *no_conflict_hash)
{
    char *path;
    gboolean case_conflict = FALSE;

    path = build_checkout_path (worktree, name, strlen(name));

    if (!path)
        return FETCH_CHECKOUT_FAILED;

    if (!seaf_util_exists (path) && seaf_util_mkdir (path, 0777) < 0) {
        seaf_warning ("Failed to create empty dir %s in checkout.\n", path);
        g_free (path);
        return FETCH_CHECKOUT_FAILED;
    }

    if (mtime != 0 && seaf_set_file_time (path, mtime) < 0) {
        seaf_warning ("Failed to set mtime for %s.\n", path);
    }

    if (case_conflict) {
        ce->ce_flags |= CE_REMOVE;
        g_free (path);
        return FETCH_CHECKOUT_SUCCESS;
    }

    SeafStat st;
    seaf_stat (path, &st);
    fill_stat_cache_info (ce, &st);

    g_free (path);
    return FETCH_CHECKOUT_SUCCESS;
}

static struct cache_entry *
cache_entry_from_diff_entry (DiffEntry *de)
{
    int size, namelen;
    struct cache_entry *ce;

    namelen = strlen(de->name);
    size = cache_entry_size(namelen);
    ce = calloc(1, size);
    memcpy(ce->name, de->name, namelen);
    ce->ce_flags = namelen;

    memcpy (ce->sha1, de->sha1, 20);
    ce->modifier = g_strdup(de->modifier);
    ce->ce_size = de->size;
    ce->ce_mtime.sec = de->mtime;

    if (S_ISREG(de->mode))
        ce->ce_mode = create_ce_mode (de->mode);
    else
        ce->ce_mode = S_IFDIR;

    return ce;
}

#define UPDATE_CACHE_SIZE_LIMIT 100 * (1 << 20) /* 100MB */

typedef struct FileTxData {
    char repo_id[37];
    int repo_version;
    SeafileCrypt *crypt;
    HttpTxTask *http_task;
    char conflict_head_id[41];
    GAsyncQueue *finished_tasks;
} FileTxData;

typedef struct FileTxTask {
    char *path;
    struct cache_entry *ce;
    DiffEntry *de;
    gboolean new_ce;
    gboolean skip_fetch;

    int result;
    gboolean no_checkout;
    gboolean force_conflict;
} FileTxTask;

static void
file_tx_task_free (FileTxTask *task)
{
    if (!task)
        return;

    g_free (task->path);
    g_free (task);
}

static int
fetch_file_http (FileTxData *data, FileTxTask *file_task)
{
    int repo_version = data->repo_version;
    struct cache_entry *ce = file_task->ce;
    DiffEntry *de = file_task->de;
    SeafileCrypt *crypt = data->crypt;
    char *path = file_task->path;
    HttpTxTask *http_task = data->http_task;
    SeafStat st;
    char file_id[41];
    gboolean path_exists = FALSE;

    rawdata_to_hex (de->sha1, file_id, 20);

    path_exists = (seaf_stat (path, &st) == 0);

    if (path_exists && S_ISREG(st.st_mode)) {
        if (st.st_mtime == ce->ce_mtime.sec) {
            /* Worktree and index are consistent. */
            if (memcmp (de->sha1, ce->sha1, 20) == 0) {
                seaf_debug ("wt and index are consistent. no need to checkout.\n");
                file_task->no_checkout = TRUE;

                /* Update mode if necessary. */
                if (de->mode != ce->ce_mode) {
#ifndef WIN32
                    chmod (path, de->mode & ~S_IFMT);
                    ce->ce_mode = de->mode;
#endif
                }

                /* Update mtime if necessary. */
                if (de->mtime != ce->ce_mtime.sec) {
                    seaf_set_file_time (path, de->mtime);
                    ce->ce_mtime.sec = de->mtime;
                }

                fill_stat_cache_info (ce, &st);

                return FETCH_CHECKOUT_SUCCESS;
            }
            /* otherwise we have to checkout the file. */
        } else {
            if (compare_file_content (path, &st, de->sha1, crypt, repo_version) == 0) {
                /* This happens after the worktree file was updated,
                 * but the index was not. Just need to update the index.
                 */
                seaf_debug ("update index only.\n");
                file_task->no_checkout = TRUE;
                fill_stat_cache_info (ce, &st);
                return FETCH_CHECKOUT_SUCCESS;
            } else {
                /* Conflict. The worktree file was updated by the user. */
                seaf_message ("File %s is updated by user. "
                              "Will checkout to conflict file later.\n", path);
                file_task->force_conflict = TRUE;
            }
        }
    }

    /* Download the blocks of this file. */
    int rc;
    rc = http_tx_task_download_file_blocks (http_task, file_id);
    if (http_task->state == HTTP_TASK_STATE_CANCELED) {
        return FETCH_CHECKOUT_CANCELED;
    }
    if (rc < 0) {
        return FETCH_CHECKOUT_TRANSFER_ERROR;
    }

    return FETCH_CHECKOUT_SUCCESS;
}

static void
fetch_file_thread_func (gpointer data, gpointer user_data)
{
    FileTxTask *task = data;
    FileTxData *tx_data = user_data;
    GAsyncQueue *finished_tasks = tx_data->finished_tasks;
    DiffEntry *de = task->de;
    char *repo_id = tx_data->repo_id;
    char file_id[41];
    gboolean is_clone = tx_data->http_task->is_clone;
    int rc = FETCH_CHECKOUT_SUCCESS;

    if (task->skip_fetch)
        goto out;

    rawdata_to_hex (de->sha1, file_id, 20);

    /* seaf_message ("Download file %s for repo %s\n", de->name, repo_id); */

    if (!is_clone)
        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              repo_id,
                                              de->name,
                                              de->mode,
                                              SYNC_STATUS_SYNCING,
                                              TRUE);

    rc = fetch_file_http (tx_data, task);

    /* Even if the file failed to check out, still need to update index.
     * But we have to stop after transfer errors.
     */
    if (rc == FETCH_CHECKOUT_CANCELED) {
        seaf_debug ("Transfer canceled.\n");
    } else if (rc == FETCH_CHECKOUT_TRANSFER_ERROR) {
        seaf_warning ("Transfer failed.\n");
    }

out:
    task->result = rc;
    g_async_queue_push (finished_tasks, task);
}

static int
schedule_file_fetch (GThreadPool *tpool,
                     const char *repo_id,
                     const char *repo_name,
                     const char *worktree,
                     struct index_state *istate,
                     DiffEntry *de,
                     GHashTable *pending_tasks,
                     GHashTable *conflict_hash,
                     GHashTable *no_conflict_hash)
{
    struct cache_entry *ce;
    gboolean new_ce = FALSE;
    gboolean skip_fetch = FALSE;
    char *path = NULL;
    FileTxTask *file_task;

    ce = index_name_exists (istate, de->name, strlen(de->name), 0);
    if (!ce) {
        ce = cache_entry_from_diff_entry (de);
        new_ce = TRUE;
    }

    IgnoreReason reason;
    if (should_ignore_on_checkout (de->name, &reason)) {
        seaf_message ("Path %s is invalid on Windows, skip checkout\n",
                      de->name);
        if (reason == IGNORE_REASON_END_SPACE_PERIOD)
            send_file_sync_error_notification (repo_id, repo_name, de->name,
                                               SYNC_ERROR_ID_PATH_END_SPACE_PERIOD);
        else if (reason == IGNORE_REASON_INVALID_CHARACTER)
            send_file_sync_error_notification (repo_id, repo_name, de->name,
                                               SYNC_ERROR_ID_PATH_INVALID_CHARACTER);
        skip_fetch = TRUE;
    }

    if (!skip_fetch) {
        path = build_checkout_path (worktree, de->name, strlen(de->name));
        if (!path) {
            if (new_ce)
                cache_entry_free (ce);
            return FETCH_CHECKOUT_FAILED;
        }
    }

    file_task = g_new0 (FileTxTask, 1);
    file_task->de = de;
    file_task->ce = ce;
    file_task->path = path;
    file_task->new_ce = new_ce;
    file_task->skip_fetch = skip_fetch;

    if (!g_hash_table_lookup (pending_tasks, de->name)) {
        g_hash_table_insert (pending_tasks, g_strdup(de->name), file_task);
        g_thread_pool_push (tpool, file_task, NULL);
    } else {
        file_tx_task_free (file_task);
    }

    return FETCH_CHECKOUT_SUCCESS;
}

static void
cleanup_file_blocks_http (HttpTxTask *task, const char *file_id)
{
    Seafile *file;
    int i;
    char *block_id;
    int *pcnt;

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                        task->repo_id, task->repo_version,
                                        file_id);
    if (!file) {
        seaf_warning ("Failed to load seafile object %s:%s\n",
                      task->repo_id, file_id);
        return;
    }

    for (i = 0; i < file->n_blocks; ++i) {
        block_id = file->blk_sha1s[i];

        pthread_mutex_lock (&task->ref_cnt_lock);

        pcnt = g_hash_table_lookup (task->blk_ref_cnts, block_id);
        if (pcnt) {
            --(*pcnt);
            if (*pcnt > 0) {
                pthread_mutex_unlock (&task->ref_cnt_lock);
                continue;
            }
        }

        seaf_block_manager_remove_block (seaf->block_mgr,
                                         task->repo_id, task->repo_version,
                                         block_id);
        g_hash_table_remove (task->blk_ref_cnts, block_id);

        pthread_mutex_unlock (&task->ref_cnt_lock);
    }

    seafile_unref (file);
}

static gboolean
check_path_conflict (const char *path, char **orig_path)
{
    gboolean is_conflict = FALSE;
    GError *error = NULL;

    is_conflict = g_regex_match (conflict_pattern, path, 0, NULL);
    if (is_conflict) {
        *orig_path = g_regex_replace_literal (conflict_pattern, path, -1,
                                              0, "", 0, &error);
        if (!*orig_path)
            is_conflict = FALSE;
    }

    return is_conflict;
}

static int
checkout_file_http (FileTxData *data,
                    FileTxTask *file_task,
                    const char *worktree,
                    GHashTable *conflict_hash,
                    GHashTable *no_conflict_hash,
                    const char *conflict_head_id,
                    LockedFileSet *fset)
{
    char *repo_id = data->repo_id;
    int repo_version = data->repo_version;
    struct cache_entry *ce = file_task->ce;
    DiffEntry *de = file_task->de;
    SeafileCrypt *crypt = data->crypt;
    gboolean no_checkout = file_task->no_checkout;
    gboolean force_conflict = file_task->force_conflict;
    HttpTxTask *http_task = data->http_task;
    gboolean path_exists;
    gboolean case_conflict = FALSE;
    SeafStat st;
    char file_id[41];
    gboolean locked_on_server = FALSE;

    if (no_checkout)
        return FETCH_CHECKOUT_SUCCESS;

    if (should_ignore_on_checkout (de->name, NULL))
        return FETCH_CHECKOUT_SUCCESS;

    rawdata_to_hex (de->sha1, file_id, 20);

    locked_on_server = seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                             repo_id, de->name);

#if defined WIN32 || defined __APPLE__
    if (do_check_file_locked (de->name, worktree, locked_on_server)) {
        if (!locked_file_set_lookup (fset, de->name))
            send_file_sync_error_notification (repo_id, NULL, de->name,
                                               SYNC_ERROR_ID_FILE_LOCKED_BY_APP);

        locked_file_set_add_update (fset, de->name, LOCKED_OP_UPDATE,
                                    ce->ce_mtime.sec, file_id);
        /* Stay in syncing status if the file is locked. */

        return FETCH_CHECKOUT_SUCCESS;
    }
#endif

    path_exists = (seaf_stat (file_task->path, &st) == 0);

    /* The worktree file may have been changed when we're downloading the blocks. */
    if (!file_task->new_ce &&
        path_exists && S_ISREG(st.st_mode) &&
        !force_conflict) {
        if (st.st_mtime != ce->ce_mtime.sec) {
            seaf_message ("File %s is updated by user. "
                          "Will checkout to conflict file later.\n", file_task->path);
            force_conflict = TRUE;
        }
    }

    /* Temporarily unlock the file if it's locked on server, so that the client
     * itself can write to it. 
     */
    if (locked_on_server)
        seaf_filelock_manager_unlock_wt_file (seaf->filelock_mgr,
                                              repo_id, de->name);

    /* then checkout the file. */
    gboolean conflicted = FALSE;
    if (seaf_fs_manager_checkout_file (seaf->fs_mgr,
                                       repo_id,
                                       repo_version,
                                       file_id,
                                       file_task->path,
                                       de->mode,
                                       de->mtime,
                                       crypt,
                                       de->name,
                                       conflict_head_id,
                                       force_conflict,
                                       &conflicted,
                                       http_task->email) < 0) {
        seaf_warning ("Failed to checkout file %s.\n", file_task->path);

        if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                  repo_id, de->name))
            seaf_filelock_manager_lock_wt_file (seaf->filelock_mgr,
                                                repo_id, de->name);

        return FETCH_CHECKOUT_FAILED;
    }

    if (locked_on_server)
        seaf_filelock_manager_lock_wt_file (seaf->filelock_mgr,
                                            repo_id, de->name);

    cleanup_file_blocks_http (http_task, file_id);

    if (conflicted) {
        send_file_sync_error_notification (repo_id, NULL, de->name, SYNC_ERROR_ID_CONFLICT);
    } else if (!http_task->is_clone) {
        char *orig_path = NULL;
        if (check_path_conflict (de->name, &orig_path))
            send_file_sync_error_notification (repo_id, NULL, orig_path, SYNC_ERROR_ID_CONFLICT);
        g_free (orig_path);
    }

    /* If case conflict, this file will be checked out to another path.
     * Remove the current entry, otherwise it won't be removed later
     * since it's timestamp is 0.
     */
    if (case_conflict)
        ce->ce_flags |= CE_REMOVE;

    /* finally fill cache_entry info */
    /* Only update index if we checked out the file without any error
     * or conflicts. The ctime of the entry will remain 0 if error.
     */
    seaf_stat (file_task->path, &st);
    fill_stat_cache_info (ce, &st);

    return FETCH_CHECKOUT_SUCCESS;
}

static void
handle_dir_added_de (const char *repo_id,
                     const char *repo_name,
                     const char *worktree,
                     struct index_state *istate,
                     DiffEntry *de,
                     GHashTable *conflict_hash,
                     GHashTable *no_conflict_hash)
{
    seaf_debug ("Checkout empty dir %s.\n", de->name);

    struct cache_entry *ce;
    gboolean add_ce = FALSE;

    ce = index_name_exists (istate, de->name, strlen(de->name), 0);
    if (!ce) {
        ce = cache_entry_from_diff_entry (de);
        add_ce = TRUE;
    }

    IgnoreReason reason;
    if (should_ignore_on_checkout (de->name, &reason)) {
        seaf_message ("Path %s is invalid on Windows, skip checkout\n",
                      de->name);
        if (reason == IGNORE_REASON_END_SPACE_PERIOD)
            send_file_sync_error_notification (repo_id, repo_name, de->name,
                                               SYNC_ERROR_ID_PATH_END_SPACE_PERIOD);
        else if (reason == IGNORE_REASON_INVALID_CHARACTER)
            send_file_sync_error_notification (repo_id, repo_name, de->name,
                                               SYNC_ERROR_ID_PATH_INVALID_CHARACTER);
        goto update_index;
    }

    checkout_empty_dir (worktree,
                        de->name,
                        de->mtime,
                        ce,
                        conflict_hash,
                        no_conflict_hash);

    seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                          repo_id,
                                          de->name,
                                          de->mode,
                                          SYNC_STATUS_SYNCED,
                                          TRUE);

update_index:
    if (add_ce) {
        if (!(ce->ce_flags & CE_REMOVE)) {
            add_index_entry (istate, ce,
                             (ADD_CACHE_OK_TO_ADD|ADD_CACHE_OK_TO_REPLACE));
        }
    } else
        ce->ce_mtime.sec = de->mtime;
}

#define DEFAULT_DOWNLOAD_THREADS 3

static int
download_files_http (const char *repo_id,
                     int repo_version,
                     const char *worktree,
                     struct index_state *istate,
                     const char *index_path,
                     SeafileCrypt *crypt,
                     HttpTxTask *http_task,
                     GList *results,
                     GHashTable *conflict_hash,
                     GHashTable *no_conflict_hash,
                     const char *conflict_head_id,
                     LockedFileSet *fset)
{
    struct cache_entry *ce;
    DiffEntry *de;
    gint64 checkout_size = 0;
    GThreadPool *tpool;
    GAsyncQueue *finished_tasks;
    GHashTable *pending_tasks;
    GList *ptr;
    FileTxTask *task;
    int ret = FETCH_CHECKOUT_SUCCESS;

    finished_tasks = g_async_queue_new ();

    FileTxData data;
    memset (&data, 0, sizeof(data));
    memcpy (data.repo_id, repo_id, 36);
    data.repo_version = repo_version;
    data.crypt = crypt;
    data.http_task = http_task;
    memcpy (data.conflict_head_id, conflict_head_id, 40);
    data.finished_tasks = finished_tasks;

    tpool = g_thread_pool_new (fetch_file_thread_func, &data,
                               DEFAULT_DOWNLOAD_THREADS, FALSE, NULL);

    pending_tasks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           g_free, (GDestroyNotify)file_tx_task_free);

    for (ptr = results; ptr != NULL; ptr = ptr->next) {
        de = ptr->data;

        if (de->status == DIFF_STATUS_DIR_ADDED) {
            handle_dir_added_de (repo_id, http_task->repo_name, worktree, istate, de,
                                 conflict_hash, no_conflict_hash);
        } else if (de->status == DIFF_STATUS_ADDED ||
                   de->status == DIFF_STATUS_MODIFIED) {
            if (FETCH_CHECKOUT_FAILED == schedule_file_fetch (tpool,
                                                              repo_id,
                                                              http_task->repo_name,
                                                              worktree,
                                                              istate,
                                                              de,
                                                              pending_tasks,
                                                              conflict_hash,
                                                              no_conflict_hash))
                continue;
        }
    }

    /* If there is no file need to be downloaded, return immediately. */
    if (g_hash_table_size(pending_tasks) == 0) {
        if (results != NULL)
            update_index (istate, index_path);
        goto out;
    }

    char file_id[41];
    while ((task = g_async_queue_pop (finished_tasks)) != NULL) {
        ce = task->ce;
        de = task->de;

        rawdata_to_hex (de->sha1, file_id, 20);
        /* seaf_message ("Finished downloading file %s for repo %s\n", */
        /*               de->name, repo_id); */

        if (task->result == FETCH_CHECKOUT_CANCELED ||
            task->result == FETCH_CHECKOUT_TRANSFER_ERROR) {
            ret = task->result;
            if (task->new_ce)
                cache_entry_free (task->ce);
            http_task->all_stop = TRUE;
            goto out;
        }

        int rc = checkout_file_http (&data, task, worktree,
                                     conflict_hash, no_conflict_hash,
                                     conflict_head_id, fset);

        if (!http_task->is_clone) {
            SyncStatus status;
            if (rc == FETCH_CHECKOUT_FAILED)
                status = SYNC_STATUS_ERROR;
            else
                status = SYNC_STATUS_SYNCED;
            seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                  repo_id,
                                                  de->name,
                                                  de->mode,
                                                  status,
                                                  TRUE);
        }

        if (task->new_ce) {
            if (!(ce->ce_flags & CE_REMOVE)) {
                add_index_entry (istate, task->ce,
                                 (ADD_CACHE_OK_TO_ADD|ADD_CACHE_OK_TO_REPLACE));
            }
        } else {
            ce->ce_mtime.sec = de->mtime;
            ce->ce_size = de->size;
            memcpy (ce->sha1, de->sha1, 20);
            if (ce->modifier) g_free (ce->modifier);
            ce->modifier = g_strdup(de->modifier);
            ce->ce_mode = create_ce_mode (de->mode);
        }

        g_hash_table_remove (pending_tasks, de->name);

        if (g_hash_table_size (pending_tasks) == 0)
            break;

        /* Save index file to disk after checking out some size of files.
         * This way we don't need to re-compare too many files if this
         * checkout is interrupted.
         */
        checkout_size += ce->ce_size;
        if (checkout_size >= UPDATE_CACHE_SIZE_LIMIT) {
            update_index (istate, index_path);
            checkout_size = 0;
        }
    }

    update_index (istate, index_path);

out:
    /* Wait until all threads exit.
     * This is necessary when the download is canceled or encountered error.
     */
    g_thread_pool_free (tpool, TRUE, TRUE);

    /* Free all pending file task structs. */
    g_hash_table_destroy (pending_tasks);

    g_async_queue_unref (finished_tasks);

    return ret;
}

static gboolean
expand_dir_added_cb (SeafFSManager *mgr,
                     const char *path,
                     SeafDirent *dent,
                     void *user_data,
                     gboolean *stop)
{
    GList **expanded = user_data;
    DiffEntry *de = NULL;
    unsigned char sha1[20];

    hex_to_rawdata (dent->id, sha1, 20);

    if (S_ISDIR(dent->mode) && strcmp(dent->id, EMPTY_SHA1) == 0)
        de = diff_entry_new (DIFF_TYPE_COMMITS, DIFF_STATUS_DIR_ADDED, sha1, path);
    else if (S_ISREG(dent->mode))
        de = diff_entry_new (DIFF_TYPE_COMMITS, DIFF_STATUS_ADDED, sha1, path);

    if (de) {
        de->mtime = dent->mtime;
        de->mode = dent->mode;
        de->modifier = g_strdup(dent->modifier);
        de->size = dent->size;
        *expanded = g_list_prepend (*expanded, de);
    }

    return TRUE;
}

/*
 * Expand DIR_ADDED results into multiple ADDED results.
 */
static int
expand_diff_results (const char *repo_id, int version,
                     const char *remote_root, const char *local_root,
                     GList **results)
{
    GList *ptr, *next;
    DiffEntry *de;
    char obj_id[41];
    GList *expanded = NULL;

    ptr = *results;
    while (ptr) {
        de = ptr->data;

        next = ptr->next;

        if (de->status == DIFF_STATUS_DIR_ADDED) {
            *results = g_list_delete_link (*results, ptr);

            rawdata_to_hex (de->sha1, obj_id, 20);
            if (seaf_fs_manager_traverse_path (seaf->fs_mgr,
                                               repo_id, version,
                                               remote_root,
                                               de->name,
                                               expand_dir_added_cb,
                                               &expanded) < 0) {
                diff_entry_free (de);
                goto error;
            }
            diff_entry_free (de);
        }

        ptr = next;
    }

    expanded = g_list_reverse (expanded);
    *results = g_list_concat (*results, expanded);

    return 0;

error:
    g_list_free_full (expanded, (GDestroyNotify)diff_entry_free);
    return -1;
}

static int
do_rename_in_worktree (DiffEntry *de, const char *worktree,
                       GHashTable *conflict_hash, GHashTable *no_conflict_hash)
{
    char *old_path, *new_path;
    int ret = 0;

    old_path = g_build_filename (worktree, de->name, NULL);

    if (seaf_util_exists (old_path)) {
        new_path = build_checkout_path (worktree, de->new_name, strlen(de->new_name));
        if (!new_path) {
            ret = -1;
            goto out;
        }

        if (seaf_util_rename (old_path, new_path) < 0) {
            seaf_warning ("Failed to rename %s to %s: %s.\n",
                          old_path, new_path, strerror(errno));
            ret = -1;
        }

        g_free (new_path);
    }

out:
    g_free (old_path);
    return ret;
}

static gboolean
is_built_in_ignored_file (const char *filename)
{
    GPatternSpec **spec = ignore_patterns;

    while (*spec) {
        if (g_pattern_match_string(*spec, filename))
            return TRUE;
        spec++;
    }

    if (!seaf->sync_extra_temp_file) {
        spec = office_temp_ignore_patterns;
        while (*spec) {
            if (g_pattern_match_string(*spec, filename))
                return TRUE;
            spec++;
        }
    }

    return FALSE;
}

#ifdef WIN32

/*
 * @path: path relative to the worktree, utf-8 encoded
 * @path_w: absolute path include worktree, utf-16 encoded.
 * Return 0 when successfully deleted the folder; otherwise -1.
 */
static int
delete_worktree_dir_recursive_win32 (struct index_state *istate,
                                     const char *path,
                                     const wchar_t *path_w)
{
    WIN32_FIND_DATAW fdata;
    HANDLE handle;
    wchar_t *pattern;
    wchar_t *sub_path_w;
    char *sub_path, *dname;
    int path_len_w;
    DWORD error;
    int ret = 0;
    guint64 mtime;
    gboolean builtin_ignored = FALSE;

    path_len_w = wcslen(path_w);

    pattern = g_new0 (wchar_t, (path_len_w + 3));
    wcscpy (pattern, path_w);
    wcscat (pattern, L"\\*");

    handle = FindFirstFileW (pattern, &fdata);
    g_free (pattern);

    if (handle == INVALID_HANDLE_VALUE) {
        seaf_warning ("FindFirstFile failed %s: %lu.\n",
                      path, GetLastError());
        return -1;
    }

    do {
        if (wcscmp (fdata.cFileName, L".") == 0 ||
            wcscmp (fdata.cFileName, L"..") == 0)
            continue;

        dname = g_utf16_to_utf8 (fdata.cFileName, -1, NULL, NULL, NULL);
        if (!dname)
            continue;

        sub_path_w = g_new0 (wchar_t, path_len_w + wcslen(fdata.cFileName) + 2);
        wcscpy (sub_path_w, path_w);
        wcscat (sub_path_w, L"\\");
        wcscat (sub_path_w, fdata.cFileName);

        sub_path = g_strconcat (path, "/", dname, NULL);
        builtin_ignored = is_built_in_ignored_file(dname);
        g_free (dname);

        if (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (delete_worktree_dir_recursive_win32 (istate, sub_path, sub_path_w) < 0) {
                ret = -1;
            }
        } else {
            struct cache_entry *ce;
            /* Files like .DS_Store and Thumbs.db should be deleted any way. */
            if (!builtin_ignored) {
                mtime = (guint64)file_time_to_unix_time (&fdata.ftLastWriteTime);
                ce = index_name_exists (istate, sub_path, strlen(sub_path), 0);
                if (!ce || (!is_eml_file (dname) && ce->ce_mtime.sec != mtime)) {
                    seaf_message ("File %s is changed, skip deleting it.\n", sub_path);
                    g_free (sub_path_w);
                    g_free (sub_path);
                    ret = -1;
                    continue;
                }
            }

            if (!DeleteFileW (sub_path_w)) {
                error = GetLastError();
                seaf_warning ("Failed to delete file %s: %lu.\n",
                              sub_path, error);
                ret = -1;
            }
        }

        g_free (sub_path_w);
        g_free (sub_path);
    } while (FindNextFileW (handle, &fdata) != 0);

    error = GetLastError();
    if (error != ERROR_NO_MORE_FILES) {
        seaf_warning ("FindNextFile failed %s: %lu.\n",
                      path, error);
        ret = -1;
    }

    FindClose (handle);

    if (ret < 0)
        return ret;

    int n = 0;
    while (!RemoveDirectoryW (path_w)) {
        error = GetLastError();
        seaf_warning ("Failed to remove dir %s: %lu.\n",
                      path, error);
        if (error != ERROR_DIR_NOT_EMPTY) {
            ret = -1;
            break;
        }
        if (++n >= 3) {
            ret = -1;
            break;
        }
        /* Sleep 100ms and retry. */
        g_usleep (100000);
        seaf_warning ("Retry remove dir %s.\n", path);
    }

    return ret;
}

#else

static int
delete_worktree_dir_recursive (struct index_state *istate,
                               const char *path,
                               const char *full_path)
{
    GDir *dir;
    const char *dname;
    char *dname_nfc;
    GError *error = NULL;
    char *sub_path, *full_sub_path;
    SeafStat st;
    int ret = 0;
    gboolean builtin_ignored = FALSE;

    dir = g_dir_open (full_path, 0, &error);
    if (!dir) {
        seaf_warning ("Failed to open dir %s: %s.\n", full_path, error->message);
        return -1;
    }

    while ((dname = g_dir_read_name (dir)) != NULL) {
        dname_nfc = g_utf8_normalize (dname, -1, G_NORMALIZE_NFC);
        sub_path = g_build_path ("/", path, dname_nfc, NULL);
        full_sub_path = g_build_path ("/", full_path, dname_nfc, NULL);
        builtin_ignored = is_built_in_ignored_file (dname_nfc);
        g_free (dname_nfc);

        if (lstat (full_sub_path, &st) < 0) {
            seaf_warning ("Failed to stat %s.\n", full_sub_path);
            g_free (sub_path);
            g_free (full_sub_path);
            ret = -1;
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (delete_worktree_dir_recursive (istate, sub_path, full_sub_path) < 0)
                ret = -1;
        } else {
            struct cache_entry *ce;
            /* Files like .DS_Store and Thumbs.db should be deleted any way. */
            if (!builtin_ignored) {
                ce = index_name_exists (istate, sub_path, strlen(sub_path), 0);
                if (!ce || ce->ce_mtime.sec != st.st_mtime) {
                    seaf_message ("File %s is changed, skip deleting it.\n", full_sub_path);
                    g_free (sub_path);
                    g_free (full_sub_path);
                    ret = -1;
                    continue;
                }
            }

            /* Delete all other file types. */
            if (seaf_util_unlink (full_sub_path) < 0) {
                seaf_warning ("Failed to delete file %s: %s.\n",
                              full_sub_path, strerror(errno));
                ret = -1;
            }
        }

        g_free (sub_path);
        g_free (full_sub_path);
    }

    g_dir_close (dir);

    if (ret < 0)
        return ret;

    if (g_rmdir (full_path) < 0) {
        seaf_warning ("Failed to delete dir %s: %s.\n", full_path, strerror(errno));
        ret = -1;
    }

    return ret;
}

#endif  /* WIN32 */

#define SEAFILE_RECYCLE_BIN_FOLDER "recycle-bin"

static int
move_dir_to_recycle_bin (const char *dir_path)
{
    char *trash_folder = g_build_path ("/", seaf->worktree_dir, SEAFILE_RECYCLE_BIN_FOLDER, NULL);
    if (checkdir_with_mkdir (trash_folder) < 0) {
        seaf_warning ("Seafile trash folder %s doesn't exist and cannot be created.\n",
                      trash_folder);
        g_free (trash_folder);
        return -1;
    }
    g_free (trash_folder);

    char *basename = g_path_get_basename (dir_path);
    char *dst_path = g_build_path ("/", seaf->worktree_dir, SEAFILE_RECYCLE_BIN_FOLDER, basename, NULL);
    int ret = 0;

    int n;
    char *tmp_path;
    for (n = 1; n < 10; ++n) {
        if (g_file_test (dst_path, G_FILE_TEST_EXISTS)) {
            tmp_path = g_strdup_printf ("%s(%d)", dst_path, n);
            g_free (dst_path);
            dst_path = tmp_path;
            continue;
        }
        break;
    }

    if (seaf_util_rename (dir_path, dst_path) < 0) {
        seaf_warning ("Failed to move %s to Seafile recycle bin %s: %s\n",
                      dir_path, dst_path, strerror(errno));
        ret = -1;
        goto out;
    }

    seaf_message ("Moved folder %s to Seafile recycle bin %s.\n",
                  dir_path, dst_path);

out:
    g_free (basename);
    g_free (dst_path);
    return ret;
}

static void
delete_worktree_dir (const char *repo_id,
                     const char *repo_name,
                     struct index_state *istate,
                     const char *worktree,
                     const char *path)
{
    char *full_path = g_build_path ("/", worktree, path, NULL);

#ifdef WIN32
    wchar_t *full_path_w = win32_long_path (full_path);
    delete_worktree_dir_recursive_win32 (istate, path, full_path_w);
    g_free (full_path_w);
#else
    delete_worktree_dir_recursive(istate, path, full_path);
#endif

    /* If for some reason the dir cannot be removed, try to move it to a trash folder
     * under Seafile folder. Otherwise the removed folder will be created agian on the
     * server, which will confuse the users.
     */
    if (g_file_test (full_path, G_FILE_TEST_EXISTS)) {
        if (move_dir_to_recycle_bin (full_path) == 0)
            send_file_sync_error_notification (repo_id, repo_name, path,
                                               SYNC_ERROR_ID_REMOVE_UNCOMMITTED_FOLDER);
    }

    g_free (full_path);
}

static void
update_sync_status (struct cache_entry *ce, void *user_data)
{
    char *repo_id = user_data;

    seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                          repo_id,
                                          ce->name,
                                          ce->ce_mode,
                                          SYNC_STATUS_SYNCED,
                                          TRUE);
}

#ifdef WIN32
static int
convert_rename_to_checkout (const char *repo_id,
                            int repo_version,
                            const char *root_id,
                            DiffEntry *de,
                            GList **entries)
{
    if (de->status == DIFF_STATUS_RENAMED) {
        char file_id[41];
        SeafDirent *dent = NULL;
        DiffEntry *new_de = NULL;

        rawdata_to_hex (de->sha1, file_id, 20);
        dent = seaf_fs_manager_get_dirent_by_path (seaf->fs_mgr,
                                                   repo_id,
                                                   repo_version,
                                                   root_id,
                                                   de->new_name,
                                                   NULL);
        if (!dent) {
            seaf_warning ("Failed to find %s in repo %s\n",
                          de->new_name, repo_id);
            return -1;
        }

        new_de = diff_entry_new (DIFF_TYPE_COMMITS, DIFF_STATUS_ADDED,
                                 de->sha1, de->new_name);
        if (new_de) {
            new_de->mtime = dent->mtime;
            new_de->mode = dent->mode;
            new_de->modifier = g_strdup(dent->modifier);
            new_de->size = dent->size;
            *entries = g_list_prepend (*entries, new_de);
        }

        seaf_dirent_free (dent);
    } else if (de->status == DIFF_STATUS_DIR_RENAMED) {
        GList *expanded = NULL;

        if (seaf_fs_manager_traverse_path (seaf->fs_mgr,
                                           repo_id, repo_version,
                                           root_id,
                                           de->new_name,
                                           expand_dir_added_cb,
                                           &expanded) < 0) {
            g_list_free_full (expanded, (GDestroyNotify)diff_entry_free);
            return -1;
        }

        *entries = g_list_concat (*entries, expanded);
    }

    return 0;
}
#endif  /* WIN32 */

int
seaf_repo_fetch_and_checkout (HttpTxTask *http_task, const char *remote_head_id)
{
    char *repo_id;
    int repo_version;
    gboolean is_clone;
    char *worktree;
    char *passwd;

    SeafRepo *repo = NULL;
    SeafBranch *master = NULL;
    SeafCommit *remote_head = NULL, *master_head = NULL;
    char index_path[SEAF_PATH_MAX];
    struct index_state istate;
    int ret = FETCH_CHECKOUT_SUCCESS;
    GList *results = NULL;
    SeafileCrypt *crypt = NULL;
    GHashTable *conflict_hash = NULL, *no_conflict_hash = NULL;
    GList *ignore_list = NULL;
    LockedFileSet *fset = NULL;

    repo_id = http_task->repo_id;
    repo_version = http_task->repo_version;
    is_clone = http_task->is_clone;
    worktree = http_task->worktree;
    passwd = http_task->passwd;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s",
              seaf->repo_mgr->index_dir, repo_id);
    if (read_index_from (&istate, index_path, repo_version) < 0) {
        seaf_warning ("Failed to load index.\n");
        return FETCH_CHECKOUT_FAILED;
    }

    if (!is_clone) {
        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!repo) {
            seaf_warning ("Failed to get repo %.8s.\n", repo_id);
            goto out;
        }

        master = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                 repo_id, "master");
        if (!master) {
            seaf_warning ("Failed to get master branch for repo %.8s.\n",
                          repo_id);
            ret = FETCH_CHECKOUT_FAILED;
            goto out;
        }

        master_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                      repo_id,
                                                      repo_version,
                                                      master->commit_id);
        if (!master_head) {
            seaf_warning ("Failed to get master head %s of repo %.8s.\n",
                          repo_id, master->commit_id);
            ret = FETCH_CHECKOUT_FAILED;
            goto out;
        }
    }

    if (!is_clone)
        worktree = repo->worktree;

    remote_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                  repo_id,
                                                  repo_version,
                                                  remote_head_id);
    if (!remote_head) {
        seaf_warning ("Failed to get remote head %s of repo %.8s.\n",
                      repo_id, remote_head_id);
        ret = FETCH_CHECKOUT_FAILED;
        goto out;
    }

    if (diff_commit_roots (repo_id, repo_version,
                           master_head ? master_head->root_id : EMPTY_SHA1,
                           remote_head->root_id,
                           &results, TRUE) < 0) {
        seaf_warning ("Failed to diff for repo %.8s.\n", repo_id);
        ret = FETCH_CHECKOUT_FAILED;
        goto out;
    }

    GList *ptr;
    DiffEntry *de;

    /* Expand DIR_ADDED diff entries. */
    if (expand_diff_results (repo_id, repo_version,
                             remote_head->root_id,
                             master_head ? master_head->root_id : EMPTY_SHA1,
                             &results) < 0) {
        ret = FETCH_CHECKOUT_FAILED;
        goto out;
    }

#ifdef WIN32
    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;
        if (de->status == DIFF_STATUS_DIR_RENAMED ||
            de->status == DIFF_STATUS_DIR_DELETED) {
            if (do_check_dir_locked (de->name, worktree)) {
                seaf_message ("File(s) in dir %s are locked by other program, "
                              "skip rename/delete.\n", de->name);
                send_file_sync_error_notification (repo_id, NULL, de->name,
                                                   SYNC_ERROR_ID_FOLDER_LOCKED_BY_APP);
                ret = FETCH_CHECKOUT_LOCKED;
                goto out;
            }
        } else if (de->status == DIFF_STATUS_RENAMED) {
            gboolean locked_on_server = seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                                              repo_id,
                                                                              de->name);

            if (do_check_file_locked (de->name, worktree, locked_on_server)) {
                seaf_message ("File %s is locked by other program, skip rename.\n",
                              de->name);
                send_file_sync_error_notification (repo_id, NULL, de->name,
                                                   SYNC_ERROR_ID_FILE_LOCKED_BY_APP);
                ret = FETCH_CHECKOUT_LOCKED;
                goto out;
            }
        }
    }
#endif

    if (remote_head->encrypted) {
        if (!is_clone) {
            crypt = seafile_crypt_new (repo->enc_version,
                                       repo->enc_key,
                                       repo->enc_iv);
        } else {
            unsigned char enc_key[32], enc_iv[16];
            seafile_decrypt_repo_enc_key (remote_head->enc_version,
                                          passwd,
                                          remote_head->random_key,
                                          remote_head->salt,
                                          enc_key, enc_iv);
            crypt = seafile_crypt_new (remote_head->enc_version,
                                       enc_key, enc_iv);
        }
    }

    conflict_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           g_free, g_free);
    no_conflict_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                              g_free, NULL);

    ignore_list = seaf_repo_load_ignore_files (worktree);

    struct cache_entry *ce;

#if defined WIN32 || defined __APPLE__
    fset = seaf_repo_manager_get_locked_file_set (seaf->repo_mgr, repo_id);
#endif

    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;
        if (de->status == DIFF_STATUS_DELETED) {
            seaf_debug ("Delete file %s.\n", de->name);

            ce = index_name_exists (&istate, de->name, strlen(de->name), 0);
            if (!ce)
                continue;

            if (should_ignore_on_checkout (de->name, NULL)) {
                remove_from_index_with_prefix (&istate, de->name, NULL);
                try_add_empty_parent_dir_entry (worktree, &istate, de->name);
                continue;
            }

            gboolean locked_on_server = seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                                              repo_id,
                                                                              de->name);
            if (locked_on_server)
                seaf_filelock_manager_unlock_wt_file (seaf->filelock_mgr,
                                                      repo_id, de->name);

#if defined WIN32 || defined __APPLE__
            if (!do_check_file_locked (de->name, worktree, locked_on_server)) {
                locked_file_set_remove (fset, de->name, FALSE);
                delete_path (worktree, de->name, de->mode, ce->ce_mtime.sec);
            } else {
                if (!locked_file_set_lookup (fset, de->name))
                    send_file_sync_error_notification (repo_id, http_task->repo_name, de->name,
                                                       SYNC_ERROR_ID_FILE_LOCKED_BY_APP);

                locked_file_set_add_update (fset, de->name, LOCKED_OP_DELETE,
                                            ce->ce_mtime.sec, NULL);
            }
#else
            delete_path (worktree, de->name, de->mode, ce->ce_mtime.sec);
#endif

            /* No need to lock wt file again since it's deleted. */

            remove_from_index_with_prefix (&istate, de->name, NULL);
            try_add_empty_parent_dir_entry (worktree, &istate, de->name);
        } else if (de->status == DIFF_STATUS_DIR_DELETED) {
            seaf_debug ("Delete dir %s.\n", de->name);

            /* Nothing to delete. */
            if (!master_head || strcmp(master_head->root_id, EMPTY_SHA1) == 0)
                continue;

            if (should_ignore_on_checkout (de->name, NULL)) {
                seaf_message ("Path %s is invalid on Windows, skip delete.\n",
                              de->name);
                remove_from_index_with_prefix (&istate, de->name, NULL);

                try_add_empty_parent_dir_entry (worktree, &istate, de->name);
                continue;
            }

            delete_worktree_dir (repo_id, http_task->repo_name, &istate, worktree, de->name);

            /* Remove all index entries under this directory */
            remove_from_index_with_prefix (&istate, de->name, NULL);

            try_add_empty_parent_dir_entry (worktree, &istate, de->name);
        }
    }

    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;
        if (de->status == DIFF_STATUS_RENAMED ||
            de->status == DIFF_STATUS_DIR_RENAMED) {
            seaf_debug ("Rename %s to %s.\n", de->name, de->new_name);

#ifdef WIN32
            IgnoreReason reason;
            if (should_ignore_on_checkout (de->new_name, &reason)) {
                seaf_message ("Path %s is invalid on Windows, skip rename.\n", de->new_name);

                if (reason == IGNORE_REASON_END_SPACE_PERIOD)
                    send_file_sync_error_notification (repo_id, http_task->repo_name,
                                                       de->new_name,
                                                       SYNC_ERROR_ID_PATH_END_SPACE_PERIOD);
                else if (reason == IGNORE_REASON_INVALID_CHARACTER)
                    send_file_sync_error_notification (repo_id, http_task->repo_name,
                                                       de->new_name,
                                                       SYNC_ERROR_ID_PATH_INVALID_CHARACTER);
                continue;
            } else if (should_ignore_on_checkout (de->name, NULL)) {
                /* If the server renames an invalid path to a valid path,
                 * directly checkout the valid path. The checkout will merge
                 * with any existing files.
                 */
                convert_rename_to_checkout (repo_id, repo_version,
                                            remote_head->root_id,
                                            de, &results);
                continue;
            }
#endif

            if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                      repo_id, de->name))
                seaf_filelock_manager_unlock_wt_file (seaf->filelock_mgr,
                                                      repo_id, de->name);

            do_rename_in_worktree (de, worktree, conflict_hash, no_conflict_hash);

            /* update_sync_status updates the sync status for each renamed path.
             * The renamed file/folder becomes "synced" immediately after rename.
             */
            if (!is_clone)
                rename_index_entries (&istate, de->name, de->new_name, NULL,
                                      update_sync_status, repo_id);
            else
                rename_index_entries (&istate, de->name, de->new_name, NULL,
                                      NULL, NULL);

            /* Moving files out of a dir may make it empty. */
            try_add_empty_parent_dir_entry (worktree, &istate, de->name);
        }
    }

    if (istate.cache_changed)
        update_index (&istate, index_path);

    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;
        if (de->status == DIFF_STATUS_ADDED || de->status == DIFF_STATUS_MODIFIED) {
            http_task->total_download += de->size;
        }
    }

    ret = download_files_http (repo_id,
                               repo_version,
                               worktree,
                               &istate,
                               index_path,
                               crypt,
                               http_task,
                               results,
                               conflict_hash,
                               no_conflict_hash,
                               remote_head_id,
                               fset);

out:
    discard_index (&istate);

    seaf_branch_unref (master);
    seaf_commit_unref (master_head);
    seaf_commit_unref (remote_head);

    g_list_free_full (results, (GDestroyNotify)diff_entry_free);

    g_free (crypt);
    if (conflict_hash)
        g_hash_table_destroy (conflict_hash);
    if (no_conflict_hash)
        g_hash_table_destroy (no_conflict_hash);

    if (ignore_list)
        seaf_repo_free_ignore_files (ignore_list);

#if defined WIN32 || defined __APPLE__
    locked_file_set_free (fset);
#endif

    return ret;
}

int
seaf_repo_manager_set_repo_worktree (SeafRepoManager *mgr,
                                     SeafRepo *repo,
                                     const char *worktree)
{
    if (g_access(worktree, F_OK) != 0)
        return -1;

    if (repo->worktree)
        g_free (repo->worktree);
    repo->worktree = g_strdup(worktree);

    if (seaf_repo_manager_set_repo_property (mgr, repo->id,
                                             "worktree",
                                             repo->worktree) < 0)
        return -1;

    repo->worktree_invalid = FALSE;

    return 0;
}

void
seaf_repo_manager_invalidate_repo_worktree (SeafRepoManager *mgr,
                                            SeafRepo *repo)
{
    if (repo->worktree_invalid)
        return;

    repo->worktree_invalid = TRUE;

    if (repo->auto_sync && (repo->sync_interval == 0)) {
        if (seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo->id) < 0) {
            seaf_warning ("failed to unwatch repo %s.\n", repo->id);
        }
    }
}

void
seaf_repo_manager_validate_repo_worktree (SeafRepoManager *mgr,
                                          SeafRepo *repo)
{
    if (!repo->worktree_invalid)
        return;

    repo->worktree_invalid = FALSE;

    if (repo->auto_sync && (repo->sync_interval == 0)) {
        if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree) < 0) {
            seaf_warning ("failed to watch repo %s.\n", repo->id);
        }
    }
}

SeafRepoManager*
seaf_repo_manager_new (SeafileSession *seaf)
{
    SeafRepoManager *mgr = g_new0 (SeafRepoManager, 1);

    mgr->priv = g_new0 (SeafRepoManagerPriv, 1);
    mgr->seaf = seaf;
    mgr->index_dir = g_build_path (PATH_SEPERATOR, seaf->seaf_dir, INDEX_DIR, NULL);

    pthread_mutex_init (&mgr->priv->db_lock, NULL);

    mgr->priv->checkout_tasks_hash = g_hash_table_new_full
        (g_str_hash, g_str_equal, g_free, g_free);

    ignore_patterns = g_new0 (GPatternSpec*, G_N_ELEMENTS(ignore_table));
    int i;
    for (i = 0; ignore_table[i] != NULL; i++) {
        ignore_patterns[i] = g_pattern_spec_new (ignore_table[i]);
    }

    office_temp_ignore_patterns[0] = g_pattern_spec_new("~$*");
    /* for files like ~WRL0001.tmp for docx and *.tmp for xlsx and pptx */
    office_temp_ignore_patterns[1] = g_pattern_spec_new("*.tmp");
    office_temp_ignore_patterns[2] = g_pattern_spec_new(".~lock*#");
    office_temp_ignore_patterns[3] = NULL;

    GError *error = NULL;
    conflict_pattern = g_regex_new (CONFLICT_PATTERN, 0, 0, &error);
    if (error) {
        seaf_warning ("Failed to create regex '%s': %s\n",
                      CONFLICT_PATTERN, error->message);
        g_clear_error (&error);
    }

    office_lock_pattern = g_regex_new (OFFICE_LOCK_PATTERN, 0, 0, &error);
    if (error) {
        seaf_warning ("Failed to create regex '%s': %s\n",
                      OFFICE_LOCK_PATTERN, error->message);
        g_clear_error (&error);
    }

    mgr->priv->repo_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    pthread_rwlock_init (&mgr->priv->lock, NULL);

    mgr->priv->lock_office_job_queue = g_async_queue_new ();

    return mgr;
}

int
seaf_repo_manager_init (SeafRepoManager *mgr)
{
    if (checkdir_with_mkdir (mgr->index_dir) < 0) {
        seaf_warning ("Index dir %s does not exist and is unable to create\n",
                   mgr->index_dir);
        return -1;
    }

    /* Load all the repos into memory on the client side. */
    load_repos (mgr, mgr->seaf->seaf_dir);

    /* Load folder permissions from db. */
    init_folder_perms (mgr);

    return 0;
}

static void
watch_repos (SeafRepoManager *mgr)
{
    GHashTableIter iter;
    SeafRepo *repo;
    gpointer key, value;

    g_hash_table_iter_init (&iter, mgr->priv->repo_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        repo = value;
        if (repo->auto_sync && !repo->worktree_invalid && (repo->sync_interval == 0)) {
            if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree) < 0) {
                seaf_warning ("failed to watch repo %s.\n", repo->id);
                /* If we fail to add watch at the beginning, sync manager
                 * will periodically check repo status and retry.
                 */
            }
        }
    }
}

#define REMOVE_OBJECTS_BATCH 1000

static int
remove_store (const char *top_store_dir, const char *store_id, int *count)
{
    char *obj_dir = NULL;
    GDir *dir1, *dir2;
    const char *dname1, *dname2;
    char *path1, *path2;

    obj_dir = g_build_filename (top_store_dir, store_id, NULL);

    dir1 = g_dir_open (obj_dir, 0, NULL);
    if (!dir1) {
        g_free (obj_dir);
        return 0;
    }

    seaf_message ("Removing store %s\n", obj_dir);

    while ((dname1 = g_dir_read_name(dir1)) != NULL) {
        path1 = g_build_filename (obj_dir, dname1, NULL);

        dir2 = g_dir_open (path1, 0, NULL);
        if (!dir2) {
            seaf_warning ("Failed to open obj dir %s.\n", path1);
            g_dir_close (dir1);
            g_free (path1);
            g_free (obj_dir);
            return -1;
        }

        while ((dname2 = g_dir_read_name(dir2)) != NULL) {
            path2 = g_build_filename (path1, dname2, NULL);
            g_unlink (path2);

            /* To prevent using too much IO, only remove 1000 objects per 5 seconds.
             */
            if (++(*count) > REMOVE_OBJECTS_BATCH) {
                g_usleep (5 * G_USEC_PER_SEC);
                *count = 0;
            }

            g_free (path2);
        }
        g_dir_close (dir2);

        g_rmdir (path1);
        g_free (path1);
    }

    g_dir_close (dir1);
    g_rmdir (obj_dir);
    g_free (obj_dir);

    return 0;
}

static void
cleanup_deleted_stores_by_type (const char *type)
{
    char *top_store_dir;
    const char *repo_id;

    top_store_dir = g_build_filename (seaf->seaf_dir, "deleted_store", type, NULL);

    GError *error = NULL;
    GDir *dir = g_dir_open (top_store_dir, 0, &error);
    if (!dir) {
        seaf_warning ("Failed to open store dir %s: %s.\n",
                      top_store_dir, error->message);
        g_free (top_store_dir);
        return;
    }

    int count = 0;
    while ((repo_id = g_dir_read_name(dir)) != NULL) {
        remove_store (top_store_dir, repo_id, &count);
    }

    g_free (top_store_dir);
    g_dir_close (dir);
}

static void *
cleanup_deleted_stores (void *vdata)
{
    while (1) {
        cleanup_deleted_stores_by_type ("commits");
        cleanup_deleted_stores_by_type ("fs");
        cleanup_deleted_stores_by_type ("blocks");
        g_usleep (60 * G_USEC_PER_SEC);
    }
    return NULL;
}

int
seaf_repo_manager_start (SeafRepoManager *mgr)
{
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    int rc;

    watch_repos (mgr);

    rc = pthread_create (&tid, &attr, cleanup_deleted_stores, NULL);
    if (rc != 0) {
        seaf_warning ("Failed to start cleanup thread: %s\n", strerror(rc));
    }

#if defined WIN32 || defined __APPLE__
    rc = pthread_create (&tid, &attr, lock_office_file_worker,
                         mgr->priv->lock_office_job_queue);
    if (rc != 0) {
        seaf_warning ("Failed to start lock office file thread: %s\n", strerror(rc));
    }
#endif

    return 0;
}

SeafRepo*
seaf_repo_manager_create_new_repo (SeafRepoManager *mgr,
                                   const char *name,
                                   const char *desc)
{
    SeafRepo *repo;
    char *repo_id;
    
    repo_id = gen_uuid ();
    repo = seaf_repo_new (repo_id, name, desc);
    if (!repo) {
        g_free (repo_id);
        return NULL;
    }
    g_free (repo_id);

    /* we directly create dir because it shouldn't exist */
    /* if (seaf_repo_mkdir (repo, base) < 0) { */
    /*     seaf_repo_free (repo); */
    /*     goto out; */
    /* } */

    seaf_repo_manager_add_repo (mgr, repo);
    return repo;
}

int
seaf_repo_manager_add_repo (SeafRepoManager *manager,
                            SeafRepo *repo)
{
    char sql[256];
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), "REPLACE INTO Repo VALUES ('%s');", repo->id);
    sqlite_query_exec (db, sql);

    pthread_mutex_unlock (&manager->priv->db_lock);

    /* There may be a "deletion record" for this repo when it was deleted
     * last time.
     */
    seaf_repo_manager_remove_garbage_repo (manager, repo->id);

    repo->manager = manager;

    if (pthread_rwlock_wrlock (&manager->priv->lock) < 0) {
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
        return -1;
    }

    g_hash_table_insert (manager->priv->repo_hash, g_strdup(repo->id), repo);

    pthread_rwlock_unlock (&manager->priv->lock);

    return 0;
}

int
seaf_repo_manager_mark_repo_deleted (SeafRepoManager *mgr, SeafRepo *repo)
{
    char sql[256];

    pthread_mutex_lock (&mgr->priv->db_lock);

    snprintf (sql, sizeof(sql), "INSERT INTO DeletedRepo VALUES ('%s')",
              repo->id);
    if (sqlite_query_exec (mgr->priv->db, sql) < 0) {
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return -1;
    }

    pthread_mutex_unlock (&mgr->priv->db_lock);

    repo->delete_pending = TRUE;

    return 0;
}

static gboolean
get_garbage_repo_id (sqlite3_stmt *stmt, void *vid_list)
{
    GList **ret = vid_list;
    char *repo_id;

    repo_id = g_strdup((const char *)sqlite3_column_text (stmt, 0));
    *ret = g_list_prepend (*ret, repo_id);

    return TRUE;
}

GList *
seaf_repo_manager_list_garbage_repos (SeafRepoManager *mgr)
{
    GList *repo_ids = NULL;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sqlite_foreach_selected_row (mgr->priv->db,
                                 "SELECT repo_id FROM GarbageRepos",
                                 get_garbage_repo_id, &repo_ids);
    pthread_mutex_unlock (&mgr->priv->db_lock);

    return repo_ids;
}

void
seaf_repo_manager_remove_garbage_repo (SeafRepoManager *mgr, const char *repo_id)
{
    char sql[256];

    pthread_mutex_lock (&mgr->priv->db_lock);

    snprintf (sql, sizeof(sql), "DELETE FROM GarbageRepos WHERE repo_id='%s'",
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);
}

void
seaf_repo_manager_remove_repo_ondisk (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      gboolean add_deleted_record)
{
    char sql[256];

    /* We don't need to care about I/O errors here, since we can
     * GC any unreferenced repo data later.
     */

    if (add_deleted_record) {
        snprintf (sql, sizeof(sql), "REPLACE INTO GarbageRepos VALUES ('%s')",
                  repo_id);
        if (sqlite_query_exec (mgr->priv->db, sql) < 0)
            goto out;
    }

    /* Once the item in Repo table is deleted, the repo is gone.
     * This is the "commit point".
     */
    pthread_mutex_lock (&mgr->priv->db_lock);

    snprintf (sql, sizeof(sql), "DELETE FROM Repo WHERE repo_id = '%s'", repo_id);
    if (sqlite_query_exec (mgr->priv->db, sql) < 0)
        goto out;

    snprintf (sql, sizeof(sql), 
              "DELETE FROM DeletedRepo WHERE repo_id = '%s'", repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    /* remove index */
    char path[SEAF_PATH_MAX];
    snprintf (path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo_id);
    seaf_util_unlink (path);

    /* remove branch */
    GList *p;
    GList *branch_list = 
        seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo_id);
    for (p = branch_list; p; p = p->next) {
        SeafBranch *b = (SeafBranch *)p->data;
        seaf_repo_manager_branch_repo_unmap (mgr, b);
        seaf_branch_manager_del_branch (seaf->branch_mgr, repo_id, b->name);
    }
    seaf_branch_list_free (branch_list);

    /* delete repo property firstly */
    seaf_repo_manager_del_repo_property (mgr, repo_id);

    pthread_mutex_lock (&mgr->priv->db_lock);

    snprintf (sql, sizeof(sql), "DELETE FROM RepoPasswd WHERE repo_id = '%s'", 
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);
    snprintf (sql, sizeof(sql), "DELETE FROM RepoKeys WHERE repo_id = '%s'", 
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    snprintf (sql, sizeof(sql), "DELETE FROM MergeInfo WHERE repo_id = '%s'", 
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    snprintf (sql, sizeof(sql), "DELETE FROM LockedFiles WHERE repo_id = '%s'",
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    snprintf (sql, sizeof(sql), "DELETE FROM FolderUserPerms WHERE repo_id = '%s'", 
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    snprintf (sql, sizeof(sql), "DELETE FROM FolderGroupPerms WHERE repo_id = '%s'", 
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    snprintf (sql, sizeof(sql), "DELETE FROM FolderPermTimestamp WHERE repo_id = '%s'", 
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    seaf_filelock_manager_remove (seaf->filelock_mgr, repo_id);

out:
    pthread_mutex_unlock (&mgr->priv->db_lock);
}

static char *
gen_deleted_store_path (const char *type, const char *repo_id)
{
    int n = 1;
    char *path = NULL;
    char *name = NULL;

    path = g_build_filename (seaf->deleted_store, type, repo_id, NULL);
    while (g_access(path, F_OK) == 0 && n < 10) {
        g_free (path);
        name = g_strdup_printf ("%s(%d)", repo_id, n);
        path = g_build_filename (seaf->deleted_store, type, name, NULL);
        g_free (name);
        ++n;
    }

    if (n == 10) {
        g_free (path);
        return NULL;
    }

    return path;
}

void
seaf_repo_manager_move_repo_store (SeafRepoManager *mgr,
                                   const char *type,
                                   const char *repo_id)
{
    char *src = NULL;
    char *dst = NULL;

    src = g_build_filename (seaf->seaf_dir, "storage", type, repo_id, NULL);
    dst = gen_deleted_store_path (type, repo_id);
    if (dst) {
        g_rename (src, dst);
    }
    g_free (src);
    g_free (dst);
}

/* Move commits, fs stores into "deleted_store" directory. */
static void
move_repo_stores (SeafRepoManager *mgr, SeafRepo *repo)
{
    seaf_repo_manager_move_repo_store (mgr, "commits", repo->id);
    seaf_repo_manager_move_repo_store (mgr, "fs", repo->id);
}

int
seaf_repo_manager_del_repo (SeafRepoManager *mgr,
                            SeafRepo *repo)
{
    seaf_repo_manager_remove_repo_ondisk (mgr, repo->id,
                                          (repo->version > 0) ? TRUE : FALSE);

    seaf_sync_manager_remove_active_path_info (seaf->sync_mgr, repo->id);

    remove_folder_perms (mgr, repo->id);

    move_repo_stores (mgr, repo);

    if (pthread_rwlock_wrlock (&mgr->priv->lock) < 0) {
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
        return -1;
    }

    g_hash_table_remove (mgr->priv->repo_hash, repo->id);

    pthread_rwlock_unlock (&mgr->priv->lock);

    seaf_repo_free (repo);

    return 0;
}

/*
  Return the internal Repo in hashtable. The caller should not free the returned Repo.
 */
SeafRepo*
seaf_repo_manager_get_repo (SeafRepoManager *manager, const gchar *id)
{
    SeafRepo *res;

    if (pthread_rwlock_rdlock (&manager->priv->lock) < 0) {
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
        return NULL;
    }

    res = g_hash_table_lookup (manager->priv->repo_hash, id);

    pthread_rwlock_unlock (&manager->priv->lock);

    if (res && !res->delete_pending)
        return res;

    return NULL;
}

gboolean
seaf_repo_manager_repo_exists (SeafRepoManager *manager, const gchar *id)
{
    SeafRepo *res;

    if (pthread_rwlock_rdlock (&manager->priv->lock) < 0) {
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
        return FALSE;
    }

    res = g_hash_table_lookup (manager->priv->repo_hash, id);

    pthread_rwlock_unlock (&manager->priv->lock);

    if (res && !res->delete_pending)
        return TRUE;
    
    return FALSE;
}

static int
save_branch_repo_map (SeafRepoManager *manager, SeafBranch *branch)
{
    char *sql;
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    sql = sqlite3_mprintf ("REPLACE INTO RepoBranch VALUES (%Q, %Q)",
                           branch->repo_id, branch->name);
    sqlite_query_exec (db, sql);
    sqlite3_free (sql);

    pthread_mutex_unlock (&manager->priv->db_lock);

    return 0;
}

int
seaf_repo_manager_branch_repo_unmap (SeafRepoManager *manager, SeafBranch *branch)
{
    char *sql;
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    sql = sqlite3_mprintf ("DELETE FROM RepoBranch WHERE branch_name = %Q"
                           " AND repo_id = %Q",
                           branch->name, branch->repo_id);
    if (sqlite_query_exec (db, sql) < 0) {
        seaf_warning ("Unmap branch repo failed\n");
        pthread_mutex_unlock (&manager->priv->db_lock);
        sqlite3_free (sql);
        return -1;
    }

    sqlite3_free (sql);
    pthread_mutex_unlock (&manager->priv->db_lock);

    return 0;
}

static void
load_repo_commit (SeafRepoManager *manager,
                  SeafRepo *repo,
                  SeafBranch *branch)
{
    SeafCommit *commit;

    commit = seaf_commit_manager_get_commit_compatible (manager->seaf->commit_mgr,
                                                        repo->id,
                                                        branch->commit_id);
    if (!commit) {
        seaf_warning ("Commit %s is missing\n", branch->commit_id);
        repo->is_corrupted = TRUE;
        return;
    }

    set_head_common (repo, branch);
    seaf_repo_from_commit (repo, commit);

    seaf_commit_unref (commit);
}

static gboolean
load_keys_cb (sqlite3_stmt *stmt, void *vrepo)
{
    SeafRepo *repo = vrepo;
    const char *key, *iv;

    key = (const char *)sqlite3_column_text(stmt, 0);
    iv = (const char *)sqlite3_column_text(stmt, 1);

    if (repo->enc_version == 1) {
        hex_to_rawdata (key, repo->enc_key, 16);
        hex_to_rawdata (iv, repo->enc_iv, 16);
    } else if (repo->enc_version >= 2) {
        hex_to_rawdata (key, repo->enc_key, 32);
        hex_to_rawdata (iv, repo->enc_iv, 16);
    }

    return FALSE;
}

static int
load_repo_passwd (SeafRepoManager *manager, SeafRepo *repo)
{
    sqlite3 *db = manager->priv->db;
    char sql[256];
    int n;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), 
              "SELECT key, iv FROM RepoKeys WHERE repo_id='%s'",
              repo->id);
    n = sqlite_foreach_selected_row (db, sql, load_keys_cb, repo);
    if (n < 0) {
        pthread_mutex_unlock (&manager->priv->db_lock);
        return -1;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    return 0;
    
}

static gboolean
load_property_cb (sqlite3_stmt *stmt, void *pvalue)
{
    char **value = pvalue;

    char *v = (char *) sqlite3_column_text (stmt, 0);
    *value = g_strdup (v);

    /* Only one result. */
    return FALSE;
}

static char *
load_repo_property (SeafRepoManager *manager,
                    const char *repo_id,
                    const char *key)
{
    sqlite3 *db = manager->priv->db;
    char sql[256];
    char *value = NULL;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf(sql, 256, "SELECT value FROM RepoProperty WHERE "
             "repo_id='%s' and key='%s'", repo_id, key);
    if (sqlite_foreach_selected_row (db, sql, load_property_cb, &value) < 0) {
        seaf_warning ("Error read property %s for repo %s.\n", key, repo_id);
        pthread_mutex_unlock (&manager->priv->db_lock);
        return NULL;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    return value;
}

static gboolean
load_branch_cb (sqlite3_stmt *stmt, void *vrepo)
{
    SeafRepo *repo = vrepo;
    SeafRepoManager *manager = repo->manager;

    char *branch_name = (char *) sqlite3_column_text (stmt, 0);
    SeafBranch *branch =
        seaf_branch_manager_get_branch (manager->seaf->branch_mgr,
                                        repo->id, branch_name);
    if (branch == NULL) {
        seaf_warning ("Broken branch name for repo %s\n", repo->id); 
        repo->is_corrupted = TRUE;
        return FALSE;
    }
    load_repo_commit (manager, repo, branch);
    seaf_branch_unref (branch);

    /* Only one result. */
    return FALSE;
}

static gboolean
is_wt_repo_name_same (const char *worktree, const char *repo_name)
{
    char *basename = g_path_get_basename (worktree);
    gboolean ret = FALSE;
    ret = (g_strcmp0 (basename, repo_name) == 0);
    g_free (basename);
    return ret;
}

static SeafRepo *
load_repo (SeafRepoManager *manager, const char *repo_id)
{
    char sql[256];

    SeafRepo *repo = seaf_repo_new(repo_id, NULL, NULL);
    if (!repo) {
        seaf_warning ("[repo mgr] failed to alloc repo.\n");
        return NULL;
    }

    repo->manager = manager;

    snprintf(sql, 256, "SELECT branch_name FROM RepoBranch WHERE repo_id='%s'",
             repo->id);
    if (sqlite_foreach_selected_row (manager->priv->db, sql, 
                                     load_branch_cb, repo) < 0) {
        seaf_warning ("Error read branch for repo %s.\n", repo->id);
        seaf_repo_free (repo);
        return NULL;
    }

    /* If repo head is set but failed to load branch or commit. */
    if (repo->is_corrupted) {
        seaf_repo_free (repo);
        /* remove_repo_ondisk (manager, repo_id); */
        return NULL;
    }

    /* Repo head may be not set if it's just cloned but not checked out yet. */
    if (repo->head == NULL) {
        /* the repo do not have a head branch, try to load 'master' branch */
        SeafBranch *branch =
            seaf_branch_manager_get_branch (manager->seaf->branch_mgr,
                                            repo->id, "master");
        if (branch != NULL) {
             SeafCommit *commit;

             commit =
                 seaf_commit_manager_get_commit_compatible (manager->seaf->commit_mgr,
                                                            repo->id,
                                                            branch->commit_id);
             if (commit) {
                 seaf_repo_from_commit (repo, commit);
                 seaf_commit_unref (commit);
             } else {
                 seaf_warning ("[repo-mgr] Can not find commit %s\n",
                            branch->commit_id);
                 repo->is_corrupted = TRUE;
             }

             seaf_branch_unref (branch);
        } else {
            seaf_warning ("[repo-mgr] Failed to get branch master");
            repo->is_corrupted = TRUE;
        }
    }

    if (repo->is_corrupted) {
        seaf_repo_free (repo);
        /* remove_repo_ondisk (manager, repo_id); */
        return NULL;
    }

    load_repo_passwd (manager, repo);

    char *value;

    value = load_repo_property (manager, repo->id, REPO_AUTO_SYNC);
    if (g_strcmp0(value, "false") == 0) {
        repo->auto_sync = 0;
    }
    g_free (value);

    repo->worktree = load_repo_property (manager, repo->id, "worktree");
    if (repo->worktree)
        repo->worktree_invalid = FALSE;

    repo->email = load_repo_property (manager, repo->id, REPO_PROP_EMAIL);
    repo->token = load_repo_property (manager, repo->id, REPO_PROP_TOKEN);

    /* May be NULL if this property is not set in db. */
    repo->server_url = load_repo_property (manager, repo->id, REPO_PROP_SERVER_URL);

    if (repo->head != NULL && seaf_repo_check_worktree (repo) < 0) {
        if (seafile_session_config_get_allow_invalid_worktree(seaf)) {
            seaf_warning ("Worktree for repo \"%s\" is invalid, but still keep it.\n",
                          repo->name);
            repo->worktree_invalid = TRUE;
        } else {
            seaf_message ("Worktree for repo \"%s\" is invalid, delete it.\n",
                          repo->name);
            seaf_repo_manager_del_repo (manager, repo);
            return NULL;
        }
    }

    /* load readonly property */
    value = load_repo_property (manager, repo->id, REPO_PROP_IS_READONLY);
    if (g_strcmp0(value, "true") == 0)
        repo->is_readonly = TRUE;
    else
        repo->is_readonly = FALSE;
    g_free (value);

    /* load sync period property */
    value = load_repo_property (manager, repo->id, REPO_PROP_SYNC_INTERVAL);
    if (value) {
        int interval = atoi(value);
        if (interval > 0)
            repo->sync_interval = interval;
    }
    g_free (value);

    if (repo->worktree) {
        gboolean wt_repo_name_same = is_wt_repo_name_same (repo->worktree, repo->name);
        value = load_repo_property (manager, repo->id, REPO_SYNC_WORKTREE_NAME);
        if (g_strcmp0 (value, "true") == 0) {
            /* If need to sync worktree name with library name, update worktree folder name. */
            if (!wt_repo_name_same)
                update_repo_worktree_name (repo, repo->name, FALSE);
        } else {
            /* If an existing repo's worktree folder name is the same as repo name, but
             * sync_worktree_name property is not set, set it.
             */
            if (wt_repo_name_same)
                save_repo_property (manager, repo->id, REPO_SYNC_WORKTREE_NAME, "true");
        }
        g_free (value);
    }

    g_hash_table_insert (manager->priv->repo_hash, g_strdup(repo->id), repo);

    return repo;
}

static sqlite3*
open_db (SeafRepoManager *manager, const char *seaf_dir)
{
    sqlite3 *db;
    char *db_path;

    db_path = g_build_filename (seaf_dir, "repo.db", NULL);
    if (sqlite_open_db (db_path, &db) < 0)
        return NULL;
    g_free (db_path);
    manager->priv->db = db;

    char *sql = "CREATE TABLE IF NOT EXISTS Repo (repo_id TEXT PRIMARY KEY);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS DeletedRepo (repo_id TEXT PRIMARY KEY);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS RepoBranch ("
        "repo_id TEXT PRIMARY KEY, branch_name TEXT);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS RepoLanToken ("
        "repo_id TEXT PRIMARY KEY, token TEXT);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS RepoTmpToken ("
        "repo_id TEXT, peer_id TEXT, token TEXT, timestamp INTEGER, "
        "PRIMARY KEY (repo_id, peer_id));";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS RepoPasswd "
        "(repo_id TEXT PRIMARY KEY, passwd TEXT NOT NULL);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS RepoKeys "
        "(repo_id TEXT PRIMARY KEY, key TEXT NOT NULL, iv TEXT NOT NULL);";
    sqlite_query_exec (db, sql);
    
    sql = "CREATE TABLE IF NOT EXISTS RepoProperty ("
        "repo_id TEXT, key TEXT, value TEXT);";
    sqlite_query_exec (db, sql);

    sql = "CREATE INDEX IF NOT EXISTS RepoIndex ON RepoProperty (repo_id);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS MergeInfo ("
        "repo_id TEXT PRIMARY KEY, in_merge INTEGER, branch TEXT);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS CommonAncestor ("
        "repo_id TEXT PRIMARY KEY, ca_id TEXT, head_id TEXT);";
    sqlite_query_exec (db, sql);

    /* Version 1 repos will be added to this table after deletion.
     * GC will scan this table and remove the objects and blocks for the repos.
     */
    sql = "CREATE TABLE IF NOT EXISTS GarbageRepos (repo_id TEXT PRIMARY KEY);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS LockedFiles (repo_id TEXT, path TEXT, "
        "operation TEXT, old_mtime INTEGER, file_id TEXT, new_path TEXT, "
        "PRIMARY KEY (repo_id, path));";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS FolderUserPerms ("
        "repo_id TEXT, path TEXT, permission TEXT);";
    sqlite_query_exec (db, sql);

    sql = "CREATE INDEX IF NOT EXISTS folder_user_perms_repo_id_idx "
        "ON FolderUserPerms (repo_id);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS FolderGroupPerms ("
        "repo_id TEXT, path TEXT, permission TEXT);";
    sqlite_query_exec (db, sql);

    sql = "CREATE INDEX IF NOT EXISTS folder_group_perms_repo_id_idx "
        "ON FolderGroupPerms (repo_id);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS FolderPermTimestamp ("
        "repo_id TEXT, timestamp INTEGER, PRIMARY KEY (repo_id));";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS ServerProperty ("
        "server_url TEXT, key TEXT, value TEXT, PRIMARY KEY (server_url, key));";
    sqlite_query_exec (db, sql);

    sql = "CREATE INDEX IF NOT EXISTS ServerIndex ON ServerProperty (server_url);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS FileSyncError ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, repo_id TEXT, repo_name TEXT, "
        "path TEXT, err_id INTEGER, timestamp INTEGER);";
    sqlite_query_exec (db, sql);

    sql = "CREATE INDEX IF NOT EXISTS FileSyncErrorIndex ON FileSyncError (repo_id, path)";
    sqlite_query_exec (db, sql);

    return db;
}

static gboolean
load_repo_cb (sqlite3_stmt *stmt, void *vmanager)
{
    SeafRepoManager *manager = vmanager;
    const char *repo_id;

    repo_id = (const char *) sqlite3_column_text (stmt, 0);

    load_repo (manager, repo_id);

    return TRUE;
}

static gboolean
remove_deleted_repo (sqlite3_stmt *stmt, void *vmanager)
{
    SeafRepoManager *manager = vmanager;
    const char *repo_id;

    repo_id = (const char *) sqlite3_column_text (stmt, 0);

    seaf_repo_manager_remove_repo_ondisk (manager, repo_id, TRUE);

    return TRUE;
}

static void
load_repos (SeafRepoManager *manager, const char *seaf_dir)
{
    sqlite3 *db = open_db(manager, seaf_dir);
    if (!db) return;

    char *sql;

    sql = "SELECT repo_id FROM DeletedRepo";
    if (sqlite_foreach_selected_row (db, sql, remove_deleted_repo, manager) < 0) {
        seaf_warning ("Error removing deleted repos.\n");
        return;
    }

    sql = "SELECT repo_id FROM Repo;";
    if (sqlite_foreach_selected_row (db, sql, load_repo_cb, manager) < 0) {
        seaf_warning ("Error read repo db.\n");
        return;
    }
}

static void
save_repo_property (SeafRepoManager *manager,
                    const char *repo_id,
                    const char *key, const char *value)
{
    char *sql;
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    sql = sqlite3_mprintf ("SELECT repo_id FROM RepoProperty WHERE repo_id=%Q AND key=%Q",
                           repo_id, key);
    if (sqlite_check_for_existence(db, sql)) {
        sqlite3_free (sql);
        sql = sqlite3_mprintf ("UPDATE RepoProperty SET value=%Q"
                               "WHERE repo_id=%Q and key=%Q",
                               value, repo_id, key);
        sqlite_query_exec (db, sql);
        sqlite3_free (sql);
    } else {
        sqlite3_free (sql);
        sql = sqlite3_mprintf ("INSERT INTO RepoProperty VALUES (%Q, %Q, %Q)",
                               repo_id, key, value);
        sqlite_query_exec (db, sql);
        sqlite3_free (sql);
    }

    pthread_mutex_unlock (&manager->priv->db_lock);
}

int
seaf_repo_manager_set_repo_property (SeafRepoManager *manager, 
                                     const char *repo_id,
                                     const char *key,
                                     const char *value)
{
    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (manager, repo_id);
    if (!repo)
        return -1;

    if (strcmp(key, REPO_AUTO_SYNC) == 0) {
        if (!seaf->started) {
            seaf_message ("System not started, skip setting auto sync value.\n");
            return 0;
        }

        if (g_strcmp0(value, "true") == 0) {
            repo->auto_sync = 1;
            if (repo->sync_interval == 0)
                seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id,
                                            repo->worktree);
            repo->last_sync_time = 0;
        } else {
            repo->auto_sync = 0;
            if (repo->sync_interval == 0)
                seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo->id);
            /* Cancel current sync task if any. */
            seaf_sync_manager_cancel_sync_task (seaf->sync_mgr, repo->id);
            seaf_sync_manager_remove_active_path_info (seaf->sync_mgr, repo->id);
        }
    }

    if (strcmp(key, REPO_PROP_SYNC_INTERVAL) == 0) {
        if (!seaf->started) {
            seaf_message ("System not started, skip setting auto sync value.\n");
            return 0;
        }

        int interval = atoi(value);

        if (interval > 0) {
            repo->sync_interval = interval;
            if (repo->auto_sync)
                seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo->id);
        } else {
            repo->sync_interval = 0;
            if (repo->auto_sync)
                seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id,
                                            repo->worktree);
        }
    }

    if (strcmp (key, REPO_PROP_SERVER_URL) == 0) {
        char *url = canonical_server_url (value);

        if (!repo->server_url) {
            /* Called from clone-mgr. */
            repo->server_url = url;
        } else {
            g_free (repo->server_url);
            repo->server_url = url;

            g_free (repo->effective_host);
            repo->effective_host = NULL;
        }

        save_repo_property (manager, repo_id, key, url);
        return 0;
    }

    if (strcmp (key, REPO_PROP_IS_READONLY) == 0) {
       if (g_strcmp0 (value, "true") == 0)
           repo->is_readonly = TRUE;
       else
           repo->is_readonly = FALSE;
    }

    save_repo_property (manager, repo_id, key, value);
    return 0;
}

char *
seaf_repo_manager_get_repo_property (SeafRepoManager *manager, 
                                     const char *repo_id,
                                     const char *key)
{
    return load_repo_property (manager, repo_id, key);
}

static void
seaf_repo_manager_del_repo_property (SeafRepoManager *manager, 
                                     const char *repo_id)
{
    char *sql;
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    sql = sqlite3_mprintf ("DELETE FROM RepoProperty WHERE repo_id = %Q", repo_id);
    sqlite_query_exec (db, sql);
    sqlite3_free (sql);

    pthread_mutex_unlock (&manager->priv->db_lock);
}

static void
seaf_repo_manager_del_repo_property_by_key (SeafRepoManager *manager,
                                            const char *repo_id,
                                            const char *key)
{
    char *sql;
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    sql = sqlite3_mprintf ("DELETE FROM RepoProperty "
                           "WHERE repo_id = %Q "
                           "  AND key = %Q", repo_id, key);
    sqlite_query_exec (db, sql);
    sqlite3_free (sql);

    pthread_mutex_unlock (&manager->priv->db_lock);
}

static int
save_repo_enc_info (SeafRepoManager *manager,
                    SeafRepo *repo)
{
    sqlite3 *db = manager->priv->db;
    char sql[512];
    char key[65], iv[33];

    if (repo->enc_version == 1) {
        rawdata_to_hex (repo->enc_key, key, 16);
        rawdata_to_hex (repo->enc_iv, iv, 16);
    } else if (repo->enc_version >= 2) {
        rawdata_to_hex (repo->enc_key, key, 32);
        rawdata_to_hex (repo->enc_iv, iv, 16);
    }

    snprintf (sql, sizeof(sql), "REPLACE INTO RepoKeys VALUES ('%s', '%s', '%s')",
              repo->id, key, iv);
    if (sqlite_query_exec (db, sql) < 0)
        return -1;

    return 0;
}

int 
seaf_repo_manager_set_repo_passwd (SeafRepoManager *manager,
                                   SeafRepo *repo,
                                   const char *passwd)
{
    int ret;

    if (seafile_decrypt_repo_enc_key (repo->enc_version, passwd, repo->random_key,
                                      repo->salt,
                                      repo->enc_key, repo->enc_iv) < 0)
        return -1;

    pthread_mutex_lock (&manager->priv->db_lock);

    ret = save_repo_enc_info (manager, repo);

    pthread_mutex_unlock (&manager->priv->db_lock);

    return ret;
}

GList*
seaf_repo_manager_get_repo_list (SeafRepoManager *manager, int start, int limit)
{
    GList *repo_list = NULL;
    GHashTableIter iter;
    SeafRepo *repo;
    gpointer key, value;

    if (pthread_rwlock_rdlock (&manager->priv->lock) < 0) {
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
        return NULL;
    }
    g_hash_table_iter_init (&iter, manager->priv->repo_hash);

    while (g_hash_table_iter_next (&iter, &key, &value)) {
        repo = value;
        if (!repo->delete_pending)
            repo_list = g_list_prepend (repo_list, repo);
    }

    pthread_rwlock_unlock (&manager->priv->lock);

    return repo_list;
}

GList *
seaf_repo_manager_get_repo_id_list_by_server (SeafRepoManager *manager, const char *server_url)
{
    GList *repo_id_list = NULL;
    GHashTableIter iter;
    SeafRepo *repo;
    gpointer key, value;

    if (pthread_rwlock_rdlock (&manager->priv->lock) < 0) {
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
        return NULL;
    }
    g_hash_table_iter_init (&iter, manager->priv->repo_hash);

    while (g_hash_table_iter_next (&iter, &key, &value)) {
        repo = value;
        if (!repo->delete_pending && g_strcmp0 (repo->server_url, server_url) == 0)
            repo_id_list = g_list_prepend (repo_id_list, g_strdup(repo->id));
    }

    pthread_rwlock_unlock (&manager->priv->lock);

    return repo_id_list;
}

int
seaf_repo_manager_set_repo_email (SeafRepoManager *mgr,
                                  SeafRepo *repo,
                                  const char *email)
{
    g_free (repo->email);
    repo->email = g_strdup(email);

    save_repo_property (mgr, repo->id, REPO_PROP_EMAIL, email);
    return 0;
}

int
seaf_repo_manager_set_repo_token (SeafRepoManager *manager, 
                                  SeafRepo *repo,
                                  const char *token)
{
    g_free (repo->token);
    repo->token = g_strdup(token);

    save_repo_property (manager, repo->id, REPO_PROP_TOKEN, token);
    return 0;
}


int
seaf_repo_manager_remove_repo_token (SeafRepoManager *manager,
                                     SeafRepo *repo)
{
    g_free (repo->token);
    repo->token = NULL;
    seaf_repo_manager_del_repo_property_by_key(manager, repo->id, REPO_PROP_TOKEN);
    return 0;
}

int
seaf_repo_manager_set_repo_relay_info (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *relay_addr,
                                       const char *relay_port)
{
    save_repo_property (mgr, repo_id, REPO_PROP_RELAY_ADDR, relay_addr);
    save_repo_property (mgr, repo_id, REPO_PROP_RELAY_PORT, relay_port);
    return 0;
}

void
seaf_repo_manager_get_repo_relay_info (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       char **relay_addr,
                                       char **relay_port)
{
    char *addr, *port;

    addr = load_repo_property (mgr, repo_id, REPO_PROP_RELAY_ADDR);
    port = load_repo_property (mgr, repo_id, REPO_PROP_RELAY_PORT);

    if (relay_addr && addr)
        *relay_addr = addr;
    if (relay_port && port)
        *relay_port = port;
}

static void
update_server_properties (SeafRepoManager *mgr,
                          const char *repo_id,
                          const char *new_server_url)
{
    char *old_server_url = NULL;
    char *sql = NULL;

    old_server_url = seaf_repo_manager_get_repo_property (mgr, repo_id,
                                                          REPO_PROP_SERVER_URL);
    if (!old_server_url)
        return;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = sqlite3_mprintf ("UPDATE ServerProperty SET server_url=%Q WHERE "
                           "server_url=%Q;", new_server_url, old_server_url);
    sqlite_query_exec (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    sqlite3_free (sql);
    g_free (old_server_url);
}

int
seaf_repo_manager_update_repos_server_host (SeafRepoManager *mgr,
                                            const char *old_server_url,
                                            const char *new_server_url)
{
    GList *ptr, *repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, 0, -1);
    SeafRepo *r;
    char *canon_old_server_url = canonical_server_url(old_server_url);    
    char *canon_new_server_url = canonical_server_url(new_server_url);

    for (ptr = repos; ptr; ptr = ptr->next) {
        r = ptr->data;
        
        char *server_url = seaf_repo_manager_get_repo_property (seaf->repo_mgr,
                                                                r->id,
                                                                REPO_PROP_SERVER_URL);
        
        if (g_strcmp0(server_url, canon_old_server_url) == 0) {
            /* Update server property before server_url is changed. */
            update_server_properties (mgr, r->id, canon_new_server_url);

            seaf_repo_manager_set_repo_property (
                seaf->repo_mgr, r->id, REPO_PROP_SERVER_URL, canon_new_server_url);
        }
        g_free (server_url);

    }

    g_list_free (repos);
    g_free (canon_old_server_url);
    g_free (canon_new_server_url);

    return 0;
}

char *
seaf_repo_manager_get_server_property (SeafRepoManager *mgr,
                                       const char *server_url,
                                       const char *key)
{
    char *sql = sqlite3_mprintf ("SELECT value FROM ServerProperty WHERE "
                                 "server_url=%Q AND key=%Q;",
                                 server_url, key);
    char *value;

    pthread_mutex_lock (&mgr->priv->db_lock);

    value = sqlite_get_string (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    sqlite3_free (sql);
    return value;
}

int
seaf_repo_manager_set_server_property (SeafRepoManager *mgr,
                                       const char *server_url,
                                       const char *key,
                                       const char *value)
{
    char *sql;
    int ret;
    char *canon_server_url = canonical_server_url(server_url);

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = sqlite3_mprintf ("REPLACE INTO ServerProperty VALUES (%Q, %Q, %Q);",
                           canon_server_url, key, value);
    ret = sqlite_query_exec (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    sqlite3_free (sql);
    g_free (canon_server_url);
    return ret;
}

gboolean
seaf_repo_manager_server_is_pro (SeafRepoManager *mgr,
                                 const char *server_url)
{
    gboolean ret = FALSE;

    char *is_pro = seaf_repo_manager_get_server_property (seaf->repo_mgr,
                                                          server_url,
                                                          SERVER_PROP_IS_PRO);
    if (is_pro != NULL && strcasecmp (is_pro, "true") == 0)
        ret = TRUE;

    g_free (is_pro);
    return ret;
}

/*
 * Read ignored files from ignore.txt
 */
GList *seaf_repo_load_ignore_files (const char *worktree)
{
    GList *list = NULL;
    SeafStat st;
    FILE *fp;
    char *full_path, *pattern;
    char path[SEAF_PATH_MAX];

    full_path = g_build_path (PATH_SEPERATOR, worktree,
                              IGNORE_FILE, NULL);
    if (seaf_stat (full_path, &st) < 0)
        goto error;
    if (!S_ISREG(st.st_mode))
        goto error;
    fp = g_fopen(full_path, "r");
    if (fp == NULL)
        goto error;

    while (fgets(path, SEAF_PATH_MAX, fp) != NULL) {
        /* remove leading and trailing whitespace, including \n \r. */
        g_strstrip (path);

        /* ignore comment and blank line */
        if (path[0] == '#' || path[0] == '\0')
            continue;

        /* Change 'foo/' to 'foo/ *'. */
        if (path[strlen(path)-1] == '/')
            pattern = g_strdup_printf("%s/%s*", worktree, path);
        else
            pattern = g_strdup_printf("%s/%s", worktree, path);

        list = g_list_prepend(list, pattern);
    }

    fclose(fp);
    g_free (full_path);
    return list;

error:
    g_free (full_path);
    return NULL;
}

gboolean
seaf_repo_check_ignore_file (GList *ignore_list, const char *fullpath)
{
    char *str;
    SeafStat st;
    GPatternSpec *ignore_spec;
    GList *p;

    str = g_strdup(fullpath);

    int rc = seaf_stat(str, &st);
    if (rc == 0 && S_ISDIR(st.st_mode)) {
        g_free (str);
        str = g_strconcat (fullpath, "/", NULL);
    }

    for (p = ignore_list; p != NULL; p = p->next) {
        char *pattern = (char *)p->data;

        ignore_spec = g_pattern_spec_new(pattern);
        if (g_pattern_match_string(ignore_spec, str)) {
            g_free (str);
            g_pattern_spec_free(ignore_spec);
            return TRUE;
        }
        g_pattern_spec_free(ignore_spec);
    }

    g_free (str);
    return FALSE;
}

/*
 * Free ignored file list
 */
void seaf_repo_free_ignore_files (GList *ignore_list)
{
    GList *p;

    if (ignore_list == NULL)
        return;

    for (p = ignore_list; p != NULL; p = p->next)
        free(p->data);

    g_list_free (ignore_list);
}
