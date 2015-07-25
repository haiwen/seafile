/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <glib/gstdio.h>

#ifdef WIN32
#include <windows.h>
#include <shlobj.h>
#endif

#include <ccnet.h>
#include "utils.h"
#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
#include "log.h"

#include "status.h"
#include "vc-utils.h"
#include "merge.h"

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
#include "unpack-trees.h"
#include "diff-simple.h"
#include "change-set.h"

#include "db.h"

#define INDEX_DIR "index"
#define IGNORE_FILE "seafile-ignore.txt"

#ifdef HAVE_KEYSTORAGE_GK
#include "repokey/seafile-gnome-keyring.h"
#endif // HAVE_KEYSTORAGE_GK

struct _SeafRepoManagerPriv {
    GHashTable *repo_hash;
    sqlite3    *db;
    pthread_mutex_t db_lock;
    GHashTable *checkout_tasks_hash;
    pthread_rwlock_t lock;

    GHashTable *user_perms;     /* repo_id -> folder user perms */
    GHashTable *group_perms;    /* repo_id -> folder group perms */
    pthread_mutex_t perm_lock;
};

static const char *ignore_table[] = {
    /* tmp files under Linux */
    "*~",
    /* Emacs tmp files */
    "#*#",
    /* windows image cache */
    "Thumbs.db",
    /* For Mac */
    ".DS_Store",
    NULL,
};

static GPatternSpec** ignore_patterns;
static GPatternSpec* office_temp_ignore_patterns[4];


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

    path = sqlite3_column_text (stmt, 0);
    permission = sqlite3_column_text (stmt, 1);

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
    repo->net_browsable = 0;
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
        seaf_warning ("Failed to access worktree %s for repo '%s'(%.8s)\n",
                      repo->worktree, repo->name, repo->id);
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
    }
    commit->no_local_history = repo->no_local_history;
    commit->version = repo->version;
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
should_ignore_on_checkout (const char *file_path)
{
    gboolean ret = FALSE;

#ifdef WIN32
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
#endif

    return ret;
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
                                      path, sha1, &size, crypt, write_data, TRUE) < 0) {
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

    if (options)
        is_writable = is_path_writable(repo_id,
                                       options->is_repo_ro, path);

    is_locked = seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                      repo_id, path);

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
                                                  status);
    }

    if (!is_writable || is_locked)
        return ret;

#ifdef WIN32
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
                                                  SYNC_STATUS_SYNCED);
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
                              NULL,
                              TRUE);
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
                                                  SYNC_STATUS_SYNCED);
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
                              NULL,
                              TRUE);
        }
    } else
        g_queue_push_tail (*remain_files, g_strdup(path));

    if (ret < 0)
        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              repo_id,
                                              path,
                                              S_IFREG,
                                              SYNC_STATUS_ERROR);

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

    dir = g_dir_open (full_path, 0, NULL);
    if (!dir) {
        seaf_warning ("Failed to open dir %s: %s.\n", full_path, strerror(errno));

        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                              params->repo_id,
                                              path,
                                              S_IFDIR,
                                              SYNC_STATUS_ERROR);

        return 0;
    }

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
                                                          SYNC_STATUS_IGNORED);
            }
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
                                                  status);
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
                                  NULL,
                                  TRUE);
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
                                              SYNC_STATUS_ERROR);

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
                                                      SYNC_STATUS_IGNORED);
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
                                              SYNC_STATUS_ERROR);
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
                                                  status);
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
                                  NULL,
                                  TRUE);
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
                                              SYNC_STATUS_ERROR);
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
        if (!should_ignore (path, dname, ignore_list)) {
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
#ifdef WIN32
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
                        add_to_changeset (changeset,
                                          DIFF_STATUS_DIR_DELETED,
                                          NULL,
                                          NULL,
                                          NULL,
                                          ce->name,
                                          NULL,
                                          TRUE);
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
                    add_to_changeset (changeset,
                                      DIFF_STATUS_DELETED,
                                      NULL,
                                      NULL,
                                      NULL,
                                      ce->name,
                                      NULL,
                                      TRUE);
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

#ifndef __APPLE__

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

#else

static int
add_path_to_index (SeafRepo *repo, struct index_state *istate,
                   SeafileCrypt *crypt, const char *path, GList *ignore_list,
                   GList **scanned_dirs, gint64 *total_size, GQueue **remain_files,
                   LockedFileSet *fset)
{
    SeafStat st;

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

        if (S_ISREG(st.st_mode)) {
            gboolean added = FALSE;
            add_to_index (repo->id, repo->version, istate, path, full_path,
                          &st, 0, crypt, index_cb, repo->email, &added);
            if (added) {
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
                                                      SYNC_STATUS_SYNCED);
            }

            if (added) {
                ce = index_name_exists (istate, path, strlen(path), 0);
                add_to_changeset (repo->changeset,
                                  DIFF_STATUS_ADDED,
                                  ce->sha1,
                                  &st,
                                  repo->email,
                                  path,
                                  NULL,
                                  TRUE);
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
                                      NULL,
                                      TRUE);
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
update_ce_mode (struct index_state *istate, const char *worktree, const char *path)
{
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
    if (new_mode != ce->ce_mode)
        ce->ce_mode = new_mode;
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
    wchar_t *path_w;
    wchar_t *dir_w = NULL;
    wchar_t *p;
    char *dir = NULL;
    char *p2;
    gboolean convertion_failed = FALSE;

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
        else
            convertion_failed = TRUE;
    }

    if (!dir_w)
        dir_w = wcsdup(L"");

    dir = g_utf16_to_utf8 (dir_w, -1, NULL, NULL, NULL);
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
    if (!convertion_failed) {
        char *basename = strrchr (path, '/');
        char *deleted_path = NULL;
        if (basename) {
            deleted_path = g_build_path ("/", dir, basename, NULL);
            add_to_changeset (changeset,
                              DIFF_STATUS_DELETED,
                              NULL,
                              NULL,
                              NULL,
                              deleted_path,
                              NULL,
                              FALSE);
            g_free (deleted_path);
        }
    }

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
        }
        if (*total_size >= MAX_COMMIT_SIZE)
            return TRUE;
    }

    return FALSE;
}

#ifdef __APPLE__

struct _WTDirent {
    char *dname;
    struct stat st;
};
typedef struct _WTDirent WTDirent;

static gint
compare_wt_dirents (gconstpointer a, gconstpointer b)
{
    const WTDirent *dent_a = a, *dent_b = b;

    return (strcmp (dent_a->dname, dent_b->dname));
}

static GList *
get_sorted_wt_dirents (const char *dir_path, const char *full_dir_path,
                       gboolean *error)
{
    GDir *dir;
    GError *err = NULL;
    const char *name;
    char *dname;
    char *full_sub_path, *sub_path;
    WTDirent *dent;
    GList *ret = NULL;

    dir = g_dir_open (full_dir_path, 0, &err);
    if (!dir) {
        seaf_warning ("Failed to open dir %s: %s.\n", full_dir_path, err->message);
        *error = TRUE;
        return NULL;
    }

    while ((name = g_dir_read_name(dir)) != NULL) {
        dname = g_utf8_normalize (name, -1, G_NORMALIZE_NFC);
        sub_path = g_strconcat (dir_path, "/", dname, NULL);
        full_sub_path = g_strconcat (full_dir_path, "/", dname, NULL);

        dent = g_new0 (WTDirent, 1);
        dent->dname = dname;

        if (stat (full_sub_path, &dent->st) < 0) {
            seaf_warning ("Failed to stat %s: %s.\n", full_sub_path, strerror(errno));
            g_free (dname);
            g_free (sub_path);
            g_free (full_sub_path);
            g_free (dent);
            continue;
        }

        ret = g_list_prepend (ret, dent);

        g_free (sub_path);
        g_free (full_sub_path);
    }

    g_dir_close (dir);

    ret = g_list_sort (ret, compare_wt_dirents);
    return ret;
}

static void
wt_dirent_free (WTDirent *dent)
{
    if (!dent)
        return;
    g_free (dent->dname);
    g_free (dent);
}

inline static char *
concat_sub_path (const char *dir, const char *dname)
{
    if (dir[0] != 0)
        return g_strconcat(dir, "/", dname, NULL);
    else
        return g_strdup(dname);
}

static int
get_changed_paths_in_folder (SeafRepo *repo, struct index_state *istate,
                             const char *dir_path,
                             GList **add, GList **mod, GList **del)
{
    char *full_dir_path;
    GList *wt_dents = NULL, *index_dents = NULL;
    gboolean error = FALSE;

    full_dir_path = g_build_filename(repo->worktree, dir_path, NULL);

    wt_dents = get_sorted_wt_dirents (dir_path, full_dir_path, &error);
    if (error) {
        g_free (full_dir_path);
        return -1;
    }

    index_dents = list_dirents_from_index (istate, dir_path);

    GList *p;
    IndexDirent *dent;
    for (p = index_dents; p; p = p->next) {
        dent = p->data;
    }

    GList *p1 = wt_dents, *p2 = index_dents;
    WTDirent *dent1;
    IndexDirent *dent2;

    while (p1 && p2) {
        dent1 = p1->data;
        dent2 = p2->data;

        int rc = strcmp (dent1->dname, dent2->dname);
        if (rc == 0) {
            if (S_ISREG(dent1->st.st_mode) && !dent2->is_dir) {
                if (dent1->st.st_mtime != dent2->ce->ce_mtime.sec)
                    *mod = g_list_prepend (*mod, concat_sub_path(dir_path, dent1->dname));
            } else if ((S_ISREG(dent1->st.st_mode) && dent2->is_dir) ||
                       (S_ISDIR(dent1->st.st_mode) && !dent2->is_dir)) {
                *add = g_list_prepend (*add, concat_sub_path(dir_path, dent1->dname));
                *del = g_list_prepend (*del, concat_sub_path(dir_path, dent1->dname));
            }
            p1 = p1->next;
            p2 = p2->next;
        } else if (rc < 0) {
            *add = g_list_prepend (*add, concat_sub_path(dir_path, dent1->dname));
            p1 = p1->next;
        } else {
            *del = g_list_prepend (*del, concat_sub_path(dir_path, dent2->dname));
            p2 = p2->next;
        }
    }

    while (p1) {
        dent1 = p1->data;
        *add = g_list_prepend (*add, concat_sub_path(dir_path, dent1->dname));
        p1 = p1->next;
    }

    while (p2) {
        dent2 = p2->data;
        *del = g_list_prepend (*del, concat_sub_path(dir_path, dent2->dname));
        p2 = p2->next;
    }

    g_free (full_dir_path);
    g_list_free_full (wt_dents, (GDestroyNotify)wt_dirent_free);
    g_list_free_full (index_dents, (GDestroyNotify)index_dirent_free);
    return 0;
}

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
                                              SYNC_STATUS_IGNORED);
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
                                                  status);
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
    SyncStatus status;
    gboolean ignored = FALSE;
    SeafStat st;

    dname = g_utf16_to_utf8 (fdata->cFileName, -1, NULL, NULL, NULL);
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
    SyncStatus status;
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
                                                  SYNC_STATUS_IGNORED);
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
                                                  status);
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
                                                  SYNC_STATUS_IGNORED);
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
                                                  status);
        }
    }
}

#endif  /* WIN32 */

static void
process_active_path (SeafRepo *repo, const char *path,
                     struct index_state *istate, GList *ignore_list)
{
    SeafStat st;
    SyncStatus status;
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

static void
process_active_folder (SeafRepo *repo, const char *dir,
                       struct index_state *istate, GList *ignore_list)
{
    GList *add = NULL, *mod = NULL, *del = NULL;
    GList *p;
    char *path;

    /* Delete event will be triggered on the deleted dir too. */
    if (!g_file_test (dir, G_FILE_TEST_IS_DIR))
        return;

    if (get_changed_paths_in_folder (repo, istate, dir, &add, &mod, &del) < 0) {
        seaf_warning ("Failed to get changed paths under %s.\n", dir);
        return;
    }

    for (p = add; p; p = p->next) {
        path = p->data;
        process_active_path (repo, path, istate, ignore_list);
    }

    for (p = mod; p; p = p->next) {
        path = p->data;
        process_active_path (repo, path, istate, ignore_list);
    }

    g_list_free_full (add, g_free);
    g_list_free_full (mod, g_free);
    g_list_free_full (del, g_free);
}

#endif  /* __APPLE__ */

static void
update_path_sync_status (SeafRepo *repo, WTStatus *status,
                         struct index_state *istate, GList *ignore_list)
{
    char *path, *dir;

    while (1) {
        pthread_mutex_lock (&status->ap_q_lock);
        path = g_queue_pop_head (status->active_paths);
        pthread_mutex_unlock (&status->ap_q_lock);

        if (!path)
            break;

#ifdef __APPLE__
        process_active_folder (repo, path, istate, ignore_list);
#else
        process_active_path (repo, path, istate, ignore_list);
#endif

        g_free (path);
    }
}

static void
handle_rename (SeafRepo *repo, struct index_state *istate,
               SeafileCrypt *crypt, GList *ignore_list,
               LockedFileSet *fset,
               WTEvent *event, GList **scanned_del_dirs)
{
    gboolean not_found, src_ignored, dst_ignored;

    if (!is_path_writable(repo->id,
                          repo->is_readonly, event->path) ||
        !is_path_writable(repo->id,
                          repo->is_readonly, event->new_path)) {
        seaf_debug ("Rename: %s or %s is not writable, ignore.\n",
                    event->path, event->new_path);
        return;
    }

    if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                              repo->id, event->path) ||
        seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                              repo->id, event->new_path)) {
        seaf_debug ("Rename: %s or %s is locked on server, ignore.\n", event->path, event->new_path);
        return;
    }

    src_ignored = check_full_path_ignore(repo->worktree, event->path, ignore_list);
    dst_ignored = check_full_path_ignore(repo->worktree, event->new_path, ignore_list);

    /* If the destination path is ignored, just remove the source path. */
    if (dst_ignored) {
        if (!src_ignored && check_locked_file_before_remove (fset, event->path)) {
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

            add_to_changeset (repo->changeset,
                              DIFF_STATUS_DELETED,
                              NULL,
                              NULL,
                              NULL,
                              event->path,
                              NULL,
                              FALSE);
        }
        return;
    }

    /* Now the destination path is not ignored. */

    if (!src_ignored && check_locked_file_before_remove (fset, event->path)) {
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
                          event->new_path,
                          TRUE);
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
                   NULL, NULL, &options);
}

static int
apply_worktree_changes_to_index (SeafRepo *repo, struct index_state *istate,
                                 SeafileCrypt *crypt, GList *ignore_list,
                                 LockedFileSet *fset)
{
    WTStatus *status;
    WTEvent *event, *next_event;
    gboolean not_found;

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
                seaf_debug ("%s is not writable, ignore.\n", event->path);
                break;
            }

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
            if (check_full_path_ignore(repo->worktree, event->path, ignore_list))
                break;

            if (!is_path_writable(repo->id,
                                  repo->is_readonly, event->path)) {
                seaf_debug ("%s is not writable, ignore.\n", event->path);
                break;
            }

            if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                      repo->id, event->path)) {
                seaf_debug ("%s is locked on server, ignore.\n", event->path);
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

                add_to_changeset (repo->changeset,
                                  DIFF_STATUS_DELETED,
                                  NULL,
                                  NULL,
                                  NULL,
                                  event->path,
                                  NULL,
                                  TRUE);

                try_add_empty_parent_dir_entry_from_wt (repo->worktree,
                                                        istate,
                                                        ignore_list,
                                                        event->path);
            }
            break;
        case WT_EVENT_RENAME:
            handle_rename (repo, istate, crypt, ignore_list, fset, event, &scanned_del_dirs);
            break;
        case WT_EVENT_ATTRIB:
            if (!is_path_writable(repo->id,
                                  repo->is_readonly, event->path)) {
                seaf_debug ("%s is not writable, ignore.\n", event->path);
                break;
            }
            update_ce_mode (istate, repo->worktree, event->path);
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

static void
handle_unmerged_index_entries (SeafRepo *repo, struct index_state *istate,
                               SeafileCrypt *crypt, GList *ignore_list)
{
    struct cache_entry **ce_array = istate->cache;
    struct cache_entry *ce;
    char path[SEAF_PATH_MAX];
    unsigned int i;
    SeafStat st;
    int ret;
    GList *unmerged_paths = NULL;
    char *last_name = "";

retry:
    for (i = 0; i < istate->cache_nr; ++i) {
        ce = ce_array[i];

        if (ce_stage(ce) == 0)
            continue;

        snprintf (path, SEAF_PATH_MAX, "%s/%s", repo->worktree, ce->name);
        ret = seaf_stat (path, &st);

        if (S_ISDIR (ce->ce_mode)) {
            if (ret < 0 || !S_ISDIR (st.st_mode)
                || !is_empty_dir (path, ignore_list))
                ce->ce_flags |= CE_REMOVE;
            else if (strcmp (ce->name, last_name) != 0) {
                unmerged_paths = g_list_append (unmerged_paths, g_strdup(ce->name));
                last_name = ce->name;
            }
        } else {
            if (ret < 0 || !S_ISREG (st.st_mode))
                ce->ce_flags |= CE_REMOVE;
            else if (strcmp (ce->name, last_name) != 0) {
                unmerged_paths = g_list_append (unmerged_paths, g_strdup(ce->name));
                last_name = ce->name;
            }
        }
    }

    remove_marked_cache_entries (istate);

    GList *ptr;
    char *ce_name;
    for (ptr = unmerged_paths; ptr; ptr = ptr->next) {
        ce_name = ptr->data;
        snprintf (path, SEAF_PATH_MAX, "%s/%s", repo->worktree, ce_name);
        ret = seaf_stat (path, &st);
        if (ret < 0) {
            seaf_warning ("Failed to stat %s: %s.\n", path, strerror(errno));
            string_list_free (unmerged_paths);
            unmerged_paths = NULL;
            goto retry;
        }

        if (S_ISDIR (st.st_mode)) {
            if (is_empty_dir (path, ignore_list))
                add_empty_dir_to_index (istate, ce_name, &st);
        } else {
            gboolean added;
            add_to_index (repo->id, repo->version, istate, ce_name, path,
                          &st, 0, crypt, index_cb, repo->email, &added);
        }
    }

    string_list_free (unmerged_paths);
}

static int
index_add (SeafRepo *repo, struct index_state *istate,
           gboolean is_force_commit, gboolean handle_unmerged)
{
    SeafileCrypt *crypt = NULL;
    LockedFileSet *fset = NULL;
    GList *ignore_list = NULL;
    GList *ptr;
    int ret = 0;

    if (repo->encrypted) {
        crypt = seafile_crypt_new (repo->enc_version, repo->enc_key, repo->enc_iv);
    }

#ifdef WIN32
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

    /* If the index contains unmerged entries, check and remove those entries
     * in the end, in cases where they were not completely handled in
     * apply_worktree_changes_to_index().
     */
    if (handle_unmerged)
        handle_unmerged_index_entries (repo, istate, crypt, ignore_list);

    seaf_repo_free_ignore_files (ignore_list);

#ifdef WIN32
    locked_file_set_free (fset);
#endif

    g_free (crypt);

    return ret;
}

/*
 * Add the files in @worktree to index and return the corresponding
 * @root_id. The repo doesn't have to exist.
 */
int
seaf_repo_index_worktree_files (const char *repo_id,
                                int repo_version,
                                const char *modifier,
                                const char *worktree,
                                const char *passwd,
                                int enc_version,
                                const char *random_key,
                                char *root_id)
{
    char index_path[SEAF_PATH_MAX];
    struct index_state istate;
    unsigned char key[32], iv[16];
    SeafileCrypt *crypt = NULL;
    struct cache_tree *it = NULL;
    GList *ignore_list = NULL;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", seaf->repo_mgr->index_dir, repo_id);

    /* Remove existing index. An existing index signifies an interrupted
     * clone-merge. Removing it assures that new blocks from the worktree
     * get added into the repo again (they're deleted by GC).
     */
    seaf_util_unlink (index_path);

    if (read_index_from (&istate, index_path, repo_version) < 0) {
        seaf_warning ("Failed to load index.\n");
        return -1;
    }

    if (passwd != NULL) {
        if (seafile_decrypt_repo_enc_key (enc_version, passwd,
                                          random_key, key, iv) < 0) {
            seaf_warning ("Failed to generate enc key for repo %s.\n", repo_id);
            goto error;
        }
        crypt = seafile_crypt_new (enc_version, key, iv);
    }

    ignore_list = seaf_repo_load_ignore_files(worktree);

    /* Add empty dir to index. Otherwise if the repo on relay contains an empty
     * dir, we'll fail to detect fast-forward relationship later.
     */
    if (add_recursive (repo_id, repo_version, modifier,
                       &istate, worktree, "", crypt, FALSE, ignore_list,
                       NULL, NULL, NULL) < 0)
        goto error;

    remove_deleted (&istate, worktree, "", ignore_list, NULL, repo_id, FALSE, NULL);

    it = cache_tree ();
    if (cache_tree_update (repo_id, repo_version, worktree,
                           it, istate.cache, istate.cache_nr,
                           0, 0, commit_trees_cb) < 0) {
        seaf_warning ("Failed to build cache tree");
        goto error;
    }

    rawdata_to_hex (it->sha1, root_id, 20);

    if (update_index (&istate, index_path) < 0)
        goto error;

    discard_index (&istate);
    g_free (crypt);
    if (it)
        cache_tree_free (&it);
    seaf_repo_free_ignore_files(ignore_list);
    return 0;

error:
    discard_index (&istate);
    g_free (crypt);
    if (it)
        cache_tree_free (&it);
    seaf_repo_free_ignore_files(ignore_list);
    return -1;
}

gboolean
seaf_repo_is_worktree_changed (SeafRepo *repo)
{
    SeafRepoManager *mgr = repo->manager;
    GList *res = NULL, *p;
    struct index_state istate;
    char index_path[SEAF_PATH_MAX];

    DiffEntry *de;
    int pos;
    struct cache_entry *ce;
    SeafStat sb;
    char *full_path;

    if (!check_worktree_common (repo))
        return FALSE;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path, repo->version) < 0) {
        repo->index_corrupted = TRUE;
        seaf_warning ("Failed to load index.\n");
        goto error;
    }
    repo->index_corrupted = FALSE;

    wt_status_collect_changes_worktree (&istate, &res, repo->worktree);
    if (res != NULL)
        goto changed;

    wt_status_collect_untracked (&istate, &res, repo->worktree, should_ignore);
    if (res != NULL)
        goto changed;

    wt_status_collect_changes_index (&istate, &res, repo);
    if (res != NULL)
        goto changed;

    discard_index (&istate);

    repo->wt_changed = FALSE;

    /* g_debug ("%s worktree is changed\n", repo->id); */
    return FALSE;

changed:

    g_message ("Worktree changes (at most 5 files are shown):\n");
    int i = 0;
    for (p = res; p != NULL && i < 5; p = p->next, ++i) {
        de = p->data;

        full_path = g_build_path ("/", repo->worktree, de->name, NULL);
        if (seaf_stat (full_path, &sb) < 0) {
            seaf_warning ("Failed to stat %s: %s.\n", full_path, strerror(errno));
            g_free (full_path);
            continue;
        }
        g_free (full_path);

        pos = index_name_pos (&istate, de->name, strlen(de->name));
        if (pos < 0) {
            seaf_warning ("Cannot find diff entry %s in index.\n", de->name);
            continue;
        }
        ce = istate.cache[pos];

        g_message ("type: %c, status: %c, name: %s, "
                   "ce mtime: %"G_GINT64_FORMAT", ce size: %" G_GUINT64_FORMAT ", "
                   "file mtime: %d, file size: %" G_GUINT64_FORMAT "\n",
                   de->type, de->status, de->name,
                   ce->ce_mtime.sec, ce->ce_size, (int)sb.st_mtime, sb.st_size);
    }

    for (p = res; p; p = p->next) {
        de = p->data;
        diff_entry_free (de);
    }
    g_list_free (res);

    discard_index (&istate);

    repo->wt_changed = TRUE;

    /* g_debug ("%s worktree is changed\n", repo->id); */
    return TRUE;

error:
    return FALSE;
}

/*
 * Generate commit description based on files to be commited.
 * It only checks index status, not worktree status.
 * So it should be called after "add" completes.
 * This way we can always get the correct list of files to be
 * commited, even we were interrupted in the last add-commit
 * sequence.
 */
static char *
gen_commit_description (SeafRepo *repo, struct index_state *istate)
{
    GList *p;
    GList *results = NULL;
    char *desc;
    
    wt_status_collect_changes_index (istate, &results, repo);
    diff_resolve_empty_dirs (&results);
    diff_resolve_renames (&results);

    desc = diff_results_to_description (results);
    if (!desc)
        return NULL;

    for (p = results; p; p = p->next) {
        DiffEntry *de = p->data;
        diff_entry_free (de);
    }
    g_list_free (results);

    return desc;
}

gboolean
seaf_repo_is_index_unmerged (SeafRepo *repo)
{
    SeafRepoManager *mgr = repo->manager;
    struct index_state istate;
    char index_path[SEAF_PATH_MAX];
    gboolean ret = FALSE;

    if (!repo->head)
        return FALSE;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path, repo->version) < 0) {
        seaf_warning ("Failed to load index.\n");
        return FALSE;
    }

    if (unmerged_index (&istate))
        ret = TRUE;

    discard_index (&istate);
    return ret;
}

static int
commit_tree (SeafRepo *repo, const char *root_id,
             const char *desc, char commit_id[],
             gboolean unmerged)
{
    SeafCommit *commit;

    commit = seaf_commit_new (NULL, repo->id, root_id,
                              repo->email ? repo->email
                              : seaf->session->base.user_name,
                              seaf->session->base.id,
                              desc, 0);

    if (repo->head)
        commit->parent_id = g_strdup (repo->head->commit_id);

    if (unmerged) {
        SeafRepoMergeInfo minfo;

        /* Don't use head commit of master branch since that branch may have
         * been updated after the last merge.
         */
        memset (&minfo, 0, sizeof(minfo));
        if (seaf_repo_manager_get_merge_info (repo->manager, repo->id, &minfo) < 0) {
            seaf_warning ("Failed to get merge info of repo %.10s.\n", repo->id);
            return -1;
        }

        commit->second_parent_id = g_strdup (minfo.remote_head);
        commit->new_merge = TRUE;
        commit->conflict = TRUE;
    }

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
need_handle_unmerged_index (SeafRepo *repo, struct index_state *istate)
{
    if (!unmerged_index (istate))
        return FALSE;

    /* Syncing with an existing directory may require a real merge.
     * If the merge produced conflicts, the index will be unmerged.
     * But we don't want to generate a merge commit in this case.
     * An "index" branch should exist in this case.
     */
    if (seaf_branch_manager_branch_exists (seaf->branch_mgr, repo->id, "index"))
        return FALSE;

    return TRUE;
}

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

static inline void
print_time (const char *desc, GTimeVal *s, GTimeVal *e)
{
    seaf_message ("%s: %lu\n", desc,
                  (e->tv_sec*G_USEC_PER_SEC+e->tv_usec - (s->tv_sec*G_USEC_PER_SEC+s->tv_usec))/1000);
}

char *
seaf_repo_index_commit (SeafRepo *repo, const char *desc, gboolean is_force_commit,
                        GError **error)
{
    SeafRepoManager *mgr = repo->manager;
    struct index_state istate;
    char index_path[SEAF_PATH_MAX];
    char *root_id = NULL;
    char commit_id[41];
    gboolean unmerged = FALSE;
    ChangeSet *changeset = NULL;
    char *my_desc = NULL;
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

    if (need_handle_unmerged_index (repo, &istate))
        unmerged = TRUE;

    GTimeVal s, e;

    g_get_current_time (&s);

    changeset = changeset_new (repo->id);
    repo->changeset = changeset;

    if (index_add (repo, &istate, is_force_commit, unmerged) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Failed to add");
        goto out;
    }

    g_get_current_time (&e);
    print_time ("index_add", &s, &e);

    if (!istate.cache_changed)
        goto out;

    g_get_current_time (&s);

    my_desc = diff_results_to_description (changeset->diff);
    if (!my_desc)
        my_desc = g_strdup("");

    g_get_current_time (&e);
    print_time ("gen_commit_description", &s, &e);

    g_get_current_time (&s);

    root_id = commit_tree_from_changeset (changeset);
    if (!root_id) {
        seaf_warning ("Create commit tree failed for repo %s\n", repo->id);
        goto out;
    }

    g_get_current_time (&e);
    print_time ("cache_tree_update", &s, &e);

    if (commit_tree (repo, root_id, my_desc, commit_id, unmerged) < 0) {
        seaf_warning ("Failed to save commit file");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Internal error");
        goto out;
    }

    if (update_index (&istate, index_path) < 0)
        goto out;

    g_signal_emit_by_name (seaf, "repo-committed", repo);

    ret = g_strdup(commit_id);

out:
    g_free (my_desc);
    g_free (root_id);
    changeset_free (changeset);
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

int
seaf_repo_checkout_commit (SeafRepo *repo, SeafCommit *commit, gboolean recover_merge,
                           char **error)
{
    SeafRepoManager *mgr = repo->manager;
    char index_path[SEAF_PATH_MAX];
    struct tree_desc trees[2];
    struct unpack_trees_options topts;
    struct index_state istate;
    gboolean initial_checkout;
    GString *err_msgs;
    int ret = 0;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path, repo->version) < 0) {
        seaf_warning ("Failed to load index.\n");
        return -1;
    }
    repo->index_corrupted = FALSE;
    initial_checkout = is_index_unborn(&istate);

    if (!initial_checkout) {
        if (!repo->head) {
            /* TODO: Set error string*/
            seaf_warning ("Repo corrupt: Index exists but head branch is not set\n");
            return -1;
        }
        SeafCommit *head =
            seaf_commit_manager_get_commit (seaf->commit_mgr,
                                            repo->id, repo->version,
                                            repo->head->commit_id);
        if (!head) {
            seaf_warning ("Failed to get commit %s:%s.\n",
                          repo->id, repo->head->commit_id);
            discard_index (&istate);
            return -1;
        }
        fill_tree_descriptor (repo->id, repo->version, &trees[0], head->root_id);
        seaf_commit_unref (head);
    } else {
        fill_tree_descriptor (repo->id, repo->version, &trees[0], NULL);
    }
    fill_tree_descriptor (repo->id, repo->version, &trees[1], commit->root_id);

    /* 2-way merge to the new branch */
    memset(&topts, 0, sizeof(topts));
    memcpy (topts.repo_id, repo->id, 36);
    topts.version = repo->version;
    topts.base = repo->worktree;
    topts.head_idx = -1;
    topts.src_index = &istate;
    /* topts.dst_index = &istate; */
    topts.initial_checkout = initial_checkout;
    topts.update = 1;
    topts.merge = 1;
    topts.gently = 0;
    topts.verbose_update = 0;
    /* topts.debug_unpack = 1; */
    topts.fn = twoway_merge;
    if (repo->encrypted) {
        topts.crypt = seafile_crypt_new (repo->enc_version, 
                                         repo->enc_key, 
                                         repo->enc_iv);
    }

    if (unpack_trees (2, trees, &topts) < 0) {
        seaf_warning ("Failed to merge commit %s with work tree.\n", commit->commit_id);
        ret = -1;
        goto out;
    }

#ifdef WIN32
    if (!initial_checkout && !recover_merge &&
        files_locked_on_windows(&topts.result, repo->worktree)) {
        g_debug ("[checkout] files are locked, quit checkout now.\n");
        ret = -1;
        goto out;
    }
#endif

    int *finished_entries = NULL;
    CheckoutTask *c_task = seaf_repo_manager_get_checkout_task (repo->manager, repo->id);
    if (c_task) {
        finished_entries = &c_task->finished_files;
    }
    if (update_worktree (&topts, recover_merge,
                         initial_checkout ? NULL : commit->commit_id,
                         commit->creator_name,
                         finished_entries) < 0) {
        seaf_warning ("Failed to update worktree.\n");
        /* Still finish checkout even have I/O errors. */
    }

    discard_index (&istate);
    istate = topts.result;
    if (update_index (&istate, index_path) < 0) {
        seaf_warning ("Failed to update index.\n");
        ret = -1;
        goto out;
    }

out:
    err_msgs = g_string_new ("");
    get_unpack_trees_error_msgs (&topts, err_msgs, OPR_CHECKOUT);
    *error = g_string_free (err_msgs, FALSE);

    tree_desc_free (&trees[0]);
    tree_desc_free (&trees[1]);

    g_free (topts.crypt);

    discard_index (&istate);

    return ret;
}


/**
 * Checkout the content of "local" branch to <worktree_parent>/repo-name.
 * The worktree will be set to this place too.
 */
int
seaf_repo_checkout (SeafRepo *repo, const char *worktree, char **error)
{
    const char *commit_id;
    SeafBranch *branch;
    SeafCommit *commit;
    GString *err_msgs;

    /* remove original index */
    char index_path[SEAF_PATH_MAX];
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", repo->manager->index_dir, repo->id);
    seaf_util_unlink (index_path);

    branch = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                             repo->id, "local");
    if (!branch) {
        seaf_warning ("[repo-mgr] Checkout repo failed: local branch does not exists\n");
        *error = g_strdup ("Repo's local branch does not exists.");
        goto error;
    }
    commit_id = branch->commit_id;
        
    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->id,
                                             repo->version,
                                             commit_id);
    if (!commit) {
        err_msgs = g_string_new ("");
        g_string_append_printf (err_msgs, "Commit %s does not exist.\n",
                                commit_id);
        seaf_warning ("%s", err_msgs->str);
        *error = g_string_free (err_msgs, FALSE);
        seaf_branch_unref (branch);
        goto error;
    }

    if (strcmp(repo->id, commit->repo_id) != 0) {
        err_msgs = g_string_new ("");
        g_string_append_printf (err_msgs, "Commit %s is not in Repo %s.\n", 
                                commit_id, repo->id);
        seaf_warning ("%s", err_msgs->str);
        *error = g_string_free (err_msgs, FALSE);
        seaf_commit_unref (commit);
        if (branch)
            seaf_branch_unref (branch);
        goto error;
    }

    CheckoutTask *task = seaf_repo_manager_get_checkout_task (seaf->repo_mgr,
                                                              repo->id);
    if (!task) {
        seaf_warning ("No checkout task found for repo %.10s.\n", repo->id);
        goto error;
    }
    task->total_files = seaf_fs_manager_count_fs_files (seaf->fs_mgr,
                                                        repo->id, repo->version,
                                                        commit->root_id);

    if (task->total_files < 0) {
        seaf_warning ("Failed to count files for repo %.10s .\n", repo->id);
        goto error;
    }

    if (seaf_repo_checkout_commit (repo, commit, FALSE, error) < 0) {
        seaf_commit_unref (commit);
        if (branch)
            seaf_branch_unref (branch);
        goto error;
    }

    seaf_branch_unref (branch);
    seaf_commit_unref (commit);

    return 0;

error:
    return -1;
}

int
seaf_repo_merge (SeafRepo *repo, const char *branch, char **error,
                 int *merge_status)
{
    SeafBranch *remote_branch;
    int ret = 0;

    if (!check_worktree_common (repo))
        return -1;

    remote_branch = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                    repo->id,
                                                    branch);
    if (!remote_branch) {
        *error = g_strdup("Invalid remote branch.\n");
        goto error;
    }

    if (g_strcmp0 (remote_branch->repo_id, repo->id) != 0) {
        *error = g_strdup ("Remote branch is not in this repository.\n");
        seaf_branch_unref (remote_branch);
        goto error;
    }

    ret = merge_branches (repo, remote_branch, error, merge_status);
    seaf_branch_unref (remote_branch);

    return ret;

error:
    return -1;
}

int
checkout_file (const char *repo_id,
               int repo_version,
               const char *worktree,
               const char *name,
               const char *file_id,
               gint64 mtime,
               unsigned int mode,
               SeafileCrypt *crypt,
               struct cache_entry *ce,
               TransferTask *task,
               HttpTxTask *http_task,
               gboolean is_http,
               const char *conflict_head_id,
               GHashTable *conflict_hash,
               GHashTable *no_conflict_hash,
               gboolean download_only)
{
    char *path;
    SeafStat st, st2;
    unsigned char sha1[20];
    gboolean path_exists = FALSE;
    gboolean case_conflict = FALSE;
    gboolean force_conflict = FALSE;
    gboolean update_mode_only = FALSE;

#ifndef __linux__
    path = build_case_conflict_free_path (worktree, name,
                                          conflict_hash, no_conflict_hash,
                                          &case_conflict,
                                          FALSE);
#else
    path = build_checkout_path (worktree, name, strlen(name));
#endif

    if (!path)
        return FETCH_CHECKOUT_FAILED;

    hex_to_rawdata (file_id, sha1, 20);

    path_exists = (seaf_stat (path, &st) == 0);

    if (path_exists && S_ISREG(st.st_mode)) {
        if (st.st_mtime == ce->ce_mtime.sec) {
            /* Worktree and index are consistent. */
            if (memcmp (sha1, ce->sha1, 20) == 0) {
                if (mode == ce->ce_mode) {
                    /* Worktree and index are all uptodate, no need to checkout.
                     * This may happen after an interrupted checkout.
                     */
                    seaf_debug ("wt and index are consistent. no need to checkout.\n");
                    goto update_cache;
                } else
                    update_mode_only = TRUE;
            }
            /* otherwise we have to checkout the file. */
        } else {
            if (compare_file_content (path, &st, sha1, crypt, repo_version) == 0) {
                /* This happens after the worktree file was updated,
                 * but the index was not. Just need to update the index.
                 */
                seaf_debug ("update index only.\n");
                goto update_cache;
            } else {
                /* Conflict. The worktree file was updated by the user. */
                seaf_message ("File %s is updated by user. "
                              "Will checkout to conflict file later.\n", path);
                force_conflict = TRUE;
            }
        }
    }

    if (update_mode_only) {
#ifdef WIN32
        g_free (path);
        return FETCH_CHECKOUT_SUCCESS;
#else
        chmod (path, mode & ~S_IFMT);
        ce->ce_mode = mode;
        g_free (path);
        return FETCH_CHECKOUT_SUCCESS;
#endif
    }

    /* Download the blocks of this file. */
    int rc;
    if (!is_http) {
        rc = seaf_transfer_manager_download_file_blocks (seaf->transfer_mgr,
                                                         task, file_id);
        switch (rc) {
        case BLOCK_CLIENT_SUCCESS:
            break;
        case BLOCK_CLIENT_UNKNOWN:
        case BLOCK_CLIENT_FAILED:
        case BLOCK_CLIENT_NET_ERROR:
        case BLOCK_CLIENT_SERVER_ERROR:
            g_free (path);
            return FETCH_CHECKOUT_TRANSFER_ERROR;
        case BLOCK_CLIENT_CANCELED:
            g_free (path);
            return FETCH_CHECKOUT_CANCELED;
        }
    } else {
        rc = http_tx_task_download_file_blocks (http_task, file_id);
        if (http_task->state == HTTP_TASK_STATE_CANCELED) {
            g_free (path);
            return FETCH_CHECKOUT_CANCELED;
        }
        if (rc < 0) {
            g_free (path);
            return FETCH_CHECKOUT_TRANSFER_ERROR;
        }
    }

    if (download_only) {
        g_free (path);
        return FETCH_CHECKOUT_SUCCESS;
    }

    /* The worktree file may have been changed when we're downloading the blocks. */
    if (path_exists && S_ISREG(st.st_mode) && !force_conflict) {
        seaf_stat (path, &st2);
        if (st.st_mtime != st2.st_mtime) {
            seaf_message ("File %s is updated by user. "
                          "Will checkout to conflict file later.\n", path);
            force_conflict = TRUE;
        }
    }

    /* Temporarily unlock the file if it's locked on server, so that the client
     * itself can write to it. 
     */
    if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                              repo_id, name))
        seaf_filelock_manager_unlock_wt_file (seaf->filelock_mgr,
                                              repo_id, name);

    /* then checkout the file. */
    gboolean conflicted = FALSE;
    if (seaf_fs_manager_checkout_file (seaf->fs_mgr,
                                       repo_id,
                                       repo_version,
                                       file_id,
                                       path,
                                       mode,
                                       mtime,
                                       crypt,
                                       name,
                                       conflict_head_id,
                                       force_conflict,
                                       &conflicted,
                                       is_http ? http_task->email : task->email) < 0) {
        seaf_warning ("Failed to checkout file %s.\n", path);
        g_free (path);

        if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                  repo_id, name))
            seaf_filelock_manager_lock_wt_file (seaf->filelock_mgr,
                                                repo_id, name);

        return FETCH_CHECKOUT_FAILED;
    }

    if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                              repo_id, name))
        seaf_filelock_manager_lock_wt_file (seaf->filelock_mgr,
                                            repo_id, name);

    /* If case conflict, this file has been checked out to another path.
     * Remove the current entry, otherwise it won't be removed later
     * since it's timestamp is 0.
     */
    if (case_conflict) {
        ce->ce_flags |= CE_REMOVE;
        g_free (path);
        return FETCH_CHECKOUT_SUCCESS;
    }

update_cache:
    /* finally fill cache_entry info */
    /* Only update index if we checked out the file without any error
     * or conflicts. The timestamp of the entry will remain 0 if error
     * or conflicted.
     */
    seaf_stat (path, &st);
    fill_stat_cache_info (ce, &st);

    g_free (path);
    return FETCH_CHECKOUT_SUCCESS;
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

#ifndef __linux__
    path = build_case_conflict_free_path (worktree, name,
                                          conflict_hash, no_conflict_hash,
                                          &case_conflict,
                                          FALSE);
#else
    path = build_checkout_path (worktree, name, strlen(name));
#endif

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

static void
cleanup_file_blocks (const char *repo_id, int version, const char *file_id)
{
    Seafile *file;
    int i;

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                        repo_id, version,
                                        file_id);
    for (i = 0; i < file->n_blocks; ++i)
        seaf_block_manager_remove_block (seaf->block_mgr,
                                         repo_id, version,
                                         file->blk_sha1s[i]);

    seafile_unref (file);
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
                                               &expanded) < 0)
                goto error;
        }

        ptr = next;
    }

    expanded = g_list_reverse (expanded);
    *results = g_list_concat (*results, expanded);

    return 0;

error:
    for (ptr = expanded; ptr; ptr = ptr->next)
        diff_entry_free ((DiffEntry *)(ptr->data));
    return -1;
}

static int
do_rename_in_worktree (DiffEntry *de, const char *worktree,
                       GHashTable *conflict_hash, GHashTable *no_conflict_hash)
{
    char *old_path, *new_path;
    gboolean case_conflict;
    int ret = 0;

    old_path = g_build_filename (worktree, de->name, NULL);

    if (seaf_util_exists (old_path)) {
#ifndef __linux__
        new_path = build_case_conflict_free_path (worktree, de->new_name,
                                                  conflict_hash, no_conflict_hash,
                                                  &case_conflict,
                                                  TRUE);
#else
        new_path = build_checkout_path (worktree, de->new_name, strlen(de->new_name));
#endif

        if (seaf_util_rename (old_path, new_path) < 0) {
            seaf_warning ("Failed to rename %s to %s: %s.\n",
                          old_path, new_path, strerror(errno));
            ret = -1;
        }

        g_free (new_path);
    }

    g_free (old_path);
    return ret;
}

#ifdef WIN32

static void
delete_worktree_dir_recursive_win32 (const char *worktree,
                                     const wchar_t *path_w)
{
    WIN32_FIND_DATAW fdata;
    HANDLE handle;
    wchar_t *pattern;
    wchar_t *sub_path_w;
    char *path, *sub_path;
    int path_len_w;
    DWORD error;

    path = g_utf16_to_utf8 (path_w, -1, NULL, NULL, NULL);

    path_len_w = wcslen(path_w);

    pattern = g_new0 (wchar_t, (path_len_w + 3));
    wcscpy (pattern, path_w);
    wcscat (pattern, L"\\*");

    handle = FindFirstFileW (pattern, &fdata);
    if (handle == INVALID_HANDLE_VALUE) {
        seaf_warning ("FindFirstFile failed %s: %lu.\n",
                      path, GetLastError());
        g_free (path);
        g_free (pattern);
        return;
    }

    do {
        if (wcscmp (fdata.cFileName, L".") == 0 ||
            wcscmp (fdata.cFileName, L"..") == 0)
            continue;

        sub_path_w = g_new0 (wchar_t, path_len_w + wcslen(fdata.cFileName) + 2);
        wcscpy (sub_path_w, path_w);
        wcscat (sub_path_w, L"\\");
        wcscat (sub_path_w, fdata.cFileName);

        if (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            delete_worktree_dir_recursive_win32 (worktree, sub_path_w);
        } else {
            if (!DeleteFileW (sub_path_w)) {
                error = GetLastError();

                sub_path = g_utf16_to_utf8 (sub_path_w, -1,
                                            NULL, NULL, NULL);
                seaf_warning ("Failed to delete file %s: %lu.\n",
                              sub_path, error);

                g_free (sub_path);
            }
        }

        g_free (sub_path_w);
    } while (FindNextFileW (handle, &fdata) != 0);

    error = GetLastError();
    if (error != ERROR_NO_MORE_FILES) {
        seaf_warning ("FindNextFile failed %s: %lu.\n",
                      path, error);
    }

    FindClose (handle);

    int n = 0;
    while (!RemoveDirectoryW (path_w)) {
        error = GetLastError();
        seaf_warning ("Failed to remove dir %s: %lu.\n",
                      path, error);
        if (error != ERROR_DIR_NOT_EMPTY)
            break;
        if (++n >= 3)
            break;
        /* Sleep 100ms and retry. */
        g_usleep (100000);
        seaf_warning ("Retry remove dir %s.\n", path);
    }
    g_free (path);
    g_free (pattern);
}

#else

static void
delete_worktree_dir_recursive (const char *path)
{
    GDir *dir;
    const char *dname;
    GError *error = NULL;
    char *sub_path;
    SeafStat st;

    dir = g_dir_open (path, 0, &error);
    if (!dir) {
        seaf_warning ("Failed to open dir %s: %s.\n", path, error->message);
        return;
    }

    while ((dname = g_dir_read_name (dir)) != NULL) {
        sub_path = g_build_filename (path, dname, NULL);

        if (lstat (sub_path, &st) < 0) {
            seaf_warning ("Failed to stat %s.\n", sub_path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            delete_worktree_dir_recursive (sub_path);
        } else {
            /* Delete all other file types. */
            if (seaf_util_unlink (sub_path) < 0) {
                seaf_warning ("Failed to delete file %s: %s.\n",
                              sub_path, strerror(errno));
            }
        }

        g_free (sub_path);
    }

    g_dir_close (dir);

    if (g_rmdir (path) < 0) {
        seaf_warning ("Failed to delete dir %s: %s.\n", path, strerror(errno));
    }
}

#endif  /* WIN32 */

static void
delete_worktree_dir (const char *worktree, const char *path)
{
    char *full_path = g_build_path ("/", worktree, path, NULL);

#ifdef WIN32
    wchar_t *full_path_w = win32_long_path (full_path);
    delete_worktree_dir_recursive_win32 (worktree, full_path_w);
    g_free (full_path_w);
#else
    delete_worktree_dir_recursive(full_path);
#endif

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
                                          SYNC_STATUS_SYNCED);
}

#define UPDATE_CACHE_SIZE_LIMIT 100 * (1 << 20) /* 100MB */

int
seaf_repo_fetch_and_checkout (TransferTask *task,
                              HttpTxTask *http_task,
                              gboolean is_http,
                              const char *remote_head_id)
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

    if (is_http) {
        repo_id = http_task->repo_id;
        repo_version = http_task->repo_version;
        is_clone = http_task->is_clone;
        worktree = http_task->worktree;
        passwd = http_task->passwd;
    } else {
        repo_id = task->repo_id;
        repo_version = task->repo_version;
        is_clone = task->is_clone;
        worktree = task->worktree;
        passwd = task->passwd;
    }

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
                ret = FETCH_CHECKOUT_LOCKED;
                goto out;
            }
        } else if (de->status == DIFF_STATUS_RENAMED) {
            if (do_check_file_locked (de->name, worktree)) {
                seaf_message ("File %s is locked by other program, skip rename.\n",
                              de->name);
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

    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;
        if (de->status == DIFF_STATUS_ADDED || de->status == DIFF_STATUS_MODIFIED) {
            if (!is_http)
                ++(task->n_to_download);
            else
                ++(http_task->n_files);
        }
    }

#ifdef WIN32
    fset = seaf_repo_manager_get_locked_file_set (seaf->repo_mgr, repo_id);
#endif

    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;
        if (de->status == DIFF_STATUS_DELETED) {
            seaf_debug ("Delete file %s.\n", de->name);

            ce = index_name_exists (&istate, de->name, strlen(de->name), 0);
            if (!ce)
                continue;

            if (seaf_filelock_manager_is_file_locked (seaf->filelock_mgr,
                                                      repo_id, de->name))
                seaf_filelock_manager_unlock_wt_file (seaf->filelock_mgr,
                                                      repo_id, de->name);

#ifdef WIN32
            if (!do_check_file_locked (de->name, worktree)) {
                locked_file_set_remove (fset, de->name, FALSE);
                delete_path (worktree, de->name, de->mode, ce->ce_mtime.sec);
            } else {
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

            delete_worktree_dir (worktree, de->name);

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

    gint64 checkout_size = 0;
    int rc;
    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;

        if (de->status == DIFF_STATUS_ADDED ||
            de->status == DIFF_STATUS_MODIFIED) {
            seaf_debug ("Checkout file %s.\n", de->name);

            gboolean add_ce = FALSE;
            gboolean is_locked = FALSE;
            char file_id[41];

            rawdata_to_hex (de->sha1, file_id, 20);

            ce = index_name_exists (&istate, de->name, strlen(de->name), 0);
            if (!ce) {
                ce = cache_entry_from_diff_entry (de);
                add_ce = TRUE;
            }

            if (!should_ignore_on_checkout (de->name)) {
#ifdef WIN32
                is_locked = do_check_file_locked (de->name, worktree);
#endif

                if (!is_clone)
                    seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                          repo_id,
                                                          de->name,
                                                          de->mode,
                                                          SYNC_STATUS_SYNCING);

                rc = checkout_file (repo_id,
                                    repo_version,
                                    worktree,
                                    de->name,
                                    file_id,
                                    de->mtime,
                                    de->mode,
                                    crypt,
                                    ce,
                                    task,
                                    http_task,
                                    is_http,
                                    remote_head_id,
                                    conflict_hash,
                                    no_conflict_hash,
                                    is_locked);

                /* Even if the file failed to check out, still need to update index.
                 * But we have to stop after transfer errors.
                 */
                if (rc == FETCH_CHECKOUT_CANCELED) {
                    seaf_debug ("Transfer canceled.\n");
                    ret = FETCH_CHECKOUT_CANCELED;
                    if (add_ce)
                        cache_entry_free (ce);
                    if (!is_clone)
                        seaf_sync_manager_delete_active_path (seaf->sync_mgr,
                                                              repo_id,
                                                              de->name);
                    goto out;
                } else if (rc == FETCH_CHECKOUT_TRANSFER_ERROR) {
                    seaf_warning ("Transfer failed.\n");
                    ret = FETCH_CHECKOUT_TRANSFER_ERROR;
                    if (add_ce)
                        cache_entry_free (ce);
                    if (!is_clone)
                        seaf_sync_manager_delete_active_path (seaf->sync_mgr,
                                                              repo_id,
                                                              de->name);
                    goto out;
                }

                if (!is_locked) {
                    cleanup_file_blocks (repo_id, repo_version, file_id);
                    if (!is_clone) {
                        SyncStatus status;
                        if (rc == FETCH_CHECKOUT_FAILED)
                            status = SYNC_STATUS_ERROR;
                        else if (seaf_filelock_manager_is_file_locked(seaf->filelock_mgr,
                                                                      repo_id,
                                                                      de->name))
                            status = SYNC_STATUS_LOCKED;
                        else
                            status = SYNC_STATUS_SYNCED;
                        seaf_sync_manager_update_active_path (seaf->sync_mgr,
                                                              repo_id,
                                                              de->name,
                                                              de->mode,
                                                              status);
                    }
                } else {
#ifdef WIN32
                    locked_file_set_add_update (fset, de->name, LOCKED_OP_UPDATE,
                                                ce->ce_mtime.sec, file_id);
                    /* Stay in syncing status if the file is locked. */
#endif
                }
            }

            if (!is_http)
                ++(task->n_downloaded);
            else
                ++(http_task->done_files);

            if (add_ce) {
                if (!(ce->ce_flags & CE_REMOVE)) {
                    add_index_entry (&istate, ce,
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

            /* Save index file to disk after checking out some size of files.
             * This way we don't need to re-compare too many files if this
             * checkout is interrupted.
             */
            checkout_size += ce->ce_size;
            if (checkout_size >= UPDATE_CACHE_SIZE_LIMIT) {
                seaf_debug ("Save index file.\n");
                update_index (&istate, index_path);
                checkout_size = 0;
            }
        } else if (de->status == DIFF_STATUS_DIR_ADDED) {
            seaf_debug ("Checkout empty dir %s.\n", de->name);

            gboolean add_ce = FALSE;

            ce = index_name_exists (&istate, de->name, strlen(de->name), 0);
            if (!ce) {
                ce = cache_entry_from_diff_entry (de);
                add_ce = TRUE;
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
                                                  SYNC_STATUS_SYNCED);

            if (add_ce) {
                if (!(ce->ce_flags & CE_REMOVE)) {
                    add_index_entry (&istate, ce,
                                     (ADD_CACHE_OK_TO_ADD|ADD_CACHE_OK_TO_REPLACE));
                }
            } else
                ce->ce_mtime.sec = de->mtime;
        }
    }

    update_index (&istate, index_path);

out:
    discard_index (&istate);

    seaf_branch_unref (master);
    seaf_commit_unref (master_head);
    seaf_commit_unref (remote_head);

    for (ptr = results; ptr; ptr = ptr->next)
        diff_entry_free ((DiffEntry *)ptr->data);

    g_free (crypt);
    if (conflict_hash)
        g_hash_table_destroy (conflict_hash);
    if (no_conflict_hash)
        g_hash_table_destroy (no_conflict_hash);

    if (ignore_list)
        seaf_repo_free_ignore_files (ignore_list);

#ifdef WIN32
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

    if (repo->auto_sync) {
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

    if (repo->auto_sync) {
        if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree) < 0) {
            seaf_warning ("failed to watch repo %s.\n", repo->id);
        }
    }
}

static int 
compare_repo (const SeafRepo *srepo, const SeafRepo *trepo)
{
    return g_strcmp0 (srepo->id, trepo->id);
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
    /* for files like ~WRL0001.tmp */
    office_temp_ignore_patterns[1] = g_pattern_spec_new("~*.tmp");
    office_temp_ignore_patterns[2] = g_pattern_spec_new(".~lock*#");
    office_temp_ignore_patterns[3] = NULL;

    mgr->priv->repo_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    pthread_rwlock_init (&mgr->priv->lock, NULL);

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
        if (repo->auto_sync && !repo->worktree_invalid) {
            if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree) < 0) {
                seaf_warning ("failed to watch repo %s.\n", repo->id);
                /* If we fail to add watch at the beginning, sync manager
                 * will periodically check repo status and retry.
                 */
            }
        }
    }
}

int
seaf_repo_manager_start (SeafRepoManager *mgr)
{
    watch_repos (mgr);

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

#ifdef WIN32
    snprintf (sql, sizeof(sql), "DELETE FROM LockedFiles WHERE repo_id = '%s'",
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);
#endif

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

int
seaf_repo_manager_del_repo (SeafRepoManager *mgr,
                            SeafRepo *repo)
{
    seaf_repo_manager_remove_repo_ondisk (mgr, repo->id,
                                          (repo->version > 0) ? TRUE : FALSE);

    seaf_sync_manager_remove_active_path_info (seaf->sync_mgr, repo->id);

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

static gboolean
get_token (sqlite3_stmt *stmt, void *data)
{
    char **token = data;

    *token = g_strdup((char *)sqlite3_column_text (stmt, 0));
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_repo_lantoken (SeafRepoManager *manager,
                                     const char *repo_id)
{
    char sql[256];
    char *ret = NULL;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql),
              "SELECT token FROM RepoLanToken WHERE repo_id='%s'",
              repo_id);
    if (sqlite_foreach_selected_row (manager->priv->db, sql,
                                     get_token, &ret) < 0) {
        seaf_warning ("DB error when get token for repo %s.\n", repo_id);
        pthread_mutex_unlock (&manager->priv->db_lock);
        return NULL;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    return ret;
}

int
seaf_repo_manager_set_repo_lantoken (SeafRepoManager *manager,
                                     const char *repo_id,
                                     const char *token)
{
    char sql[256];
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), "REPLACE INTO RepoLanToken VALUES ('%s', '%s');",
              repo_id, token);
    if (sqlite_query_exec (db, sql) < 0) {
        pthread_mutex_unlock (&manager->priv->db_lock);
        return -1;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    return 0;
}

int
seaf_repo_manager_verify_repo_lantoken (SeafRepoManager *manager,
                                        const char *repo_id,
                                        const char *token)
{
    int ret = 0;
    if (!token)
        return 0;

    char *my_token = seaf_repo_manager_get_repo_lantoken (manager, repo_id);

    if (!my_token) {
        if (memcmp (DEFAULT_REPO_TOKEN, token, strlen(token)) == 0)
            ret = 1;
    } else {
        if (memcmp (my_token, token, strlen(token)) == 0)
            ret = 1;
        g_free (my_token);
    }

    return ret;
}

char *
seaf_repo_manager_generate_tmp_token (SeafRepoManager *manager,
                                      const char *repo_id,
                                      const char *peer_id)
{
    char sql[256];
    sqlite3 *db = manager->priv->db;

    int now = time(NULL);
    char *token = gen_uuid();
    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql),
              "REPLACE INTO RepoTmpToken VALUES ('%s', '%s', '%s', %d);",
              repo_id, peer_id, token, now);
    if (sqlite_query_exec (db, sql) < 0) {
        pthread_mutex_unlock (&manager->priv->db_lock);
        g_free (token);
        return NULL;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);
    return token;
}

int
seaf_repo_manager_verify_tmp_token (SeafRepoManager *manager,
                                    const char *repo_id,
                                    const char *peer_id,
                                    const char *token)
{
    int ret;
    char sql[512];
    if (!repo_id || !peer_id || !token)
        return 0;

    pthread_mutex_lock (&manager->priv->db_lock);
    snprintf (sql, 512, "SELECT timestamp FROM RepoTmpToken "
              "WHERE repo_id='%s' AND peer_id='%s' AND token='%s'",
              repo_id, peer_id, token);
    ret = sqlite_check_for_existence (manager->priv->db, sql);
    if (ret) {
        snprintf (sql, 512, "DELETE FROM RepoTmpToken WHERE "
                  "repo_id='%s' AND peer_id='%s'",
                  repo_id, peer_id);
        sqlite_query_exec (manager->priv->db, sql);
    }
    pthread_mutex_unlock (&manager->priv->db_lock);

    return ret;
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
    } else if (repo->enc_version == 2) {
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
    if (n < 0)
        return -1;

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

    repo->relay_id = load_repo_property (manager, repo->id, REPO_RELAY_ID);
    if (repo->relay_id && strlen(repo->relay_id) != 40) {
        g_free (repo->relay_id);
        repo->relay_id = NULL;
    }

    value = load_repo_property (manager, repo->id, REPO_NET_BROWSABLE);
    if (g_strcmp0(value, "true") == 0) {
        repo->net_browsable = 1;
    }
    g_free (value);

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

#ifdef WIN32
    sql = "CREATE TABLE IF NOT EXISTS LockedFiles (repo_id TEXT, path TEXT, "
        "operation TEXT, old_mtime INTEGER, file_id TEXT, new_path TEXT, "
        "PRIMARY KEY (repo_id, path));";
    sqlite_query_exec (db, sql);
#endif

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

inline static gboolean is_peer_relay (const char *peer_id)
{
    CcnetPeer *peer = ccnet_get_peer(seaf->ccnetrpc_client, peer_id);

    if (!peer)
        return FALSE;

    gboolean is_relay = string_list_is_exists(peer->role_list, "MyRelay");
    g_object_unref (peer);
    return is_relay;
}

int
seaf_repo_manager_set_repo_relay_id (SeafRepoManager *mgr,
                                     SeafRepo *repo,
                                     const char *relay_id)
{
    if (relay_id && strlen(relay_id) != 40)
        return -1;

    save_repo_property (mgr, repo->id, REPO_RELAY_ID, relay_id);

    g_free (repo->relay_id);

    if (relay_id)
        repo->relay_id = g_strdup (relay_id);
    else
        repo->relay_id = NULL;        
    return 0;
}

static char *
canonical_server_url (const char *url_in)
{
    char *url = g_strdup(url_in);
    int len = strlen(url);

    if (url[len - 1] == '/')
        url[len - 1] = 0;

    return url;
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
            seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id,
                                        repo->worktree);
            repo->last_sync_time = 0;
        } else {
            repo->auto_sync = 0;
            seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo->id);
            /* Cancel current sync task if any. */
            seaf_sync_manager_cancel_sync_task (seaf->sync_mgr, repo->id);
            seaf_sync_manager_remove_active_path_info (seaf->sync_mgr, repo->id);
        }
    }
    if (strcmp(key, REPO_NET_BROWSABLE) == 0) {
        if (g_strcmp0(value, "true") == 0)
            repo->net_browsable = 1;
        else
            repo->net_browsable = 0;
    }

    if (strcmp(key, REPO_RELAY_ID) == 0)
        return seaf_repo_manager_set_repo_relay_id (manager, repo, value);

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
    } else if (repo->enc_version == 2) {
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
                                      repo->enc_key, repo->enc_iv) < 0)
        return -1;

    pthread_mutex_lock (&manager->priv->db_lock);

    ret = save_repo_enc_info (manager, repo);

    pthread_mutex_unlock (&manager->priv->db_lock);

    return ret;
}

int
seaf_repo_manager_set_merge (SeafRepoManager *manager,
                             const char *repo_id,
                             const char *remote_head)
{
    char sql[256];

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), "REPLACE INTO MergeInfo VALUES ('%s', 1, '%s');",
              repo_id, remote_head);
    int ret = sqlite_query_exec (manager->priv->db, sql);

    pthread_mutex_unlock (&manager->priv->db_lock);
    return ret;
}

int
seaf_repo_manager_clear_merge (SeafRepoManager *manager,
                               const char *repo_id)
{
    char sql[256];

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), "UPDATE MergeInfo SET in_merge=0 WHERE repo_id='%s';",
              repo_id);
    int ret = sqlite_query_exec (manager->priv->db, sql);

    pthread_mutex_unlock (&manager->priv->db_lock);
    return ret;
}

static gboolean
get_merge_info (sqlite3_stmt *stmt, void *vinfo)
{
    SeafRepoMergeInfo *info = vinfo;
    int in_merge;

    in_merge = sqlite3_column_int (stmt, 1);
    if (in_merge == 0)
        info->in_merge = FALSE;
    else
        info->in_merge = TRUE;

    /* 
     * Note that compatibility, we store remote_head in the "branch" column.
     */
    const char *remote_head = (const char *) sqlite3_column_text (stmt, 2);
    memcpy (info->remote_head, remote_head, 40);

    return FALSE;
}

int
seaf_repo_manager_get_merge_info (SeafRepoManager *manager,
                                  const char *repo_id,
                                  SeafRepoMergeInfo *info)
{
    char sql[256];

    /* Default not in_merge, if no row is found in db. */
    info->in_merge = FALSE;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), "SELECT * FROM MergeInfo WHERE repo_id='%s';",
              repo_id);
    if (sqlite_foreach_selected_row (manager->priv->db, sql,
                                     get_merge_info, info) < 0) {
        pthread_mutex_unlock (&manager->priv->db_lock);
        return -1;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    return 0;
}

typedef struct {
    char common_ancestor[41];
    char head_id[41];
} CAInfo;

static gboolean
get_common_ancestor (sqlite3_stmt *stmt, void *vinfo)
{
    CAInfo *info = vinfo;

    const char *ancestor = (const char *) sqlite3_column_text (stmt, 0);
    const char *head_id = (const char *) sqlite3_column_text (stmt, 1);

    memcpy (info->common_ancestor, ancestor, 40);
    memcpy (info->head_id, head_id, 40);

    return FALSE;
}

int
seaf_repo_manager_get_common_ancestor (SeafRepoManager *manager,
                                       const char *repo_id,
                                       char *common_ancestor,
                                       char *head_id)
{
    char sql[256];
    CAInfo info;

    memset (&info, 0, sizeof(info));

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql),
              "SELECT ca_id, head_id FROM CommonAncestor WHERE repo_id='%s';",
              repo_id);
    if (sqlite_foreach_selected_row (manager->priv->db, sql,
                                     get_common_ancestor, &info) < 0) {
        pthread_mutex_unlock (&manager->priv->db_lock);
        return -1;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    memcpy (common_ancestor, info.common_ancestor, 41);
    memcpy (head_id, info.head_id, 41);

    return 0;
}

int
seaf_repo_manager_set_common_ancestor (SeafRepoManager *manager,
                                       const char *repo_id,
                                       const char *common_ancestor,
                                       const char *head_id)
{
    char sql[256];

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql),
              "REPLACE INTO CommonAncestor VALUES ('%s', '%s', '%s');",
              repo_id, common_ancestor, head_id);
    int ret = sqlite_query_exec (manager->priv->db, sql);

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

typedef struct {
    SeafRepo                *repo;
    CheckoutTask            *task;
    CheckoutDoneCallback     done_cb;
    void                    *cb_data;
} CheckoutData;

static void
checkout_job_done (void *vresult)
{
    if (!vresult)
        return;
    CheckoutData *cdata = vresult;
    SeafRepo *repo = cdata->repo;
    SeafBranch *local = NULL;

    if (!cdata->task->success)
        goto out;

    seaf_repo_manager_set_repo_worktree (repo->manager,
                                         repo,
                                         cdata->task->worktree);

    local = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "local");
    if (!local) {
        seaf_warning ("Cannot get branch local for repo %s(%.10s).\n",
                      repo->name, repo->id);
        return;
    }
    /* Set repo head to mark checkout done. */
    seaf_repo_set_head (repo, local);
    seaf_branch_unref (local);

    if (repo->auto_sync) {
        if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree) < 0) {
            seaf_warning ("failed to watch repo %s(%.10s).\n", repo->name, repo->id);
            return;
        }
    }

out:
    if (cdata->done_cb)
        cdata->done_cb (cdata->task, cdata->repo, cdata->cb_data);

    /* g_hash_table_remove (mgr->priv->checkout_tasks_hash, cdata->repo->id); */
}

static void *
checkout_repo_job (void *data)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    CheckoutData *cdata = data;
    SeafRepo *repo = cdata->repo;
    CheckoutTask *task;

    task = g_hash_table_lookup (mgr->priv->checkout_tasks_hash, repo->id);
    if (!task) {
        seaf_warning ("Failed to find checkout task for repo %.10s\n", repo->id);
        return NULL;
    }

    repo->worktree = g_strdup (task->worktree);

    char *error_msg = NULL;
    if (seaf_repo_checkout (repo, task->worktree, &error_msg) < 0) {
        seaf_warning ("Failed to checkout repo %.10s to %s : %s\n",
                      repo->id, task->worktree, error_msg);
        g_free (error_msg);
        task->success = FALSE;
        goto ret;
    }
    task->success = TRUE;

ret:
    return data;
}

int
seaf_repo_manager_add_checkout_task (SeafRepoManager *mgr,
                                     SeafRepo *repo,
                                     const char *worktree,
                                     CheckoutDoneCallback done_cb,
                                     void *cb_data)
{
    if (!repo || !worktree) {
        seaf_warning ("Invaid args\n");
        return -1;
    }

    CheckoutTask *task = g_new0 (CheckoutTask, 1);
    memcpy (task->repo_id, repo->id, 41);
    g_return_val_if_fail (strlen(worktree) < SEAF_PATH_MAX, -1);
    strcpy (task->worktree, worktree);

    g_hash_table_insert (mgr->priv->checkout_tasks_hash,
                         g_strdup(repo->id), task);

    CheckoutData *cdata = g_new0 (CheckoutData, 1);
    cdata->repo = repo;
    cdata->task = task;
    cdata->done_cb = done_cb;
    cdata->cb_data = cb_data;
    ccnet_job_manager_schedule_job(seaf->job_mgr,
                                   (JobThreadFunc)checkout_repo_job,
                                   (JobDoneCallback)checkout_job_done,
                                   cdata);
    return 0;
}

CheckoutTask *
seaf_repo_manager_get_checkout_task (SeafRepoManager *mgr,
                                     const char *repo_id)
{
    if (!repo_id || strlen(repo_id) != 36) {
        seaf_warning ("Invalid args\n");
        return NULL;
    }

    return g_hash_table_lookup(mgr->priv->checkout_tasks_hash, repo_id);
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

int
seaf_repo_manager_update_repo_relay_info (SeafRepoManager *mgr,
                                          SeafRepo *repo,
                                          const char *new_addr,
                                          const char *new_port)
{
    GList *ptr, *repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, 0, -1);
    SeafRepo *r;
    for (ptr = repos; ptr; ptr = ptr->next) {
        r = ptr->data;
        if (g_strcmp0(r->relay_id, repo->relay_id) != 0)
            continue;

        char *relay_addr = NULL;
        char *relay_port = NULL;
        seaf_repo_manager_get_repo_relay_info (seaf->repo_mgr, r->id,
                                               &relay_addr, &relay_port);
        if (g_strcmp0(relay_addr, new_addr) != 0 ||
            g_strcmp0(relay_port, new_port) != 0) {
            seaf_repo_manager_set_repo_relay_info (seaf->repo_mgr, r->id,
                                                   new_addr, new_port);
        }

        g_free (relay_addr);
        g_free (relay_port);
    }

    g_list_free (repos);

    return 0;
}

int
seaf_repo_manager_update_repos_server_host (SeafRepoManager *mgr,
                                            const char *old_host,
                                            const char *new_host,
                                            const char *new_server_url)
{
    GList *ptr, *repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, 0, -1);
    SeafRepo *r;
    for (ptr = repos; ptr; ptr = ptr->next) {
        r = ptr->data;
                
        char *relay_addr = NULL;
        char *relay_port = NULL;
        seaf_repo_manager_get_repo_relay_info (seaf->repo_mgr, r->id, 
                                               &relay_addr, &relay_port);
        if (g_strcmp0(relay_addr, old_host) == 0) {
            seaf_repo_manager_set_repo_relay_info (seaf->repo_mgr, r->id,
                                                   new_host, relay_port);
            seaf_repo_manager_set_repo_property (
                seaf->repo_mgr, r->id, REPO_PROP_SERVER_URL, new_server_url);
        }

        g_free (relay_addr);
        g_free (relay_port);
    }

    g_list_free (repos);

    return 0;
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
    char path[PATH_MAX];

    full_path = g_build_path (PATH_SEPERATOR, worktree,
                              IGNORE_FILE, NULL);
    if (seaf_stat (full_path, &st) < 0)
        goto error;
    if (!S_ISREG(st.st_mode))
        goto error;
    fp = g_fopen(full_path, "r");
    if (fp == NULL)
        goto error;

    while (fgets(path, PATH_MAX, fp) != NULL) {
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

    /* first check the path is a reg file or a dir */
    if (seaf_stat(str, &st) < 0) {
        g_free(str);
        return FALSE;
    }
    if (S_ISDIR(st.st_mode)) {
        g_free(str);
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
