#include "common.h"

#include "seafile-session.h"

#include "sync-status-tree.h"

#include "log.h"

struct _SyncStatusDir {
    GHashTable *dirents;        /* name -> dirent. */
};
typedef struct _SyncStatusDir SyncStatusDir;

struct _SyncStatusDirent {
    char *name;
    int mode;
    /* Only used for directories. */
    SyncStatusDir *subdir;
};
typedef struct _SyncStatusDirent SyncStatusDirent;

struct SyncStatusTree {
    SyncStatusDir *root;
    char *worktree;
};
typedef struct SyncStatusTree SyncStatusTree;

static void
sync_status_dirent_free (SyncStatusDirent *dirent);

static SyncStatusDir *
sync_status_dir_new ()
{
    SyncStatusDir *dir = g_new0 (SyncStatusDir, 1);
    dir->dirents = g_hash_table_new_full (g_str_hash, g_str_equal,
                                          g_free,
                                          (GDestroyNotify)sync_status_dirent_free);
    return dir;
}

static void
sync_status_dir_free (SyncStatusDir *dir)
{
    if (!dir)
        return;
    g_hash_table_destroy (dir->dirents);
    g_free (dir);
}

static SyncStatusDirent *
sync_status_dirent_new (const char *name, int mode)
{
    SyncStatusDirent *dirent = g_new0(SyncStatusDirent, 1);
    dirent->name = g_strdup(name);
    dirent->mode = mode;

    if (S_ISDIR(mode))
        dirent->subdir = sync_status_dir_new ();

    return dirent;
}

static void
sync_status_dirent_free (SyncStatusDirent *dirent)
{
    if (!dirent)
        return;
    g_free (dirent->name);
    sync_status_dir_free (dirent->subdir);
    g_free (dirent);
}

SyncStatusTree *
sync_status_tree_new (const char *worktree)
{
    SyncStatusTree *tree = g_new0(SyncStatusTree, 1);
    tree->root = sync_status_dir_new ();
    tree->worktree = g_strdup(worktree);
    return tree;
}

#if 0
#ifdef WIN32
static void
refresh_recursive (const char *basedir, SyncStatusDir *dir)
{
    GHashTableIter iter;
    gpointer key, value;
    char *dname, *path;
    SyncStatusDirent *dirent;

    g_hash_table_iter_init (&iter, dir->dirents);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        dname = key;
        dirent = value;

        path = g_strconcat(basedir, "/", dname, NULL);
        seaf_sync_manager_add_refresh_path (seaf->sync_mgr, path);

        if (S_ISDIR(dirent->mode))
            refresh_recursive (path, dirent->subdir);

        g_free (path);
    }
}
#endif
#endif	/* 0 */

void
sync_status_tree_free (struct SyncStatusTree *tree)
{
    if (!tree)
        return;

#ifdef WIN32
    /* refresh_recursive (tree->worktree, tree->root); */
#endif
    /* Free the tree recursively. */
    sync_status_dir_free (tree->root);

    g_free (tree->worktree);
    g_free (tree);
}

void
sync_status_tree_add (SyncStatusTree *tree,
                      const char *path,
                      int mode,
                      gboolean refresh)
{
    char **dnames = NULL;
    guint n, i;
    char *dname;
    SyncStatusDir *dir = tree->root;
    SyncStatusDirent *dirent;
    GString *buf;

    dnames = g_strsplit (path, "/", 0);
    if (!dnames)
        return;
    n = g_strv_length (dnames);

    buf = g_string_new ("");
    g_string_append (buf, tree->worktree);

    for (i = 0; i < n; i++) {
        dname = dnames[i];
        dirent = g_hash_table_lookup (dir->dirents, dname);
        g_string_append (buf, "/");
        g_string_append (buf, dname);
        if (dirent) {
            if (S_ISDIR(dirent->mode)) {
                if (i == (n-1)) {
                    goto out;
                } else {
                    dir = dirent->subdir;
                }
            } else {
                goto out;
            }
        } else {
            if (i == (n-1)) {
                dirent = sync_status_dirent_new (dname, mode);
                g_hash_table_insert (dir->dirents, g_strdup(dname), dirent);
            } else {
                dirent = sync_status_dirent_new (dname, S_IFDIR);
                g_hash_table_insert (dir->dirents, g_strdup(dname), dirent);
                dir = dirent->subdir;
            }
#ifdef WIN32
            if (refresh)
                seaf_sync_manager_add_refresh_path (seaf->sync_mgr, buf->str);
#endif
        }
    }

out:
    g_string_free (buf, TRUE);
    g_strfreev (dnames);
}

inline static gboolean
is_empty_dir (SyncStatusDirent *dirent)
{
    return (g_hash_table_size(dirent->subdir->dirents) == 0);
}

static void
remove_item (SyncStatusDir *dir, const char *dname, const char *fullpath)
{
    g_hash_table_remove (dir->dirents, dname);
}

static void
delete_recursive (SyncStatusDir *dir, char **dnames, guint n, guint i,
                  const char *base)
{
    char *dname;
    SyncStatusDirent *dirent;
    char *fullpath = NULL;

    dname = dnames[i];
    fullpath = g_strconcat (base, "/", dname, NULL);

    dirent = g_hash_table_lookup (dir->dirents, dname);
    if (dirent) {
        if (S_ISDIR(dirent->mode)) {
            if (i == (n-1)) {
                if (is_empty_dir(dirent))
                    remove_item (dir, dname, fullpath);
            } else {
                delete_recursive (dirent->subdir, dnames, n, ++i, fullpath);
                /* If this dir becomes empty after deleting the entry below,
                 * remove the dir itself too.
                 */
                if (is_empty_dir(dirent))
                    remove_item (dir, dname, fullpath);
            }
        } else if (i == (n-1)) {
            remove_item (dir, dname, fullpath);
        }
    }

    g_free (fullpath);
}

void
sync_status_tree_del (SyncStatusTree *tree,
                      const char *path)
{
    char **dnames = NULL;
    guint n;
    SyncStatusDir *dir = tree->root;

    dnames = g_strsplit (path, "/", 0);
    if (!dnames)
        return;
    n = g_strv_length (dnames);

    delete_recursive (dir, dnames, n, 0, tree->worktree);

    g_strfreev (dnames);
}

int
sync_status_tree_exists (SyncStatusTree *tree,
                         const char *path)
{
    char **dnames = NULL;
    guint n, i;
    char *dname;
    SyncStatusDir *dir = tree->root;
    SyncStatusDirent *dirent;
    int ret = 0;

    dnames = g_strsplit (path, "/", 0);
    if (!dnames)
        return ret;
    n = g_strv_length (dnames);

    for (i = 0; i < n; i++) {
        dname = dnames[i];
        dirent = g_hash_table_lookup (dir->dirents, dname);
        if (dirent) {
            if (S_ISDIR(dirent->mode)) {
                if (i == (n-1)) {
                    ret = 1;
                    goto out;
                } else {
                    dir = dirent->subdir;
                }
            } else {
                if (i == (n-1)) {
                    ret = 1;
                    goto out;
                } else {
                    goto out;
                }
            }
        } else {
            goto out;
        }
    }

out:
    g_strfreev (dnames);
    return ret;
}
