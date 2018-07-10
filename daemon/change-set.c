/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"

#include "utils.h"
#include "log.h"

#include "index/index.h"

#include "diff-simple.h"
#include "change-set.h"

struct _ChangeSetDir {
    int version;
    char dir_id[41];
    /* A hash table of dirents for fast lookup and insertion. */
    GHashTable *dents;
#if defined WIN32 || defined __APPLE__
    /* Case-insensitive hash table. */
    GHashTable *dents_i;
#endif

};
typedef struct _ChangeSetDir ChangeSetDir;

struct _ChangeSetDirent {
    guint32 mode;
    char id[41];
    char *name;
    gint64 mtime;
    char *modifier;
    gint64 size;
    /* Only used for directory. Most of time this is NULL
     * unless we change the subdir too.
     */
    ChangeSetDir *subdir;
};
typedef struct _ChangeSetDirent ChangeSetDirent;

/* Change set dirent. */

static ChangeSetDirent *
changeset_dirent_new (const char *id, guint32 mode, const char *name,
                      gint64 mtime, const char *modifier, gint64 size)
{
    ChangeSetDirent *dent = g_new0 (ChangeSetDirent, 1);

    dent->mode = mode;
    memcpy (dent->id, id, 40);
    dent->name = g_strdup(name);
    dent->mtime = mtime;
    dent->modifier = g_strdup(modifier);
    dent->size = size;

    return dent;    
}

static ChangeSetDirent *
seaf_dirent_to_changeset_dirent (SeafDirent *seaf_dent)
{
    return changeset_dirent_new (seaf_dent->id, seaf_dent->mode, seaf_dent->name,
                                 seaf_dent->mtime, seaf_dent->modifier, seaf_dent->size);
}

static SeafDirent *
changeset_dirent_to_seaf_dirent (int version, ChangeSetDirent *dent)
{
    return seaf_dirent_new (version, dent->id, dent->mode, dent->name,
                            dent->mtime, dent->modifier, dent->size);
}

static void
changeset_dir_free (ChangeSetDir *dir);

static void
changeset_dirent_free (ChangeSetDirent *dent)
{
    if (!dent)
        return;

    g_free (dent->name);
    g_free (dent->modifier);
    /* Recursively free subdir. */
    if (dent->subdir)
        changeset_dir_free (dent->subdir);
    g_free (dent);
}

/* Change set dir. */

static void
add_dent_to_dir (ChangeSetDir *dir, ChangeSetDirent *dent)
{
    g_hash_table_insert (dir->dents,
                         g_strdup(dent->name),
                         dent);
#if defined WIN32 || defined __APPLE__
    g_hash_table_insert (dir->dents_i,
                         g_utf8_strdown(dent->name, -1),
                         dent);
#endif
}

static void
remove_dent_from_dir (ChangeSetDir *dir, const char *dname)
{
    char *key;

    if (g_hash_table_lookup_extended (dir->dents, dname,
                                      (gpointer*)&key, NULL)) {
        g_hash_table_steal (dir->dents, dname);
        g_free (key);
    }
#if defined WIN32 || defined __APPLE__
    char *dname_i = g_utf8_strdown (dname, -1);
    g_hash_table_remove (dir->dents_i, dname_i);
    g_free (dname_i);
#endif
}

static ChangeSetDir *
changeset_dir_new (int version, const char *id, GList *dirents)
{
    ChangeSetDir *dir = g_new0 (ChangeSetDir, 1);
    GList *ptr;
    SeafDirent *dent;
    ChangeSetDirent *changeset_dent;

    dir->version = version;
    if (id)
        memcpy (dir->dir_id, id, 40);
    dir->dents = g_hash_table_new_full (g_str_hash, g_str_equal,
                                        g_free, (GDestroyNotify)changeset_dirent_free);
#if defined WIN32 || defined __APPLE__
    dir->dents_i = g_hash_table_new_full (g_str_hash, g_str_equal,
                                          g_free, NULL);
#endif
    for (ptr = dirents; ptr; ptr = ptr->next) {
        dent = ptr->data;
        changeset_dent = seaf_dirent_to_changeset_dirent(dent);
        add_dent_to_dir (dir, changeset_dent);
    }

    return dir;
} 

static void
changeset_dir_free (ChangeSetDir *dir)
{
    if (!dir)
        return;
    g_hash_table_destroy (dir->dents);
#if defined WIN32 || defined __APPLE__
    g_hash_table_destroy (dir->dents_i);
#endif
    g_free (dir);
}

static ChangeSetDir *
seaf_dir_to_changeset_dir (SeafDir *seaf_dir)
{
    return changeset_dir_new (seaf_dir->version, seaf_dir->dir_id, seaf_dir->entries);
}

static gint
compare_dents (gconstpointer a, gconstpointer b)
{
    const SeafDirent *denta = a, *dentb = b;

    return strcmp(dentb->name, denta->name);
}

static SeafDir *
changeset_dir_to_seaf_dir (ChangeSetDir *dir)
{
    GList *dents = NULL, *seaf_dents = NULL;
    GList *ptr;
    ChangeSetDirent *dent;
    SeafDirent *seaf_dent;
    SeafDir *seaf_dir;

    dents = g_hash_table_get_values (dir->dents);
    for (ptr = dents; ptr; ptr = ptr->next) {
        dent = ptr->data;
        seaf_dent = changeset_dirent_to_seaf_dirent (dir->version, dent);
        seaf_dents = g_list_prepend (seaf_dents, seaf_dent);
    }
    /* Sort it in descending order. */
    seaf_dents = g_list_sort (seaf_dents, compare_dents);

    /* seaf_dir_new() computes the dir id. */
    seaf_dir = seaf_dir_new (NULL, seaf_dents, dir->version);

    g_list_free (dents);
    return seaf_dir;
}

/* Change set. */

#define CASE_CONFLICT_PATTERN " \\(case conflict \\d+\\)"

ChangeSet *
changeset_new (const char *repo_id)
{
    SeafRepo *repo;
    SeafCommit *commit = NULL;
    SeafDir *seaf_dir = NULL;
    ChangeSetDir *changeset_dir = NULL;
    ChangeSet *changeset = NULL;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to find repo %s.\n", repo_id);
        return NULL;
    }

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo_id,
                                             repo->version,
                                             repo->head->commit_id);
    if (!commit) {
        seaf_warning ("Failed to find head commit %s for repo %s.\n",
                      repo->head->commit_id, repo_id);
        return NULL;
    }

    seaf_dir = seaf_fs_manager_get_seafdir_sorted (seaf->fs_mgr,
                                                   repo_id,
                                                   repo->version,
                                                   commit->root_id);
    if (!seaf_dir) {
        seaf_warning ("Failed to find root dir %s in repo %s\n",
                      repo->root_id, repo_id);
        goto out;
    }

    changeset_dir = seaf_dir_to_changeset_dir (seaf_dir);
    if (!changeset_dir)
        goto out;

    GError *error = NULL;
    GRegex *case_conflict_pattern = g_regex_new(CASE_CONFLICT_PATTERN,
                                                0, 0, &error);
    if (error) {
        seaf_warning ("Failed to create regex '%s': %s\n",
                      CASE_CONFLICT_PATTERN, error->message);
        goto out;
    }

    changeset = g_new0 (ChangeSet, 1);
    memcpy (changeset->repo_id, repo_id, 36);
    changeset->tree_root = changeset_dir;
    changeset->case_conflict_pattern = case_conflict_pattern;

out:
    seaf_commit_unref (commit);
    seaf_dir_free (seaf_dir);
    return changeset;
}

void
changeset_free (ChangeSet *changeset)
{
    if (!changeset)
        return;

    changeset_dir_free (changeset->tree_root);
    g_regex_unref (changeset->case_conflict_pattern);
    g_free (changeset);
}

static void
update_file (ChangeSetDirent *dent,
             unsigned char *sha1,
             SeafStat *st,
             const char *modifier)
{
    if (!sha1 || !st || !S_ISREG(st->st_mode))
        return;
    dent->mode = create_ce_mode(st->st_mode);
    dent->mtime = (gint64)st->st_mtime;
    dent->size = (gint64)st->st_size;
    rawdata_to_hex (sha1, dent->id, 20);

    g_free (dent->modifier);
    dent->modifier = g_strdup(modifier);
}

static void
create_new_dent (ChangeSetDir *dir,
                 const char *dname,
                 unsigned char *sha1,
                 SeafStat *st,
                 const char *modifier,
                 ChangeSetDirent *in_new_dent)
{
    if (in_new_dent) {
        g_free (in_new_dent->name);
        in_new_dent->name = g_strdup(dname);
        add_dent_to_dir (dir, in_new_dent);
        return;
    }

    char id[41];
    rawdata_to_hex (sha1, id, 20);
    ChangeSetDirent *new_dent;
    new_dent = changeset_dirent_new (id, create_ce_mode(st->st_mode), dname,
                                     st->st_mtime, modifier, st->st_size);

    add_dent_to_dir (dir, new_dent);
}

static ChangeSetDir *
create_intermediate_dir (ChangeSetDir *parent, const char *dname)
{
    ChangeSetDirent *dent;

    dent = changeset_dirent_new (EMPTY_SHA1, S_IFDIR, dname, 0, NULL, 0);
    dent->subdir = changeset_dir_new (parent->version, EMPTY_SHA1, NULL);
    add_dent_to_dir (parent, dent);

    return dent->subdir;
}

#if defined WIN32 || defined __APPLE__
static void
handle_case_conflict (ChangeSet *changeset,
                      ChangeSetDir *dir,
                      const char *dname)
{
    char *conflict_dname;
    ChangeSetDirent *dent;
    GError *error = NULL;

    if (g_regex_match (changeset->case_conflict_pattern,
                       dname, 0, NULL)) {
        conflict_dname = g_regex_replace_literal (changeset->case_conflict_pattern,
                                                  dname, -1, 0, "", 0, &error);
        if (!conflict_dname) {
            seaf_warning ("Failed to replace regex for %s: %s\n",
                          dname, error->message);
            return;
        }

        dent = g_hash_table_lookup (dir->dents, conflict_dname);
        if (dent) {
            remove_dent_from_dir (dir, conflict_dname);
            changeset_dirent_free (dent);
        }
        g_free (conflict_dname);
    }
}
#endif

static void
add_to_tree (ChangeSet *changeset,
             unsigned char *sha1,
             SeafStat *st,
             const char *modifier,
             const char *path,
             ChangeSetDirent *new_dent)
{
    char *repo_id = changeset->repo_id;
    ChangeSetDir *root = changeset->tree_root;
    char **parts, *dname;
    int n, i;
    ChangeSetDir *dir;
    ChangeSetDirent *dent;
    SeafDir *seaf_dir;

    parts = g_strsplit (path, "/", 0);
    n = g_strv_length(parts);
    dir = root;
    for (i = 0; i < n; i++) {
#if defined WIN32 || defined __APPLE__
    try_again:
#endif
        dname = parts[i];
        dent = g_hash_table_lookup (dir->dents, dname);

        if (dent) {
            if (S_ISDIR(dent->mode)) {
                if (i == (n-1))
                    /* Don't need to update empty dir */
                    break;

                if (!dent->subdir) {
                    seaf_dir = seaf_fs_manager_get_seafdir(seaf->fs_mgr,
                                                           repo_id,
                                                           root->version,
                                                           dent->id);
                    if (!seaf_dir) {
                        seaf_warning ("Failed to load seafdir %s:%s\n",
                                      repo_id, dent->id);
                        break;
                    }
                    dent->subdir = seaf_dir_to_changeset_dir (seaf_dir);
                    seaf_dir_free (seaf_dir);
                }
                dir = dent->subdir;
            } else if (S_ISREG(dent->mode)) {
                if (i == (n-1)) {
                    /* File exists, update it. */
                    update_file (dent, sha1, st, modifier);
                    break;
                }
            }
        } else {
#if defined WIN32 || defined __APPLE__
            /* Only effective for add operation, not applicable to rename. */
            if (!new_dent) {
                char *search_key = g_utf8_strdown (dname, -1);
                dent = g_hash_table_lookup (dir->dents_i, search_key);
                g_free (search_key);
                if (dent) {
                    remove_dent_from_dir (dir, dent->name);

                    g_free (dent->name);
                    dent->name = g_strdup(dname);
                    add_dent_to_dir (dir, dent);

                    goto try_again;
                }

                handle_case_conflict (changeset, dir, dname);
            }
#endif

            if (i == (n-1)) {
                create_new_dent (dir, dname, sha1, st, modifier, new_dent);
            } else {
                dir = create_intermediate_dir (dir, dname);
            }
        }
    }

    g_strfreev (parts);
}

static ChangeSetDirent *
delete_from_tree (ChangeSet *changeset,
                  const char *path,
                  gboolean *parent_empty)
{
    char *repo_id = changeset->repo_id;
    ChangeSetDir *root = changeset->tree_root;
    char **parts, *dname;
    int n, i;
    ChangeSetDir *dir;
    ChangeSetDirent *dent, *ret = NULL;
    SeafDir *seaf_dir;

    *parent_empty = FALSE;

    parts = g_strsplit (path, "/", 0);
    n = g_strv_length(parts);
    dir = root;
    for (i = 0; i < n; i++) {
        dname = parts[i];

        dent = g_hash_table_lookup (dir->dents, dname);
        if (!dent)
            break;

        if (S_ISDIR(dent->mode)) {
            if (i == (n-1)) {
                /* Remove from hash table without freeing dent. */
                remove_dent_from_dir (dir, dname);
                if (g_hash_table_size (dir->dents) == 0)
                    *parent_empty = TRUE;
                ret = dent;
                break;
            }

            if (!dent->subdir) {
                seaf_dir = seaf_fs_manager_get_seafdir(seaf->fs_mgr,
                                                       repo_id,
                                                       root->version,
                                                       dent->id);
                if (!seaf_dir) {
                    seaf_warning ("Failed to load seafdir %s:%s\n",
                                  repo_id, dent->id);
                    break;
                }
                dent->subdir = seaf_dir_to_changeset_dir (seaf_dir);
                seaf_dir_free (seaf_dir);
            }
            dir = dent->subdir;
        } else if (S_ISREG(dent->mode)) {
            if (i == (n-1)) {
                /* Remove from hash table without freeing dent. */
                remove_dent_from_dir (dir, dname);
                if (g_hash_table_size (dir->dents) == 0)
                    *parent_empty = TRUE;
                ret = dent;
                break;
            }
        }
    }

    g_strfreev (parts);
    return ret;
}

static void
apply_to_tree (ChangeSet *changeset,
               char status,
               unsigned char *sha1,
               SeafStat *st,
               const char *modifier,
               const char *path,
               const char *new_path)
{
    ChangeSetDirent *dent, *dent_dst;
    gboolean dummy;

    switch (status) {
    case DIFF_STATUS_ADDED:
    case DIFF_STATUS_MODIFIED:
    case DIFF_STATUS_DIR_ADDED:
        add_to_tree (changeset, sha1, st, modifier, path, NULL);
        break;
    case DIFF_STATUS_RENAMED:
        dent = delete_from_tree (changeset, path, &dummy);
        if (!dent)
            break;

        dent_dst = delete_from_tree (changeset, new_path, &dummy);
        changeset_dirent_free (dent_dst);
        add_to_tree (changeset, NULL, NULL, NULL, new_path, dent);

        break;
    }
}

void
add_to_changeset (ChangeSet *changeset,
                  char status,
                  unsigned char *sha1,
                  SeafStat *st,
                  const char *modifier,
                  const char *path,
                  const char *new_path)
{
    apply_to_tree (changeset,
                   status, sha1, st, modifier, path, new_path);
}

static void
remove_from_changeset_recursive (ChangeSet *changeset,
                                 const char *path,
                                 gboolean remove_parent,
                                 const char *top_dir)
{
    ChangeSetDirent *dent;
    gboolean parent_empty = FALSE;

    dent = delete_from_tree (changeset, path, &parent_empty);
    changeset_dirent_free (dent);

    if (remove_parent && parent_empty) {
        char *parent = g_strdup(path);
        char *slash = strrchr (parent, '/');
        if (slash) {
            *slash = '\0';
            if (strlen(parent) >= strlen(top_dir)) {
                /* Recursively remove parent dirs. */
                remove_from_changeset_recursive (changeset,
                                                 parent,
                                                 remove_parent,
                                                 top_dir);
            }
        }
        g_free (parent);
    }
}

void
remove_from_changeset (ChangeSet *changeset,
                       char status,
                       const char *path,
                       gboolean remove_parent,
                       const char *top_dir)
{
    remove_from_changeset_recursive (changeset, path, remove_parent, top_dir);
}

static char *
commit_tree_recursive (const char *repo_id, ChangeSetDir *dir, gint64 *new_mtime)
{
    ChangeSetDirent *dent;
    GHashTableIter iter;
    gpointer key, value;
    char *new_id;
    gint64 subdir_new_mtime;
    gint64 dir_mtime = 0;
    SeafDir *seaf_dir;
    char *ret = NULL;

    g_hash_table_iter_init (&iter, dir->dents);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        dent = value;
        if (dent->subdir) {
            new_id = commit_tree_recursive (repo_id, dent->subdir, &subdir_new_mtime);
            if (!new_id)
                return NULL;

            memcpy (dent->id, new_id, 40);
            dent->mtime = subdir_new_mtime;
            g_free (new_id);
        }
        if (dir_mtime < dent->mtime)
            dir_mtime = dent->mtime;
    }

    seaf_dir = changeset_dir_to_seaf_dir (dir);

    memcpy (dir->dir_id, seaf_dir->dir_id, 40);

    if (!seaf_fs_manager_object_exists (seaf->fs_mgr,
                                        repo_id, dir->version,
                                        seaf_dir->dir_id)) {
        if (seaf_dir_save (seaf->fs_mgr, repo_id, dir->version, seaf_dir) < 0) {
            seaf_warning ("Failed to save dir object %s to repo %s.\n",
                          seaf_dir->dir_id, repo_id);
            goto out;
        }
    }

    ret = g_strdup(seaf_dir->dir_id);

out:
    if (ret != NULL)
        *new_mtime = dir_mtime;

    seaf_dir_free (seaf_dir);
    return ret;
}

/*
 * This function does two things:
 * - calculate dir id from bottom up;
 * - create and save seaf dir objects.
 * It returns root dir id of the new commit.
 */
char *
commit_tree_from_changeset (ChangeSet *changeset)
{
    gint64 mtime;
    char *root_id = commit_tree_recursive (changeset->repo_id,
                                           changeset->tree_root,
                                           &mtime);

    return root_id;
}

gboolean
changeset_check_path (ChangeSet *changeset,
                      const char *path,
                      unsigned char *sha1,
                      guint32 mode,
                      gint64 mtime)
{
    ChangeSetDir *root = changeset->tree_root;
    char **parts, *dname;
    int n, i;
    ChangeSetDir *dir;
    ChangeSetDirent *dent;
    gboolean ret = FALSE;
    char id[41];

    rawdata_to_hex (sha1, id, 20);

    parts = g_strsplit (path, "/", 0);
    n = g_strv_length(parts);
    dir = root;
    for (i = 0; i < n; i++) {
        dname = parts[i];

        dent = g_hash_table_lookup (dir->dents, dname);
        if (!dent) {
            seaf_message ("Changeset mismatch: path component %s of %s not found\n",
                          dname, path);
            break;
        }

        if (S_ISDIR(dent->mode)) {
            if (i == (n-1)) {
                if (dent->mode != mode) {
                    seaf_message ("Changeset mismatch: %s is not a dir\n", path);
                    break;
                } else if (strcmp (dent->id, EMPTY_SHA1) != 0) {
                    seaf_message ("Changeset mismatch: %s is not a empty dir\n", path);
                    break;
                }
                ret = TRUE;
                break;
            }

            if (!dent->subdir) {
                seaf_message ("Changeset mismatch: path component %s of %s is not in changeset\n",
                              dname, path);
                break;
            }
            dir = dent->subdir;
        } else if (S_ISREG(dent->mode)) {
            if (i == (n-1)) {
                if (dent->mode != mode) {
                    seaf_message ("Changeset mismatch: %s mode mismatch, "
                                  "index: %u, changeset: %u\n",
                                  path, mode, dent->mode);
                    break;
                } else if (dent->mtime != mtime) {
                    seaf_message ("Changeset mismatch: %s mtime mismatch, "
                                  "index: %"G_GINT64_FORMAT
                                  ", changeset: %"G_GINT64_FORMAT"\n",
                                  path, mtime, dent->mtime);
                    break;
                } else if (strcmp (dent->id, id) != 0) {
                    seaf_message ("Changeset mismatch: %s id mismatch, "
                                  "index: %s, changeset: %s\n",
                                  path, id, dent->id);
                    break;
                }
                ret = TRUE;
                break;
            }

            /* We find a file in the middle of the path, this is invalid. */
            seaf_message ("Changeset mismatch: path component %s of %s is a file\n",
                          dname, path);
            break;
        }
    }

    g_strfreev (parts);
    return ret;
}
