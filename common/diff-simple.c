#include "common.h"
#include "diff-simple.h"
#include "utils.h"
#include "log.h"

#ifndef SEAFILE_SERVER
#include "unpack-trees.h"
#endif

DiffEntry *
diff_entry_new (char type, char status, unsigned char *sha1, const char *name)
{
    DiffEntry *de = g_new0 (DiffEntry, 1);

    de->type = type;
    de->status = status;
    memcpy (de->sha1, sha1, 20);
    de->name = g_strdup(name);

    return de;
}

DiffEntry *
diff_entry_new_from_dirent (char type, char status,
                            SeafDirent *dent, const char *basedir)
{
    DiffEntry *de = g_new0 (DiffEntry, 1);
    unsigned char sha1[20];
    char *path;

    hex_to_rawdata (dent->id, sha1, 20);
    path = g_strconcat (basedir, dent->name, NULL);

    de->type = type;
    de->status = status;
    memcpy (de->sha1, sha1, 20);
    de->name = path;

#ifdef SEAFILE_CLIENT
    if (type == DIFF_TYPE_COMMITS &&
        (status == DIFF_STATUS_ADDED ||
         status == DIFF_STATUS_MODIFIED ||
         status == DIFF_STATUS_DIR_ADDED ||
         status == DIFF_STATUS_DIR_DELETED)) {
        de->mtime = dent->mtime;
        de->mode = dent->mode;
        de->modifier = g_strdup(dent->modifier);
        de->size = dent->size;
    }
#endif

    return de;
}

void
diff_entry_free (DiffEntry *de)
{
    g_free (de->name);
    if (de->new_name)
        g_free (de->new_name);

#ifdef SEAFILE_CLIENT
    g_free (de->modifier);
#endif

    g_free (de);
}

#ifndef SEAFILE_SERVER

static void
diff_two_cache_entries (struct cache_entry *tree1,
                        struct cache_entry *tree2,
                        int diff_type,
                        GList **results)
{
    DiffEntry *de;

    if (!tree1) {
        if (S_ISDIR(tree2->ce_mode)) {
            de = diff_entry_new (diff_type, DIFF_STATUS_DIR_ADDED,
                                 tree2->sha1, tree2->name);
        } else {
            de = diff_entry_new (diff_type, DIFF_STATUS_ADDED,
                                 tree2->sha1, tree2->name);
        }
        *results = g_list_prepend (*results, de);
        return;
    }

    if (!tree2) {
        if (S_ISDIR(tree1->ce_mode)) {
            de = diff_entry_new (diff_type, DIFF_STATUS_DIR_DELETED,
                                 tree1->sha1, tree1->name);
        } else {
            de = diff_entry_new (diff_type, DIFF_STATUS_DELETED,
                                 tree1->sha1, tree1->name);
        }
        *results = g_list_prepend (*results, de);
        return;
    }

    if (tree2->ce_mode != tree1->ce_mode || hashcmp(tree2->sha1, tree1->sha1) != 0) {
        if (S_ISDIR(tree2->ce_mode)) {
            de = diff_entry_new (diff_type, DIFF_STATUS_DELETED,
                                 tree1->sha1, tree1->name);
            *results = g_list_prepend (*results, de);
            de = diff_entry_new (diff_type, DIFF_STATUS_DIR_ADDED,
                                 tree2->sha1, tree2->name);
            *results = g_list_prepend (*results, de);
        } else if (S_ISDIR(tree1->ce_mode)) {
            de = diff_entry_new (diff_type, DIFF_STATUS_DIR_DELETED,
                                 tree1->sha1, tree1->name);
            *results = g_list_prepend (*results, de);
            de = diff_entry_new (diff_type, DIFF_STATUS_ADDED,
                                 tree2->sha1, tree2->name);
            *results = g_list_prepend (*results, de);
        } else {
            de = diff_entry_new (diff_type, DIFF_STATUS_MODIFIED,
                                 tree2->sha1, tree2->name);
            *results = g_list_prepend (*results, de);
        }
    }
}

static int oneway_diff(struct cache_entry **src, struct unpack_trees_options *o)
{
    struct cache_entry *idx = src[0];
    struct cache_entry *tree = src[1];
    GList **results = o->unpack_data;

    if (idx == o->df_conflict_entry)
        idx = NULL;
    if (tree == o->df_conflict_entry)
        tree = NULL;

    diff_two_cache_entries (tree, idx, DIFF_TYPE_INDEX, results);

    return 0;
}

int diff_index(const char *repo_id, int version,
               struct index_state *istate, SeafDir *root, GList **results)
{
    struct tree_desc t;
    struct unpack_trees_options opts;

    memset(&opts, 0, sizeof(opts));
    memcpy (opts.repo_id, repo_id, 36);
    opts.version = version;
    opts.head_idx = 1;
    opts.index_only = 1;
    /* Unmerged entries are handled in diff worktree. */
    opts.skip_unmerged = 1;
    opts.merge = 1;
    opts.fn = oneway_diff;
    opts.unpack_data = results;
    opts.src_index = istate;
    opts.dst_index = NULL;

    fill_tree_descriptor(repo_id, version, &t, root->dir_id);
    int ret = unpack_trees(1, &t, &opts);

    tree_desc_free (&t);
    return ret;
}

#endif  /* not SEAFILE_SERVER */

inline static gboolean
dirent_same (SeafDirent *denta, SeafDirent *dentb)
{
    return (strcmp (dentb->id, denta->id) == 0 && denta->mode == dentb->mode);
}

static int
diff_files (int n, SeafDirent *dents[], const char *basedir, DiffOptions *opt)
{
    SeafDirent *files[3];
    int i, n_files = 0;

    memset (files, 0, sizeof(files[0])*n);
    for (i = 0; i < n; ++i) {
        if (dents[i] && S_ISREG(dents[i]->mode)) {
            files[i] = dents[i];
            ++n_files;
        }
    }

    if (n_files == 0)
        return 0;

    return opt->file_cb (n, basedir, files, opt->data);
}

static int
diff_trees_recursive (int n, SeafDir *trees[],
                      const char *basedir, DiffOptions *opt);

static int
diff_directories (int n, SeafDirent *dents[], const char *basedir, DiffOptions *opt)
{
    SeafDirent *dirs[3];
    int i, n_dirs = 0;
    char *dirname = "";
    int ret;
    SeafDir *sub_dirs[3], *dir;

    memset (dirs, 0, sizeof(dirs[0])*n);
    for (i = 0; i < n; ++i) {
        if (dents[i] && S_ISDIR(dents[i]->mode)) {
            dirs[i] = dents[i];
            ++n_dirs;
        }
    }

    if (n_dirs == 0)
        return 0;

    gboolean recurse = TRUE;
    ret = opt->dir_cb (n, basedir, dirs, opt->data, &recurse);
    if (ret < 0)
        return ret;

    if (!recurse)
        return 0;

    memset (sub_dirs, 0, sizeof(sub_dirs[0])*n);
    for (i = 0; i < n; ++i) {
        if (dents[i] != NULL && S_ISDIR(dents[i]->mode)) {
            dir = seaf_fs_manager_get_seafdir (seaf->fs_mgr,
                                               opt->store_id,
                                               opt->version,
                                               dents[i]->id);
            if (!dir) {
                seaf_warning ("Failed to find dir %s:%s.\n",
                              opt->store_id, dents[i]->id);
                ret = -1;
                goto free_sub_dirs;
            }
            sub_dirs[i] = dir;

            dirname = dents[i]->name;
        }
    }

    char *new_basedir = g_strconcat (basedir, dirname, "/", NULL);

    ret = diff_trees_recursive (n, sub_dirs, new_basedir, opt);

    g_free (new_basedir);

free_sub_dirs:
    for (i = 0; i < n; ++i)
        seaf_dir_free (sub_dirs[i]);
    return ret;
}

static int
diff_trees_recursive (int n, SeafDir *trees[],
                      const char *basedir, DiffOptions *opt)
{
    GList *ptrs[3];
    SeafDirent *dents[3];
    int i;
    SeafDirent *dent;
    char *first_name;
    gboolean done;
    int ret = 0;

    for (i = 0; i < n; ++i) {
        if (trees[i])
            ptrs[i] = trees[i]->entries;
        else
            ptrs[i] = NULL;
    }

    while (1) {
        first_name = NULL;
        memset (dents, 0, sizeof(dents[0])*n);
        done = TRUE;

        /* Find the "largest" name, assuming dirents are sorted. */
        for (i = 0; i < n; ++i) {
            if (ptrs[i] != NULL) {
                done = FALSE;
                dent = ptrs[i]->data;
                if (!first_name)
                    first_name = dent->name;
                else if (strcmp(dent->name, first_name) > 0)
                    first_name = dent->name;
            }
        }

        if (done)
            break;

        /*
         * Setup dir entries for all names that equal to first_name
         */
        for (i = 0; i < n; ++i) {
            if (ptrs[i] != NULL) {
                dent = ptrs[i]->data;
                if (strcmp(first_name, dent->name) == 0) {
                    dents[i] = dent;
                    ptrs[i] = ptrs[i]->next;
                }
            }
        }

        if (n == 2 && dents[0] && dents[1] && dirent_same(dents[0], dents[1]))
            continue;

        if (n == 3 && dents[0] && dents[1] && dents[2] &&
            dirent_same(dents[0], dents[1]) && dirent_same(dents[0], dents[2]))
            continue;

        /* Diff files of this level. */
        ret = diff_files (n, dents, basedir, opt);
        if (ret < 0)
            return ret;

        /* Recurse into sub level. */
        ret = diff_directories (n, dents, basedir, opt);
        if (ret < 0)
            return ret;
    }

    return ret;
}

int
diff_trees (int n, const char *roots[], DiffOptions *opt)
{
    SeafDir **trees, *root;
    int i, ret;

    g_return_val_if_fail (n == 2 || n == 3, -1);

    trees = g_new0 (SeafDir *, n);
    for (i = 0; i < n; ++i) {
        root = seaf_fs_manager_get_seafdir (seaf->fs_mgr,
                                            opt->store_id,
                                            opt->version,
                                            roots[i]);
        if (!root) {
            seaf_warning ("Failed to find dir %s:%s.\n", opt->store_id, roots[i]);
            g_free (trees);
            return -1;
        }
        trees[i] = root;
    }

    ret = diff_trees_recursive (n, trees, "", opt);

    for (i = 0; i < n; ++i)
        seaf_dir_free (trees[i]);
    g_free (trees);

    return ret;
}

typedef struct DiffData {
    GList **results;
    gboolean fold_dir_diff;
} DiffData;

static int
twoway_diff_files (int n, const char *basedir, SeafDirent *files[], void *vdata)
{
    DiffData *data = vdata;
    GList **results = data->results;
    DiffEntry *de;
    SeafDirent *tree1 = files[0];
    SeafDirent *tree2 = files[1];

    if (!tree1) {
        de = diff_entry_new_from_dirent (DIFF_TYPE_COMMITS, DIFF_STATUS_ADDED,
                                         tree2, basedir);
        *results = g_list_prepend (*results, de);
        return 0;
    }

    if (!tree2) {
        de = diff_entry_new_from_dirent (DIFF_TYPE_COMMITS, DIFF_STATUS_DELETED,
                                         tree1, basedir);
        *results = g_list_prepend (*results, de);
        return 0;
    }

    if (!dirent_same (tree1, tree2)) {
        de = diff_entry_new_from_dirent (DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED,
                                         tree2, basedir);
        *results = g_list_prepend (*results, de);
    }

    return 0;
}

static int
twoway_diff_dirs (int n, const char *basedir, SeafDirent *dirs[], void *vdata,
                  gboolean *recurse)
{
    DiffData *data = vdata;
    GList **results = data->results;
    DiffEntry *de;
    SeafDirent *tree1 = dirs[0];
    SeafDirent *tree2 = dirs[1];

    if (!tree1) {
        if (strcmp (tree2->id, EMPTY_SHA1) == 0 || data->fold_dir_diff) {
            de = diff_entry_new_from_dirent (DIFF_TYPE_COMMITS, DIFF_STATUS_DIR_ADDED,
                                             tree2, basedir);
            *results = g_list_prepend (*results, de);
            *recurse = FALSE;
        } else
            *recurse = TRUE;
        return 0;
    }

    if (!tree2) {
        de = diff_entry_new_from_dirent (DIFF_TYPE_COMMITS,
                                         DIFF_STATUS_DIR_DELETED,
                                         tree1, basedir);
        *results = g_list_prepend (*results, de);

        if (data->fold_dir_diff) {
            *recurse = FALSE;
        } else
            *recurse = TRUE;
        return 0;
    }

    return 0;
}

int
diff_commits (SeafCommit *commit1, SeafCommit *commit2, GList **results,
              gboolean fold_dir_diff)
{
    SeafRepo *repo = NULL;
    DiffOptions opt;
    const char *roots[2];

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, commit1->repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", commit1->repo_id);
        return -1;
    }

    DiffData data;
    memset (&data, 0, sizeof(data));
    data.results = results;
    data.fold_dir_diff = fold_dir_diff;

    memset (&opt, 0, sizeof(opt));
#ifdef SEAFILE_SERVER
    memcpy (opt.store_id, repo->store_id, 36);
#else
    memcpy (opt.store_id, repo->id, 36);
#endif
    opt.version = repo->version;
    opt.file_cb = twoway_diff_files;
    opt.dir_cb = twoway_diff_dirs;
    opt.data = &data;

#ifdef SEAFILE_SERVER
    seaf_repo_unref (repo);
#endif

    roots[0] = commit1->root_id;
    roots[1] = commit2->root_id;

    diff_trees (2, roots, &opt);
    diff_resolve_renames (results);

    return 0;
}

int
diff_commit_roots (const char *store_id, int version,
                   const char *root1, const char *root2, GList **results,
                   gboolean fold_dir_diff)
{
    DiffOptions opt;
    const char *roots[2];

    DiffData data;
    memset (&data, 0, sizeof(data));
    data.results = results;
    data.fold_dir_diff = fold_dir_diff;

    memset (&opt, 0, sizeof(opt));
    memcpy (opt.store_id, store_id, 36);
    opt.version = version;
    opt.file_cb = twoway_diff_files;
    opt.dir_cb = twoway_diff_dirs;
    opt.data = &data;

    roots[0] = root1;
    roots[1] = root2;

    diff_trees (2, roots, &opt);
    diff_resolve_renames (results);

    return 0;
}

static int
threeway_diff_files (int n, const char *basedir, SeafDirent *files[], void *vdata)
{
    DiffData *data = vdata;
    SeafDirent *m = files[0];
    SeafDirent *p1 = files[1];
    SeafDirent *p2 = files[2];
    GList **results = data->results;
    DiffEntry *de;

    /* diff m with both p1 and p2. */
    if (m && p1 && p2) {
        if (!dirent_same(m, p1) && !dirent_same (m, p2)) {
            de = diff_entry_new_from_dirent (DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED,
                                             m, basedir);
            *results = g_list_prepend (*results, de);
        }
    } else if (!m && p1 && p2) {
        de = diff_entry_new_from_dirent (DIFF_TYPE_COMMITS, DIFF_STATUS_DELETED,
                                         p1, basedir);
        *results = g_list_prepend (*results, de);
    } else if (m && !p1 && p2) {
        if (!dirent_same (m, p2)) {
            de = diff_entry_new_from_dirent (DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED,
                                             m, basedir);
            *results = g_list_prepend (*results, de);
        }
    } else if (m && p1 && !p2) {
        if (!dirent_same (m, p1)) {
            de = diff_entry_new_from_dirent (DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED,
                                             m, basedir);
            *results = g_list_prepend (*results, de);
        }
    } else if (m && !p1 && !p2) {
        de = diff_entry_new_from_dirent (DIFF_TYPE_COMMITS, DIFF_STATUS_ADDED,
                                         m, basedir);
        *results = g_list_prepend (*results, de);
    }
    /* Nothing to do for:
     * 1. !m && p1 && !p2;
     * 2. !m && !p1 && p2;
     * 3. !m && !p1 && !p2 (should not happen)
     */

    return 0;
}

static int
threeway_diff_dirs (int n, const char *basedir, SeafDirent *dirs[], void *vdata,
                    gboolean *recurse)
{
    *recurse = TRUE;
    return 0;
}

int
diff_merge (SeafCommit *merge, GList **results, gboolean fold_dir_diff)
{
    SeafRepo *repo = NULL;
    DiffOptions opt;
    const char *roots[3];
    SeafCommit *parent1, *parent2;

    g_return_val_if_fail (*results == NULL, -1);
    g_return_val_if_fail (merge->parent_id != NULL &&
                          merge->second_parent_id != NULL,
                          -1);

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, merge->repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", merge->repo_id);
        return -1;
    }

    parent1 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                              repo->id,
                                              repo->version,
                                              merge->parent_id);
    if (!parent1) {
        seaf_warning ("failed to find commit %s:%s.\n", repo->id, merge->parent_id);
        return -1;
    }

    parent2 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                              repo->id,
                                              repo->version,
                                              merge->second_parent_id);
    if (!parent2) {
        seaf_warning ("failed to find commit %s:%s.\n",
                      repo->id, merge->second_parent_id);
        seaf_commit_unref (parent1);
        return -1;
    }

    DiffData data;
    memset (&data, 0, sizeof(data));
    data.results = results;
    data.fold_dir_diff = fold_dir_diff;

    memset (&opt, 0, sizeof(opt));
#ifdef SEAFILE_SERVER
    memcpy (opt.store_id, repo->store_id, 36);
#else
    memcpy (opt.store_id, repo->id, 36);
#endif
    opt.version = repo->version;
    opt.file_cb = threeway_diff_files;
    opt.dir_cb = threeway_diff_dirs;
    opt.data = &data;

#ifdef SEAFILE_SERVER
    seaf_repo_unref (repo);
#endif

    roots[0] = merge->root_id;
    roots[1] = parent1->root_id;
    roots[2] = parent2->root_id;

    int ret = diff_trees (3, roots, &opt);
    diff_resolve_renames (results);

    seaf_commit_unref (parent1);
    seaf_commit_unref (parent2);

    return ret;
}

int
diff_merge_roots (const char *store_id, int version,
                  const char *merged_root, const char *p1_root, const char *p2_root,
                  GList **results, gboolean fold_dir_diff)
{
    DiffOptions opt;
    const char *roots[3];

    g_return_val_if_fail (*results == NULL, -1);

    DiffData data;
    memset (&data, 0, sizeof(data));
    data.results = results;
    data.fold_dir_diff = fold_dir_diff;

    memset (&opt, 0, sizeof(opt));
    memcpy (opt.store_id, store_id, 36);
    opt.version = version;
    opt.file_cb = threeway_diff_files;
    opt.dir_cb = threeway_diff_dirs;
    opt.data = &data;

    roots[0] = merged_root;
    roots[1] = p1_root;
    roots[2] = p2_root;

    diff_trees (3, roots, &opt);
    diff_resolve_renames (results);

    return 0;
}

/* This function only resolve "strict" rename, i.e. two files must be
 * exactly the same.
 * Don't detect rename of empty files and empty dirs.
 */
void
diff_resolve_renames (GList **diff_entries)
{
    GHashTable *deleted;
    GList *p;
    GList *added = NULL;
    DiffEntry *de;
    unsigned char empty_sha1[20];

    memset (empty_sha1, 0, 20);

    /* Hash and equal functions for raw sha1. */
    deleted = g_hash_table_new (ccnet_sha1_hash, ccnet_sha1_equal);

    /* Collect all "deleted" entries. */
    for (p = *diff_entries; p != NULL; p = p->next) {
        de = p->data;
        if ((de->status == DIFF_STATUS_DELETED ||
             de->status == DIFF_STATUS_DIR_DELETED) &&
            memcmp (de->sha1, empty_sha1, 20) != 0)
            g_hash_table_insert (deleted, de->sha1, p);
    }

    /* Collect all "added" entries into a separate list. */
    for (p = *diff_entries; p != NULL; p = p->next) {
        de = p->data;
        if ((de->status == DIFF_STATUS_ADDED ||
             de->status == DIFF_STATUS_DIR_ADDED) &&
            memcmp (de->sha1, empty_sha1, 20) != 0)
            added = g_list_prepend (added, p);
    }

    /* For each "added" entry, if we find a "deleted" entry with
     * the same content, we find a rename pair.
     */
    p = added;
    while (p != NULL) {
        GList *p_add, *p_del;
        DiffEntry *de_add, *de_del, *de_rename;
        int rename_status;

        p_add = p->data;
        de_add = p_add->data;

        p_del = g_hash_table_lookup (deleted, de_add->sha1);
        if (p_del) {
            de_del = p_del->data;

            if (de_add->status == DIFF_STATUS_DIR_ADDED)
                rename_status = DIFF_STATUS_DIR_RENAMED;
            else
                rename_status = DIFF_STATUS_RENAMED;

            de_rename = diff_entry_new (de_del->type, rename_status, 
                                        de_del->sha1, de_del->name);
            de_rename->new_name = g_strdup(de_add->name);

            *diff_entries = g_list_delete_link (*diff_entries, p_add);
            *diff_entries = g_list_delete_link (*diff_entries, p_del);
            *diff_entries = g_list_prepend (*diff_entries, de_rename);

            g_hash_table_remove (deleted, de_add->sha1);

            diff_entry_free (de_add);
            diff_entry_free (de_del);
        }

        p = g_list_delete_link (p, p);
    }

    g_hash_table_destroy (deleted);
}

static gboolean
is_redundant_empty_dir (DiffEntry *de_dir, DiffEntry *de_file)
{
    int dir_len;

    if (de_dir->status == DIFF_STATUS_DIR_ADDED &&
        de_file->status == DIFF_STATUS_DELETED)
    {
        dir_len = strlen (de_dir->name);
        if (strlen (de_file->name) > dir_len &&
            strncmp (de_dir->name, de_file->name, dir_len) == 0)
            return TRUE;
    }

    if (de_dir->status == DIFF_STATUS_DIR_DELETED &&
        de_file->status == DIFF_STATUS_ADDED)
    {
        dir_len = strlen (de_dir->name);
        if (strlen (de_file->name) > dir_len &&
            strncmp (de_dir->name, de_file->name, dir_len) == 0)
            return TRUE;
    }

    return FALSE;
}

/*
 * An empty dir entry may be added by deleting all the files under it.
 * Similarly, an empty dir entry may be deleted by adding some file in it.
 * In both cases, we don't want to include the empty dir entry in the
 * diff results.
 */
void
diff_resolve_empty_dirs (GList **diff_entries)
{
    GList *empty_dirs = NULL;
    GList *p, *dir, *file;
    DiffEntry *de, *de_dir, *de_file;

    for (p = *diff_entries; p != NULL; p = p->next) {
        de = p->data;
        if (de->status == DIFF_STATUS_DIR_ADDED ||
            de->status == DIFF_STATUS_DIR_DELETED)
            empty_dirs = g_list_prepend (empty_dirs, p);
    }

    for (dir = empty_dirs; dir != NULL; dir = dir->next) {
        de_dir = ((GList *)dir->data)->data;
        for (file = *diff_entries; file != NULL; file = file->next) {
            de_file = file->data;
            if (is_redundant_empty_dir (de_dir, de_file)) {
                *diff_entries = g_list_delete_link (*diff_entries, dir->data);
                break;
            }
        }
    }

    g_list_free (empty_dirs);
}

int diff_unmerged_state(int mask)
{
    mask >>= 1;
    switch (mask) {
        case 7:
            return STATUS_UNMERGED_BOTH_CHANGED;
        case 3:
            return STATUS_UNMERGED_OTHERS_REMOVED;
        case 5:
            return STATUS_UNMERGED_I_REMOVED;
        case 6:
            return STATUS_UNMERGED_BOTH_ADDED;
        case 2:
            return STATUS_UNMERGED_DFC_I_ADDED_FILE;
        case 4:
            return STATUS_UNMERGED_DFC_OTHERS_ADDED_FILE;
        default:
            seaf_warning ("Unexpected unmerged case\n");
    }
    return 0;
}

char *
format_diff_results(GList *results)
{
    GList *ptr;
    GString *fmt_status;
    DiffEntry *de;

    fmt_status = g_string_new("");

    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;

        if (de->status != DIFF_STATUS_RENAMED)
            g_string_append_printf(fmt_status, "%c %c %d %u %s\n",
                                   de->type, de->status, de->unmerge_state,
                                   (int)strlen(de->name), de->name);
        else
            g_string_append_printf(fmt_status, "%c %c %d %u %s %u %s\n",
                                   de->type, de->status, de->unmerge_state,
                                   (int)strlen(de->name), de->name,
                                   (int)strlen(de->new_name), de->new_name);
    }

    return g_string_free(fmt_status, FALSE);
}

inline static char *
get_basename (char *path)
{
    char *slash;
    slash = strrchr (path, '/');
    if (!slash)
        return path;
    return (slash + 1);
}

char *
diff_results_to_description (GList *results)
{
    GList *p;
    DiffEntry *de;
    char *add_mod_file = NULL, *removed_file = NULL;
    char *renamed_file = NULL;
    char *new_dir = NULL, *removed_dir = NULL;
    int n_add_mod = 0, n_removed = 0, n_renamed = 0;
    int n_new_dir = 0, n_removed_dir = 0;
    GString *desc;

    if (results == NULL)
        return NULL;

    for (p = results; p != NULL; p = p->next) {
        de = p->data;
        switch (de->status) {
        case DIFF_STATUS_ADDED:
            if (n_add_mod == 0)
                add_mod_file = get_basename(de->name);
            n_add_mod++;
            break;
        case DIFF_STATUS_DELETED:
            if (n_removed == 0)
                removed_file = get_basename(de->name);
            n_removed++;
            break;
        case DIFF_STATUS_RENAMED:
            if (n_renamed == 0)
                renamed_file = get_basename(de->name);
            n_renamed++;
            break;
        case DIFF_STATUS_MODIFIED:
            if (n_add_mod == 0)
                add_mod_file = get_basename(de->name);
            n_add_mod++;
            break;
        case DIFF_STATUS_DIR_ADDED:
            if (n_new_dir == 0)
                new_dir = get_basename(de->name);
            n_new_dir++;
            break;
        case DIFF_STATUS_DIR_DELETED:
            if (n_removed_dir == 0)
                removed_dir = get_basename(de->name);
            n_removed_dir++;
            break;
        }
    }

    desc = g_string_new ("");

    if (n_add_mod == 1)
        g_string_append_printf (desc, "Added or modified \"%s\".\n", add_mod_file);
    else if (n_add_mod > 1)
        g_string_append_printf (desc, "Added or modified \"%s\" and %d more files.\n",
                                add_mod_file, n_add_mod - 1);

    if (n_removed == 1)
        g_string_append_printf (desc, "Deleted \"%s\".\n", removed_file);
    else if (n_removed > 1)
        g_string_append_printf (desc, "Deleted \"%s\" and %d more files.\n",
                                removed_file, n_removed - 1);

    if (n_renamed == 1)
        g_string_append_printf (desc, "Renamed \"%s\".\n", renamed_file);
    else if (n_renamed > 1)
        g_string_append_printf (desc, "Renamed \"%s\" and %d more files.\n",
                                renamed_file, n_renamed - 1);

    if (n_new_dir == 1)
        g_string_append_printf (desc, "Added directory \"%s\".\n", new_dir);
    else if (n_new_dir > 1)
        g_string_append_printf (desc, "Added \"%s\" and %d more directories.\n",
                                new_dir, n_new_dir - 1);

    if (n_removed_dir == 1)
        g_string_append_printf (desc, "Removed directory \"%s\".\n", removed_dir);
    else if (n_removed_dir > 1)
        g_string_append_printf (desc, "Removed \"%s\" and %d more directories.\n",
                                removed_dir, n_removed_dir - 1);

    return g_string_free (desc, FALSE);
}
