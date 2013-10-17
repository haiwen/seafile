#include "common.h"
#include "diff-simple.h"
#include "unpack-trees.h"
#include "utils.h"
#include "log.h"

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

void
diff_entry_free (DiffEntry *de)
{
    g_free (de->name);
    if (de->new_name)
        g_free (de->new_name);
    g_free (de);
}

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

int diff_index(struct index_state *istate, SeafDir *root, GList **results)
{
    struct tree_desc t;
    struct unpack_trees_options opts;

    memset(&opts, 0, sizeof(opts));
    opts.head_idx = 1;
    opts.index_only = 1;
    /* Unmerged entries are handled in diff worktree. */
    opts.skip_unmerged = 1;
    opts.merge = 1;
    opts.fn = oneway_diff;
    opts.unpack_data = results;
    opts.src_index = istate;
    opts.dst_index = NULL;

    fill_tree_descriptor(&t, root->dir_id);
    int ret = unpack_trees(1, &t, &opts);

    tree_desc_free (&t);
    return ret;
}

inline static gboolean
ce_same (struct cache_entry *ce1, struct cache_entry *ce2)
{
    return (ce1->ce_mode == ce2->ce_mode &&
            hashcmp(ce1->sha1, ce2->sha1) == 0);
}

static int 
twoway_diff(struct cache_entry **src, struct unpack_trees_options *o)
{
    struct cache_entry *tree1 = src[1];
    struct cache_entry *tree2 = src[2];
    GList **results = o->unpack_data;

    if (tree1 == o->df_conflict_entry)
        tree1 = NULL;
    if (tree2 == o->df_conflict_entry)
        tree2 = NULL;

    diff_two_cache_entries (tree1, tree2, DIFF_TYPE_COMMITS, results);

    return 0;
}

#ifdef DEBUG
static void
print_results (GList *results)
{
    GList *p;
    DiffEntry *de;

    g_debug ("diff results:\n");
    for (p = results; p != NULL; p = p->next) {
        de = p->data;
        g_debug ("%c %s\n", de->status, de->name);
    }
}
#endif

int
diff_commits (SeafCommit *commit1, SeafCommit *commit2, GList **results)
{
    struct tree_desc t[2];
    struct unpack_trees_options opts;
    struct index_state istate;

    g_return_val_if_fail (*results == NULL, -1);

    if (strcmp (commit1->commit_id, commit2->commit_id) == 0)
        return 0;

    if (strcmp (commit1->root_id, EMPTY_SHA1) != 0) {
        fill_tree_descriptor(&t[0], commit1->root_id);
    } else {
        fill_tree_descriptor(&t[0], NULL);
    }

    if (strcmp (commit2->root_id, EMPTY_SHA1) != 0) {
        fill_tree_descriptor(&t[1], commit2->root_id);
    } else {
        fill_tree_descriptor(&t[1], NULL);
    }

    /* Empty index */
    memset(&istate, 0, sizeof(istate));
    memset(&opts, 0, sizeof(opts));

    opts.head_idx = -1;
    opts.index_only = 1;
    opts.merge = 1;
    opts.fn = twoway_diff;
    opts.unpack_data = results;
    opts.src_index = &istate;
    opts.dst_index = NULL;

    if (unpack_trees(2, t, &opts) < 0) {
        seaf_warning ("failed to unpack trees.\n");
        return -1;
    }

    if (results != NULL)
        diff_resolve_empty_dirs (results);

    if (*results != NULL)
        diff_resolve_renames (results);

    tree_desc_free (&t[0]);
    tree_desc_free (&t[1]);

    return 0;
}

static int 
threeway_diff(struct cache_entry **src, struct unpack_trees_options *o)
{
    struct cache_entry *m = src[1];
    struct cache_entry *p1 = src[2];
    struct cache_entry *p2 = src[3];
    GList **results = o->unpack_data;
    DiffEntry *de;

    if (m == o->df_conflict_entry)
        m = NULL;
    if (p1 == o->df_conflict_entry)
        p1 = NULL;
    if (p2 == o->df_conflict_entry)
        p2 = NULL;

    /* diff m from both p1 and p2. */
    if (m && p1 && p2) {
        if (!ce_same(m, p1) && !ce_same (m, p2)) {
            de = diff_entry_new (DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED,
                                 m->sha1, m->name);
            *results = g_list_prepend (*results, de);
        }
    } else if (!m && p1 && p2) {
        de = diff_entry_new (DIFF_TYPE_COMMITS, DIFF_STATUS_DELETED,
                             p1->sha1, p1->name);
        *results = g_list_prepend (*results, de);
    } else if (m && !p1 && p2) {
        if (!ce_same (m, p2)) {
            de = diff_entry_new (DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED,
                                 m->sha1, m->name);
            *results = g_list_prepend (*results, de);
        }
    } else if (m && p1 && !p2) {
        if (!ce_same (m, p1)) {
            de = diff_entry_new (DIFF_TYPE_COMMITS, DIFF_STATUS_MODIFIED,
                                 m->sha1, m->name);
            *results = g_list_prepend (*results, de);
        }
    } else if (m && !p1 && !p2) {
        de = diff_entry_new (DIFF_TYPE_COMMITS, DIFF_STATUS_ADDED,
                             m->sha1, m->name);
        *results = g_list_prepend (*results, de);
    }
    /* Nothing to do for:
     * 1. !m && p1 && !p2;
     * 2. !m && !p1 && p2;
     * 3. !m && !p1 && !p2 (should not happen)
     */

    return 0;
}

int
diff_merge (SeafCommit *merge, GList **results)
{
    SeafCommit *parent1, *parent2;
    struct tree_desc t[3];
    struct unpack_trees_options opts;
    struct index_state istate;

    g_return_val_if_fail (*results == NULL, -1);
    g_return_val_if_fail (merge->parent_id != NULL &&
                          merge->second_parent_id != NULL,
                          -1);

    parent1 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                              merge->parent_id);
    if (!parent1) {
        seaf_warning ("failed to find commit %s.\n", merge->parent_id);
        return -1;
    }

    parent2 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                              merge->second_parent_id);
    if (!parent2) {
        seaf_warning ("failed to find commit %s.\n", merge->second_parent_id);
        seaf_commit_unref (parent1);
        return -1;
    }

    fill_tree_descriptor(&t[0], merge->root_id);
    fill_tree_descriptor(&t[1], parent1->root_id);
    fill_tree_descriptor(&t[2], parent2->root_id);

    seaf_commit_unref (parent1);
    seaf_commit_unref (parent2);

    /* Empty index */
    memset(&istate, 0, sizeof(istate));
    memset(&opts, 0, sizeof(opts));

    opts.head_idx = -1;
    opts.index_only = 1;
    opts.merge = 1;
    opts.fn = threeway_diff;
    opts.unpack_data = results;
    opts.src_index = &istate;
    opts.dst_index = NULL;

    if (unpack_trees(3, t, &opts) < 0) {
        seaf_warning ("failed to unpack trees.\n");
        return -1;
    }

    if (*results != NULL)
        diff_resolve_renames (results);

    tree_desc_free (&t[0]);
    tree_desc_free (&t[1]);
    tree_desc_free (&t[2]);

    return 0;
}

/* This function only resolve "strict" rename, i.e. two files must be
 * exactly the same.
 */
void
diff_resolve_renames (GList **diff_entries)
{
    GHashTable *deleted;
    GList *p;
    GList *added = NULL;
    DiffEntry *de;

    /* Hash and equal functions for raw sha1. */
    deleted = g_hash_table_new (ccnet_sha1_hash, ccnet_sha1_equal);

    /* Collect all "deleted" entries. */
    for (p = *diff_entries; p != NULL; p = p->next) {
        de = p->data;
        if (de->status == DIFF_STATUS_DELETED)
            g_hash_table_insert (deleted, de->sha1, p);
    }

    /* Collect all "added" entries into a separate list. */
    for (p = *diff_entries; p != NULL; p = p->next) {
        de = p->data;
        if (de->status == DIFF_STATUS_ADDED)
            added = g_list_prepend (added, p);
    }

    /* For each "added" entry, if we find a "deleted" entry with
     * the same content, we find a rename pair.
     */
    p = added;
    while (p != NULL) {
        GList *p_add, *p_del;
        DiffEntry *de_add, *de_del, *de_rename;

        p_add = p->data;
        de_add = p_add->data;

        p_del = g_hash_table_lookup (deleted, de_add->sha1);
        if (p_del) {
            de_del = p_del->data;
            de_rename = diff_entry_new (de_del->type, DIFF_STATUS_RENAMED, 
                                        de_del->sha1, de_del->name);
            de_rename->new_name = g_strdup(de_add->name);

            *diff_entries = g_list_delete_link (*diff_entries, p_add);
            *diff_entries = g_list_delete_link (*diff_entries, p_del);
            *diff_entries = g_list_prepend (*diff_entries, de_rename);

            g_hash_table_remove (deleted, de_add->sha1);
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
            g_warning ("Unexpected unmerged case\n");
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
