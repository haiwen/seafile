/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * Recursive Merge algorithm stolen from git-merge-recursive.py by
 * Fredrik Kuivinen.
 * The thieves were Alex Riesen and Johannes Schindelin, in June/July 2006
 */
#include "common.h"

#ifdef WIN32
#include <windows.h>
#endif

#include "seafile-session.h"

#include "index/index.h"
#include "index/cache-tree.h"
#include "unpack-trees.h"
#include "merge-recursive.h"
#include "vc-utils.h"
#include "vc-common.h"
#include "utils.h"

/*
 * Since we want to write the index eventually, we cannot reuse the index
 * for these (temporary) data.
 */
struct stage_data
{
    char *path;
    struct
    {
        unsigned mode;
        guint64 ctime;
        guint64 mtime;
        guint64 current_mtime;
        unsigned char sha[20];
        char *modifier;
    } stages[4];
    unsigned processed:1;
};

#if 0
__attribute__((format (printf, 2, 3)))
static void output(struct merge_options *o, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    g_string_append_vprintf(o->obuf, fmt, ap);
    g_string_append (o->obuf, "\n");
    va_end(ap);
}
#endif

static int add_cacheinfo(struct index_state *index,
                         unsigned int mode, const unsigned char *sha1,
                         const char *modifier,
                         const char *path, const char *full_path,
                         int stage, int refresh, int options)
{
    struct cache_entry *ce;
    ce = make_cache_entry(mode, sha1, path, full_path, stage, refresh);
    if (!ce) {
        g_warning("addinfo_cache failed for path '%s'", path);
        return -1;
    }
    ce->modifier = g_strdup(modifier);
    return add_index_entry(index, ce, options);
}

static int seafile_merge_trees(struct merge_options *o,
                               struct unpack_trees_options *opts,
                               SeafDir *common,
                               SeafDir *head,
                               SeafDir *merge,
                               char **error)
{
    int rc;
    struct tree_desc t[3];

    memset(opts, 0, sizeof(*opts));
    memcpy (opts->repo_id, o->repo_id, 36);
    opts->version = o->version;
    if (o->call_depth)
        opts->index_only = 1;
    else
        opts->update = 1;
    opts->merge = 1;
    opts->head_idx = 2;
    opts->base = o->worktree;
    opts->fn = threeway_merge;
    opts->src_index = o->index;
    opts->dst_index = o->index;
    if (o->crypt)
        opts->crypt = o->crypt;

    fill_tree_descriptor(o->repo_id, o->version, t+0, common->dir_id);
    fill_tree_descriptor(o->repo_id, o->version, t+1, head->dir_id);
    fill_tree_descriptor(o->repo_id, o->version, t+2, merge->dir_id);

    rc = unpack_trees(3, t, opts);

    if (rc == 0) {
        discard_index(o->index);
        *(o->index) = opts->result;

        if (o->collect_blocks_only)
            collect_new_blocks_from_index (o->repo_id, o->version, o->index, o->bl);
    }

    tree_desc_free (t);
    tree_desc_free (t+1);
    tree_desc_free (t+2);

    return rc;
}

char *write_tree_from_memory(struct merge_options *o)
{
    struct cache_tree *it;
    char root_id[41];

    if (unmerged_index(o->index)) {
        int i;
        g_warning("BUG: There are unmerged index entries:\n");
        for (i = 0; i < o->index->cache_nr; i++) {
            struct cache_entry *ce = o->index->cache[i];
            if (ce_stage(ce))
                g_warning("%d %.*s\n", ce_stage(ce),
                        (int)ce_namelen(ce), ce->name);
        }
        return NULL;
    }

    /* if (!active_cache_tree) */
    it = cache_tree();

    if (cache_tree_update(o->repo_id, o->version,
                          o->worktree, 
                          it, o->index->cache, o->index->cache_nr, 
                          0, 0, commit_trees_cb) < 0) {
        g_warning("error building trees");
        cache_tree_free (&it);
        return NULL;
    }

    rawdata_to_hex(it->sha1, root_id, 20);
    cache_tree_free (&it);
    return g_strdup(root_id);
}

static int get_files_dirs_recursive(struct merge_options *o, SeafDir *tree,
                                    char *base, int baselen)
{
    GList *p;
    char *path;
    int ret = 0;

    for (p = tree->entries; p; p = p->next) {
        SeafDirent *dent = (SeafDirent *)p->data;
        SeafDir *subdir;
        int new_baselen;
        int pathlen;
        switch (S_IFMT & dent->mode) {
        case S_IFREG:
            pathlen = baselen + dent->name_len + 1;
            path = malloc(pathlen);
            snprintf(path, pathlen, "%s%s", base, dent->name);
            g_hash_table_replace(o->current_file_set, path, path);
            break;
        case S_IFDIR:
            /* Ignore empty dirs. */
            if (memcmp (dent->id, EMPTY_SHA1, 40) == 0)
                break;

            pathlen = baselen + dent->name_len + 1;
            path = malloc(pathlen);
            snprintf(path, pathlen, "%s%s", base, dent->name);
            g_hash_table_replace(o->current_directory_set, path, path);

            snprintf(base + baselen, SEAF_PATH_MAX, "%s/", dent->name);
            new_baselen = baselen + dent->name_len + 1;
            subdir = seaf_fs_manager_get_seafdir(seaf->fs_mgr,
                                                 o->repo_id, o->version,
                                                 dent->id);
            if (!subdir) {
                g_warning("Failed to get dir %s\n", dent->id);
                return -1;
            }
            ret = get_files_dirs_recursive(o, subdir, base, new_baselen);
            base[baselen] = 0;
            seaf_dir_free (subdir);
            break;
        case S_IFLNK:
            break;
        default:
            break;
        }
    }

    return ret;
}

static int get_files_dirs(struct merge_options *o, SeafDir *tree)
{
    char base[SEAF_PATH_MAX];

    base[0] = 0;
    return get_files_dirs_recursive(o, tree, base, 0);
}

inline static int ce_in_unmerged_list(GList *unmerged, struct cache_entry *ce)
{
    struct stage_data *e;

    if (!unmerged)
        return 0;
    /* unmerged is sorted. Only need to check the first item. */
    e = unmerged->data;
    return (strcmp(e->path, ce->name) == 0);
}

/*
 * Create a dictionary mapping file names to stage_data objects. The
 * dictionary contains one entry for every path with a non-zero stage entry.
 */
static GList *get_unmerged(struct index_state *index)
{
    GList *unmerged = NULL;
    int i;

    for (i = 0; i < index->cache_nr; i++) {
        struct stage_data *e;
        struct cache_entry *ce = index->cache[i];
        if (!ce_stage(ce))
            continue;

        if (!ce_in_unmerged_list(unmerged, ce)) {
            e = (struct stage_data *)calloc(1, sizeof(struct stage_data));
            e->path = g_strdup(ce->name);
            unmerged = g_list_prepend(unmerged, e);
        }

        e->stages[ce_stage(ce)].ctime = ce->ce_ctime.sec;
        e->stages[ce_stage(ce)].mtime = ce->ce_mtime.sec;
        e->stages[ce_stage(ce)].current_mtime = ce->current_mtime;
        e->stages[ce_stage(ce)].mode = ce->ce_mode;
        hashcpy(e->stages[ce_stage(ce)].sha, ce->sha1);
        e->stages[ce_stage(ce)].modifier = g_strdup(ce->modifier);
    }
    unmerged = g_list_reverse(unmerged);

    return unmerged;
}

#if 0
static void make_room_for_directories_of_df_conflicts(struct merge_options *o,
                                                      GList *entries)
{
    /* If there are D/F conflicts, and the paths currently exist
     * in the working copy as a file, we want to remove them to
     * make room for the corresponding directory.  Such paths will
     * later be processed in process_df_entry() at the end.  If
     * the corresponding directory ends up being removed by the
     * merge, then the file will be reinstated at that time;
     * otherwise, if the file is not supposed to be removed by the
     * merge, the contents of the file will be placed in another
     * unique filename.
     *
     * NOTE: This function relies on the fact that entries for a
     * D/F conflict will appear adjacent in the index, with the
     * entries for the file appearing before entries for paths
     * below the corresponding directory.
     */
    const char *last_file = NULL;
    int last_len = 0;
    struct stage_data *last_e;
    GList *p;
    char *real_path;

    for (p = entries; p != NULL; p = p->next) {
        struct stage_data *e = p->data;
        int len = strlen(e->path);

        /*
         * Check if last_file & path correspond to a D/F conflict;
         * i.e. whether path is last_file+'/'+<something>.
         * If so, remove last_file to make room for path and friends.
         */
        if (last_file &&
            len > last_len &&
            memcmp(e->path, last_file, last_len) == 0 &&
            e->path[last_len] == '/') {
            real_path = g_build_path(PATH_SEPERATOR, o->worktree, last_file, NULL);
            seaf_util_unlink(real_path);
            g_free (real_path);
        }

        /*
         * Determine whether path could exist as a file in the
         * working directory as a possible D/F conflict.  This
         * will only occur when it exists in stage 2 as a
         * file.
         */
        if (S_ISREG(e->stages[2].mode) || S_ISLNK(e->stages[2].mode)) {
            last_file = e->path;
            last_len = len;
            last_e = e;
        } else {
            last_file = NULL;
        }
    }
}
#endif

static int
remove_path (const char *worktree, const char *name, guint64 mtime)
{
    char *slash;
    char *path;
    SeafStat st;

    path = g_build_path(PATH_SEPERATOR, worktree, name, NULL);

    /* file doesn't exist in work tree */
    if (seaf_stat (path, &st) < 0) {
        g_free (path);
        return 0;
    }

    if (S_ISREG (st.st_mode)) {
        /* file has been changed. */
        if (mtime != st.st_mtime) {
            g_free (path);
            return -1;
        }

        seaf_util_unlink(path);
    } else if (S_ISDIR (st.st_mode)) {
        if (seaf_remove_empty_dir (path) < 0) {
            g_warning ("Failed to remove %s: %s.\n", path, strerror(errno));
            g_free (path);
            return -1;
        }
    } else {
        g_free (path);
        return 0;
    }

    slash = strrchr (path, '/');
    if (slash) {
        do {
            *slash = '\0';
        } while (strcmp (worktree, path) != 0 &&
                 seaf_remove_empty_dir (path) == 0 &&
                 (slash = strrchr (path, '/')));
    }

    g_free (path);
    return 0;
}

static int remove_file(struct merge_options *o, int clean,
                       const char *path, int no_wd,
                       guint64 mtime)
{
    int update_cache = o->call_depth || clean;
    int update_working_directory = !o->call_depth && !no_wd;

    if (o->collect_blocks_only)
        return 0;

    if (update_cache) {
        if (remove_file_from_index(o->index, path))
            return -1;
    }
    if (update_working_directory) {
        if (remove_path(o->worktree, path, mtime) < 0)
            return -1;
    }
    return 0;
}

inline static int file_exists(const char *f)
{
    SeafStat sb;
    return (seaf_stat (f, &sb) == 0);
}

#if 0
static int would_lose_untracked(struct index_state *index, const char *path, const char *real_path)
{
    int pos = index_name_pos(index, path, strlen(path));

    if (pos < 0)
        pos = -1 - pos;
    while (pos < index->cache_nr &&
           !strcmp(path, index->cache[pos]->name)) {
        /*
         * If stage #0, it is definitely tracked.
         * If it has stage #2 then it was tracked
         * before this merge started.  All other
         * cases the path was not tracked.
         */
        switch (ce_stage(index->cache[pos])) {
        case 0:
        case 2:
            return 0;
        }
        pos++;
    }
    return file_exists(real_path);
}
#endif

static int create_leading_directories(int base_len,
                                      const char *path, char **new_path,
                                      const char *conflict_suffix,
                                      int *clean)
{
    int len = strlen(path);
    char buf[SEAF_PATH_MAX];
    int offset = base_len, my_offset = base_len;
    SeafStat st;
    int n;

    memcpy (buf, path, base_len);
    *clean = 1;

    /* first create all leading directories. */
    while (offset < len) {
        do {
            buf[my_offset] = path[offset];
            offset++;
            my_offset++;
        } while (offset < len && path[offset] != '/');
        if (offset >= len) {
            buf[my_offset] = 0;
            break;
        }
        buf[my_offset] = 0;

        if (seaf_stat (buf, &st) == 0 && S_ISDIR(st.st_mode)) {
            continue;
        } else if (S_ISREG(st.st_mode)) {
            time_t t = time(NULL);
            char time_buf[64];

            /* It's not a clean merge if conflict path is created. */
            *clean = 0;

            strftime(time_buf, 64, "%Y-%m-%d-%H-%M-%S", localtime(&t));
            n = snprintf (&buf[my_offset], SEAF_PATH_MAX - my_offset,
                          " (%s)", time_buf);
            my_offset += n;
            if (seaf_stat (buf, &st) == 0 && S_ISDIR(st.st_mode))
                continue;
        }
        
        if (seaf_util_mkdir (buf, 0777) < 0) {
            g_warning ("Failed to create directory %s.\n", buf);
            return -1;
        }
    }

    *new_path = g_strdup(buf);

    return 0;
}

static int make_room_for_path(struct index_state *index, const char *path, 
                              const char *real_path, char **new_path,
                              const char *conflict_suffix, int *clean)
{
    int status;
    SeafStat st;
    int base_len = strlen(real_path) - strlen(path);

    status = create_leading_directories(base_len, real_path, new_path, conflict_suffix, clean);
    if (status) {
        return -1;
    }

    if (seaf_stat (*new_path, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (seaf_util_rmdir (*new_path) < 0) {
            g_warning ("failed to remove directory %s.\n", *new_path);
            /* Don't return error since we can handle conflict later. */
        }
        return 0;
    }

    /*
     * Do not unlink a file in the work tree if we are not
     * tracking it.
     */
    /* if (would_lose_untracked(index, path, *new_path)) { */
    /*  g_warning("refusing to lose untracked file at '%s'", path); */
    /*  return -1; */
    /* } */

    return 0;

    /* /\* Successful unlink is good.. *\/ */
    /* if (!g_unlink(*new_path)) */
    /*  return 0; */
    /* /\* .. and so is no existing file *\/ */
    /* if (errno == ENOENT) */
    /*  return 0; */
    /* /\* .. but not some other error (who really cares what?) *\/ */
    /* return -1; */
}

static int update_file_flags(struct merge_options *o,
                             const unsigned char *sha,
                             unsigned mode,
                             const char *modifier,
                             guint64 mtime,
                             const char *path,
                             int update_cache,
                             int update_wd)
{
    char *real_path;
    char file_id[41];
    int clean = 1;
    int refresh = 1;

    if (update_wd && o->collect_blocks_only) {
        fill_seafile_blocks (o->repo_id, o->version, sha, o->bl);
        return clean;
    }

    real_path = g_build_path(PATH_SEPERATOR, o->worktree, path, NULL);

    if (update_wd) {
        char *new_path;
        SeafStat st;

        /* When creating a conflict directory, we use o->branch2 as conflict
         * suffix instead of the last changer name of path.
         * This is because there may be more than one conflicting file
         * under this directory, each has different changer.
         */
        if (make_room_for_path(o->index, path, real_path, 
                               &new_path, o->branch2, &clean) < 0) {
            g_free (real_path);
            refresh = 0;
            goto update_cache;
        }
        g_free (real_path);
        real_path = new_path;

        /* Checkout an empty dir. */
        if (S_ISDIR (mode)) {
            if (seaf_util_mkdir (real_path, 0777) < 0) {
                g_warning ("Failed to create empty dir %s in merge.\n", real_path);
                refresh = 0;
            }
            if (mtime != 0 && seaf_set_file_time (real_path, mtime) < 0)
                g_warning ("Failed to set mtime for %s.\n", real_path);
            goto update_cache;
        }

        /* We're checking out a clean file in recover merge.
         * Note that file is clean only when it's added by others.
         */
        if (update_cache && o->recover_merge && 
            seaf_stat(real_path, &st) == 0 && S_ISREG(st.st_mode)) {
            if (compare_file_content (real_path, &st, sha, 
                                      o->crypt, o->version) == 0) {
                goto update_cache;
            }
            /* If the file was checked out and changed by user, we
             * don't need to check out again, since the user should
             * know the content of this file.
             */
            g_free (real_path);
            return clean;
        }

        gboolean conflicted = FALSE;
        rawdata_to_hex(sha, file_id, 20);
        if (seaf_fs_manager_checkout_file(seaf->fs_mgr, 
                                          o->repo_id,
                                          o->version,
                                          file_id,
                                          real_path,
                                          mode,
                                          mtime,
                                          o->crypt,
                                          o->remote_head,
                                          path,
                                          FALSE,
                                          &conflicted) < 0) {
            g_warning("Failed to checkout file %s.\n", file_id);
            refresh = 0;
            goto update_cache;
        }
    }

update_cache:
    if (update_cache && clean)
        add_cacheinfo(o->index, mode, sha, modifier,
                      path, real_path, 0, refresh, ADD_CACHE_OK_TO_ADD);
    g_free(real_path);

    return clean;
}

static int update_file(struct merge_options *o,
                       int clean,
                       const unsigned char *sha,
                       unsigned mode,
                       const char *modifier,
                       guint64 mtime,
                       const char *path)
{
    return update_file_flags(o, sha, mode, modifier, mtime, path, clean, 1);
}

/* Per entry merge function */
static int process_entry(struct merge_options *o,
                         const char *path,
                         struct stage_data *entry)
{
    /*
      printf("processing entry, clean cache: %s\n", index_only ? "yes": "no");
      print_index_entry("\tpath: ", entry);
    */
    int clean_merge = 1;
    unsigned o_mode = entry->stages[1].mode;
    unsigned a_mode = entry->stages[2].mode;
    unsigned b_mode = entry->stages[3].mode;
    unsigned char *o_sha = o_mode ? entry->stages[1].sha : NULL;
    unsigned char *a_sha = a_mode ? entry->stages[2].sha : NULL;
    unsigned char *b_sha = b_mode ? entry->stages[3].sha : NULL;
    guint64 current_mtime = entry->stages[2].current_mtime;
    guint64 a_mtime = entry->stages[2].mtime;
    guint64 b_mtime = entry->stages[3].mtime;
    char *a_modifier = entry->stages[2].modifier;
    char *b_modifier = entry->stages[3].modifier;

    /* if (entry->rename_df_conflict_info) */
    /*  return 1; /\* Such cases are handled elsewhere. *\/ */

    entry->processed = 1;
    if (o_sha && (!a_sha || !b_sha)) {
        /* Case A: Deleted in one */
        if ((!a_sha && !b_sha) ||
            (!b_sha && memcmp(o_sha, a_sha, 20) == 0 && o_mode == a_mode) ||
            (!a_sha && memcmp(o_sha, b_sha, 20) == 0 && o_mode == b_mode)) {
            /* Deleted in both or deleted in one and
             * unchanged in the other */
            /* do not touch working file if it did not exist */
            /* do not remove working file if it's changed. */
            remove_file(o, 1, path, !a_sha, current_mtime);
        } else if (g_hash_table_lookup(o->current_directory_set,
                                       path)) {
            /* file -> (file, directory), the file side. */
            entry->processed = 0;
            return 1;
        } else {
            /* Deleted in one and changed in the other */
            /* or directory -> (file, directory), directory side */
            /* Don't consider as unclean. */
            if (!a_sha)
                clean_merge = update_file(o, 1, b_sha, b_mode, b_modifier, b_mtime, path);
            else
                update_file_flags (o, a_sha, a_mode, a_modifier, a_mtime, path, 1, 0);
        }

    } else if ((!o_sha && a_sha && !b_sha) ||
               (!o_sha && !a_sha && b_sha)) {
        /* Case B: Added in one. */
        if (g_hash_table_lookup(o->current_directory_set, path)) {
            /* directory -> (file, directory), file side. */
            entry->processed = 0;
            return 1;
        } else {
            /* Added in one */
            /* or file -> (file, directory), directory side */
            if (b_sha)
                clean_merge = update_file(o, 1, b_sha, b_mode, b_modifier, b_mtime, path);
            else
                /* For my file, just set index entry to stage 0,
                 * without updating worktree. */
                update_file_flags (o, a_sha, a_mode, a_modifier, a_mtime, path, 1, 0);
        }
    } else if (a_sha && b_sha) {
        /* Case C: Added in both (check for same permissions) and */
        /* case D: Modified in both, but differently. */
        if (memcmp(a_sha, b_sha, 20) != 0 || a_mode != b_mode) {
            char *new_path = NULL;

            clean_merge = 0;

            if (!o->collect_blocks_only) {
                new_path = gen_conflict_path_wrapper (o->repo_id, o->version,
                                                      o->remote_head, path,
                                                      path);
                if (!new_path)
                    new_path = gen_conflict_path(path,
                                                 o->branch2,
                                                 (gint64)time(NULL));
            }

            /* Dont update index. */
            /* Keep my version, rename other's version. */
            update_file_flags(o, b_sha, b_mode, b_modifier, b_mtime, new_path, 0, 1);
            g_free (new_path);
        } else {
            update_file_flags (o, a_sha, a_mode, a_modifier, a_mtime, path, 1, 0);
        }
    } else if (!o_sha && !a_sha && !b_sha) {
        /*
         * this entry was deleted altogether. a_mode == 0 means
         * we had that path and want to actively remove it.
         */
        remove_file(o, 1, path, !a_mode, current_mtime);
    } else
        g_error("Fatal merge failure, shouldn't happen.");

    return clean_merge;
}

static int is_garbage_empty_dir (struct index_state *index, const char *name)
{
    int pos = index_name_pos (index, name, strlen(name));

    /*
     * If pos >= 0, ++pos to the next entry in the index.
     * If pos < 0, -pos = (the position this entry *should* be) + 1.
     * So -pos-1 is the first entry larger than this entry.
     */
    if (pos >= 0)
        pos++;
    else
        pos = -pos-1;

    struct cache_entry *next;
    int this_len = strlen (name);
    while (pos < index->cache_nr) {
        next = index->cache[pos];

        /* If 'name' is the prefix of next->name but they are unequal,
         * it means there are entries under this empty dir. So this "emtpy dir"
         * is useless.
         */
        if (strncmp (name, next->name, this_len) != 0)
            break;
        if (strcmp (name, next->name) != 0)
            return 1;
        ++pos;
    }

    return 0;
}

/*
 * per entry merge function for D/F (and/or rename) conflicts.  In the
 * cases we can cleanly resolve D/F conflicts, process_entry() can
 * clean out all the files below the directory for us.  All D/F
 * conflict cases must be handled here at the end to make sure any
 * directories that can be cleaned out, are.
 */
static int process_df_entry(struct merge_options *o,
                            const char *path,
                            struct stage_data *entry)
{
    int clean_merge = 1;
    unsigned o_mode = entry->stages[1].mode;
    unsigned a_mode = entry->stages[2].mode;
    unsigned b_mode = entry->stages[3].mode;
    unsigned char *o_sha = o_mode ? entry->stages[1].sha : NULL;
    unsigned char *a_sha = a_mode ? entry->stages[2].sha : NULL;
    unsigned char *b_sha = b_mode ? entry->stages[3].sha : NULL;
    guint64 a_mtime = entry->stages[2].mtime;
    guint64 b_mtime = entry->stages[3].mtime;
    char *a_modifier = entry->stages[2].modifier;
    char *b_modifier = entry->stages[3].modifier;
    SeafStat st;
    char *real_path = g_build_path(PATH_SEPERATOR, o->worktree, path, NULL);
    char *new_path = NULL;

    entry->processed = 1;
    if (o_sha && (!a_sha || !b_sha)) {
        /* Modify/delete; deleted side may have put a directory in the way */
        if (b_sha) {
            if (seaf_stat (real_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                /* D/F conflict. */
                clean_merge = 0;

                if (!o->collect_blocks_only) {
                    new_path = gen_conflict_path_wrapper (o->repo_id, o->version,
                                                          o->remote_head, path,
                                                          path);
                    if (!new_path)
                        new_path = gen_conflict_path(path,
                                                     o->branch2,
                                                     (gint64)time(NULL));
                }

                update_file(o, 0, b_sha, b_mode, b_modifier, b_mtime, new_path);
                g_free (new_path);
            } else {
                /* Modify/Delete conflict. Don't consider as unclean. */
                clean_merge = update_file(o, 1, b_sha, b_mode, b_modifier, b_mtime, path);
            }
        } else {
            if (seaf_stat (real_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                clean_merge = 0;
            } else {
                /* Clean merge. Just need to update index. */
                update_file_flags (o, a_sha, a_mode, a_modifier, a_mtime, path, 1, 0);
            }
        }
    } else if (!o_sha && !!a_sha != !!b_sha) {
        unsigned char *sha = a_sha ? a_sha : b_sha;
        unsigned mode = a_sha ? a_mode : b_mode;
        char *modifier = a_sha ? a_modifier : b_modifier;
        guint64 mtime = a_sha ? a_mtime : b_mtime;

        /* directory -> (directory, empty dir) or
         * directory -> (empty dir, directory) */
        if (S_ISDIR(mode)) {
            /* Merge is always clean. If the merge result is non empty dir,
             * remove the empty dir entry from the index.
             */
            if (is_garbage_empty_dir (o->index, path))
                remove_file_from_index (o->index, path);
            else if (a_sha)
                update_file_flags (o, sha, mode, modifier, mtime, path, 1, 0);
            else
                update_file_flags (o, sha, mode, modifier, mtime, path, 1, 1);
            goto out;
        }

        /* directory -> (directory, file) */
        if (b_sha) {
            if (seaf_stat (real_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                /* D/F conflict. */
                clean_merge = 0;

                if (!o->collect_blocks_only) {
                    new_path = gen_conflict_path_wrapper (o->repo_id, o->version,
                                                          o->remote_head, path,
                                                          path);
                    if (!new_path)
                        new_path = gen_conflict_path(path,
                                                     o->branch2,
                                                     (gint64)time(NULL));
                }

                update_file(o, 0, b_sha, b_mode, b_modifier, b_mtime, new_path);
                g_free (new_path);
            } else {
                /* Clean merge. */
                clean_merge = update_file(o, 1, b_sha, b_mode, b_modifier, b_mtime, path);
            }
        } else {
            if (seaf_stat (real_path, &st) == 0 && S_ISDIR(st.st_mode)) {
                clean_merge = 0;
            } else {
                /* Clean merge. Just need to update index. */
                update_file_flags (o, a_sha, a_mode, a_modifier, a_mtime, path, 1, 0);
            }
        }
    } else {
        entry->processed = 0;
        g_free(real_path);
        return 1; /* not handled; assume clean until processed */
    }

out:
    g_free(real_path);
    return clean_merge;
}

#if 0
static void
print_index (struct index_state *istate)
{
    g_message ("Totally %u entries in index.\n", istate->cache_nr);
    int i;
    char id[41];
    for (i = 0; i < istate->cache_nr; ++i) {
        struct cache_entry *ce = istate->cache[i];
        rawdata_to_hex (ce->sha1, id, 20);
        g_message ("%s\t%s\t%o\t%d\t%d\t%d\n", ce->name, id, ce->ce_mode, ce_stage(ce),
                ce->ce_ctime.sec, ce->ce_mtime.sec);
    }

}
#endif

static int
process_unmerged_entries (struct merge_options *o,
                          SeafDir *head,
                          SeafDir *merge)
{
    int clean = 1;

    if (unmerged_index(o->index)) {
        GList *entries, *p;
        g_hash_table_remove_all(o->current_file_set);
        g_hash_table_remove_all(o->current_directory_set);
        get_files_dirs(o, head);
        get_files_dirs(o, merge);

        entries = get_unmerged(o->index);
        /* We don't want to remove any existing file. */
        /* make_room_for_directories_of_df_conflicts(o, entries); */
        for (p = entries; p != NULL; p = p->next) {
            struct stage_data *e = p->data;
            if (!e->processed
                && !process_entry(o, e->path, e))
                clean = 0;
        }
        for (p = entries; p != NULL; p = p->next) {
            struct stage_data *e = p->data;
            if (!e->processed
                && !process_df_entry(o, e->path, e))
                clean = 0;
        }
        for (p = entries; p != NULL; p = p->next) {
            struct stage_data *e = p->data;
            if (!e->processed) {
                g_warning("Unprocessed path??? %s", e->path);
                return 0;
            }
            g_free(e->path);
            int i;
            for (i = 0; i < 4; ++i)
                g_free (e->stages[i].modifier);
            free(e);
        }
        g_list_free(entries);
    }

    return clean;
}

/*
 * Merge the commits h1 and h2, return merged tree root id
 * and a flag indicating the cleanness of the merge.
 * Return 0 if merge is done (no matter clean or not); -1 otherwise.
 */
int merge_recursive(struct merge_options *o,
                    const char *h1_root,
                    const char *h2_root,
                    const char *ca_root,
                    int *clean,
                    char **root_id)
{
    SeafDir *head, *remote, *common;
    int code, ret = 0;
    struct unpack_trees_options opts;
    char *error = NULL;

    *clean = 1;

    head = seaf_fs_manager_get_seafdir (seaf->fs_mgr, o->repo_id, o->version, h1_root);
    remote = seaf_fs_manager_get_seafdir (seaf->fs_mgr, o->repo_id, o->version, h2_root);
    common = seaf_fs_manager_get_seafdir (seaf->fs_mgr, o->repo_id, o->version, ca_root);
    if (!head || !remote || !common) {
        g_warning ("Invalid commits!\n");
        return -1;
    }

    /* Get merged index. */
    code = seafile_merge_trees(o, &opts, common, head, remote, &error);

    if (code != 0) {
        ret = -1;
        goto out;
    }

    /* If only collect blocks, return success. */
    if (o->collect_blocks_only) {
        process_unmerged_entries (o, head, remote);
        goto out;
    }

    /* Update worktree. */
    /* On windows, we have to Check if any files need to be updated
     * are locked by other program (e.g. Office). If no file is locked,
     * update worktree; otherwise just quit.
     * 
     * Note that if we're recovering merge on startup, we need to update
     * worktree no matter files are locked or not, since we cannot retry
     * this operation. This will produce more confusing results, but
     * it doesn't hurt data integrity.
     */
#ifdef WIN32
    if (o->recover_merge || o->force_merge ||
        !files_locked_on_windows (o->index, o->worktree)) {
        update_worktree (&opts, o->recover_merge,
                         o->remote_head, o->branch2, NULL);
        *clean = process_unmerged_entries (o, head, remote);
    } else {
        /* Don't update anything. */
        g_debug ("[merge] files are locked, quit merge now.\n");
        ret = -1;
        goto out;
    }
#else
    update_worktree (&opts, o->recover_merge,
                     o->remote_head, o->branch2, NULL);
    *clean = process_unmerged_entries (o, head, remote);
#endif

    if (*clean) {
        *root_id = write_tree_from_memory(o);
        if (*root_id == NULL)
            ret = -1;
    }

out:
    seaf_dir_free (head);
    seaf_dir_free (remote);
    seaf_dir_free (common);
    return ret;
}

void init_merge_options(struct merge_options *o)
{
    memset(o, 0, sizeof(struct merge_options));
    o->obuf = g_string_new("");
    o->current_file_set = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
    o->current_directory_set = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
}

void clear_merge_options(struct merge_options *o)
{
    g_string_free (o->obuf, TRUE);
    g_hash_table_destroy (o->current_file_set);
    g_hash_table_destroy (o->current_directory_set);
}
