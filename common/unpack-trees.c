/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include "seaf-tree-walk.h"
/* #include "cache-tree.h" */
#include "unpack-trees.h"
/* #include "vc-utils.h" */

static void add_entry(struct unpack_trees_options *o, struct cache_entry *ce,
                      unsigned int set, unsigned int clear)
{
    unsigned int size = ce_size(ce);
    struct cache_entry *new = malloc(size);

    clear |= CE_HASHED | CE_UNHASHED;

    if (set & CE_REMOVE)
        set |= CE_WT_REMOVE;

    memcpy(new, ce, size);
    new->next = NULL;
    new->ce_flags = (new->ce_flags & ~clear) | set;
    add_index_entry(&o->result, new, ADD_CACHE_OK_TO_ADD|ADD_CACHE_OK_TO_REPLACE);
}

/*
 * add error messages on path <path>
 * corresponding to the type <e> with the message <msg>
 * indicating if it should be display in porcelain or not
 */
static int add_rejected_path(struct unpack_trees_options *o,
                             enum unpack_trees_error_types e,
                             const char *path)
{
    o->unpack_rejects[e] = g_list_prepend(o->unpack_rejects[e], g_strdup(path));
    return -1;
}

#if 0
/*
 * Unlink the last component and schedule the leading directories for
 * removal, such that empty directories get removed.
 */
static void unlink_entry(struct cache_entry *ce)
{
    if (!check_leading_path(ce->name, ce_namelen(ce)))
        return;
    if (remove_or_warn(ce->ce_mode, ce->name))
        return;
    schedule_dir_for_removal(ce->name, ce_namelen(ce));
}

static struct checkout state;
static int check_updates(struct unpack_trees_options *o)
{
    unsigned cnt = 0, total = 0;
    struct progress *progress = NULL;
    struct index_state *index = &o->result;
    int i;
    int errs = 0;

    if (o->update && o->verbose_update) {
        for (total = cnt = 0; cnt < index->cache_nr; cnt++) {
            struct cache_entry *ce = index->cache[cnt];
            if (ce->ce_flags & (CE_UPDATE | CE_WT_REMOVE))
                total++;
        }

        progress = start_progress_delay("Checking out files",
                                        total, 50, 1);
        cnt = 0;
    }

    if (o->update)
        git_attr_set_direction(GIT_ATTR_CHECKOUT, &o->result);
    for (i = 0; i < index->cache_nr; i++) {
        struct cache_entry *ce = index->cache[i];

        if (ce->ce_flags & CE_WT_REMOVE) {
            display_progress(progress, ++cnt);
            if (o->update)
                unlink_entry(ce);
            continue;
        }
    }
    remove_marked_cache_entries(&o->result);
    remove_scheduled_dirs();

    for (i = 0; i < index->cache_nr; i++) {
        struct cache_entry *ce = index->cache[i];

        if (ce->ce_flags & CE_UPDATE) {
            display_progress(progress, ++cnt);
            ce->ce_flags &= ~CE_UPDATE;
            if (o->update) {
                errs |= checkout_entry(ce, &state, NULL);
            }
        }
    }
    stop_progress(&progress);
    if (o->update)
        git_attr_set_direction(GIT_ATTR_CHECKIN, NULL);
    return errs != 0;
}
#endif

static inline int call_unpack_fn(struct cache_entry **src, struct unpack_trees_options *o)
{
    int ret = o->fn(src, o);
    if (ret > 0)
        ret = 0;
    return ret;
}

static void mark_ce_used(struct cache_entry *ce, struct unpack_trees_options *o)
{
    ce->ce_flags |= CE_UNPACKED;

    if (o->cache_bottom < o->src_index->cache_nr &&
        o->src_index->cache[o->cache_bottom] == ce) {
        int bottom = o->cache_bottom;
        while (bottom < o->src_index->cache_nr &&
               o->src_index->cache[bottom]->ce_flags & CE_UNPACKED)
            bottom++;
        o->cache_bottom = bottom;
    }
}

static int locate_in_src_index(struct cache_entry *ce,
                               struct unpack_trees_options *o)
{
    struct index_state *index = o->src_index;
    int len = ce_namelen(ce);
    int pos = index_name_pos(index, ce->name, len);
    if (pos < 0)
        pos = -1 - pos;
    return pos;
}

/*
 * We call unpack_index_entry() with an unmerged cache entry
 * only in diff-index, and it wants a single callback.  Skip
 * the other unmerged entry with the same name.
 */
static void mark_ce_used_same_name(struct cache_entry *ce,
                                   struct unpack_trees_options *o)
{
    struct index_state *index = o->src_index;
    int len = ce_namelen(ce);
    int pos;

    for (pos = locate_in_src_index(ce, o); pos < index->cache_nr; pos++) {
        struct cache_entry *next = index->cache[pos];
        if (len != ce_namelen(next) ||
            memcmp(ce->name, next->name, len))
            break;
        mark_ce_used(next, o);
    }
}

static struct cache_entry *next_cache_entry(struct unpack_trees_options *o)
{
    const struct index_state *index = o->src_index;
    int pos = o->cache_bottom;

    while (pos < index->cache_nr) {
        struct cache_entry *ce = index->cache[pos];
        if (!(ce->ce_flags & CE_UNPACKED))
            return ce;
        pos++;
    }
    return NULL;
}

static void add_same_unmerged(struct cache_entry *ce,
                              struct unpack_trees_options *o)
{
    struct index_state *index = o->src_index;
    int len = ce_namelen(ce);
    int pos = index_name_pos(index, ce->name, len);

    if (0 <= pos) {
        g_error("programming error in a caller of mark_ce_used_same_name");
    }
    for (pos = -pos - 1; pos < index->cache_nr; pos++) {
        struct cache_entry *next = index->cache[pos];
        if (len != ce_namelen(next) ||
            memcmp(ce->name, next->name, len))
            break;
        add_entry(o, next, 0, 0);
        mark_ce_used(next, o);
    }
}

static int unpack_index_entry(struct cache_entry *ce,
                              struct unpack_trees_options *o)
{
    struct cache_entry *src[5] = { NULL };
    int ret;

    src[0] = ce;

    mark_ce_used(ce, o);
    if (ce_stage(ce)) {
        if (o->skip_unmerged) {
            add_entry(o, ce, 0, 0);
            return 0;
        }
    }
    ret = call_unpack_fn(src, o);
    if (ce_stage(ce))
        mark_ce_used_same_name(ce, o);
    return ret;
}

static int find_cache_pos(struct traverse_info *, const struct name_entry *);

static void restore_cache_bottom(struct traverse_info *info, int bottom)
{
    struct unpack_trees_options *o = info->data;

    if (o->diff_index_cached)
        return;
    o->cache_bottom = bottom;
}

static int switch_cache_bottom(struct traverse_info *info)
{
    struct unpack_trees_options *o = info->data;
    int ret, pos;

    if (o->diff_index_cached)
        return 0;
    ret = o->cache_bottom;
    pos = find_cache_pos(info->prev, &info->name);

    if (pos < -1)
        o->cache_bottom = -2 - pos;
    else if (pos < 0)
        o->cache_bottom = o->src_index->cache_nr;
    return ret;
}

static int traverse_trees_recursive(int n, unsigned long dirmask, unsigned long df_conflicts, struct name_entry *names, struct traverse_info *info)
{
    int i, ret, bottom;
    struct tree_desc t[MAX_UNPACK_TREES];
    struct traverse_info newinfo;
    struct name_entry *p;

    p = names;
    while (!p->mode)
        p++;

    newinfo = *info;
    newinfo.prev = info;
    newinfo.name = *p;
    newinfo.pathlen += p->pathlen + 1;
    newinfo.conflicts |= df_conflicts;

    for (i = 0; i < n; i++, dirmask >>= 1) {
        char root_id[41];
        if (dirmask & 1) {
            rawdata_to_hex(names[i].sha1, root_id, 20);
            fill_tree_descriptor(t+i, root_id);
        } else {
            fill_tree_descriptor(t+i, NULL);
        }
    }

    bottom = switch_cache_bottom(&newinfo);
    ret = traverse_trees(n, t, &newinfo);
    restore_cache_bottom(&newinfo, bottom);

    for (i = 0; i < n; ++i) {
        tree_desc_free (&t[i]);
    }

    return ret;
}

/*
 * Compare the traverse-path to the cache entry without actually
 * having to generate the textual representation of the traverse
 * path.
 *
 * NOTE! This *only* compares up to the size of the traverse path
 * itself - the caller needs to do the final check for the cache
 * entry having more data at the end!
 */
static int do_compare_entry(const struct cache_entry *ce, const struct traverse_info *info, const struct name_entry *n)
{
    int len, pathlen, ce_len;
    const char *ce_name;

    if (info->prev) {
        int cmp = do_compare_entry(ce, info->prev, &info->name);
        if (cmp)
            return cmp;
    }
    pathlen = info->pathlen;
    ce_len = ce_namelen(ce);

    /* If ce_len < pathlen then we must have previously hit "name == directory" entry */
    if (ce_len < pathlen)
        return -1;

    ce_len -= pathlen;
    ce_name = ce->name + pathlen;

    len = n->pathlen;
    return df_name_compare(ce_name, ce_len, S_IFREG, n->path, len, n->mode);
}

static int compare_entry(const struct cache_entry *ce, const struct traverse_info *info, const struct name_entry *n)
{
    int cmp = do_compare_entry(ce, info, n);
    if (cmp)
        return cmp;

    /*
     * Even if the beginning compared identically, the ce should
     * compare as bigger than a directory leading up to it!
     */
    return ce_namelen(ce) > traverse_path_len(info, n);
}

static int ce_in_traverse_path(const struct cache_entry *ce,
                               const struct traverse_info *info)
{
    if (!info->prev)
        return 1;
    if (do_compare_entry(ce, info->prev, &info->name))
        return 0;
    /*
     * If ce (blob) is the same name as the path (which is a tree
     * we will be descending into), it won't be inside it.
     */
    return (info->pathlen < ce_namelen(ce));
}

static struct cache_entry *create_ce_entry(const struct traverse_info *info, const struct name_entry *n, int stage)
{
    int len = traverse_path_len(info, n);
    struct cache_entry *ce = calloc(1, cache_entry_size(len));

    ce->ce_mode = create_ce_mode(n->mode);
    ce->ce_flags = create_ce_flags(len, stage);
    hashcpy(ce->sha1, n->sha1);
    make_traverse_path(ce->name, info, n);

    return ce;
}

static int unpack_nondirectories(int n, unsigned long mask,
                                 unsigned long dirmask,
                                 struct cache_entry **src,
                                 const struct name_entry *names,
                                 const struct traverse_info *info)
{
    int i;
    struct unpack_trees_options *o = info->data;
    unsigned long conflicts;

    /* Do we have *only* directories? Nothing to do */
    if (mask == dirmask && !src[0])
        return 0;

    conflicts = info->conflicts;
    if (o->merge)
        conflicts >>= 1;
    conflicts |= dirmask;

    /*
     * Ok, we've filled in up to any potential index entry in src[0],
     * now do the rest.
     */
    for (i = 0; i < n; i++) {
        int stage;
        unsigned int bit = 1ul << i;
        if (conflicts & bit) {
            src[i + o->merge] = o->df_conflict_entry;
            continue;
        }
        if (!(mask & bit))
            continue;
        if (!o->merge)
            stage = 0;
        else if (i + 1 < o->head_idx)
            stage = 1;
        else if (i + 1 > o->head_idx)
            stage = 3;
        else
            stage = 2;
        src[i + o->merge] = create_ce_entry(info, names + i, stage);
    }

    if (o->merge) {
        int ret = call_unpack_fn(src, o);
        for (i = 1; i <= n; i++)
            if (src[i] && src[i] != o->df_conflict_entry) 
                free(src[i]);
        return ret;
    }

    for (i = 0; i < n; i++)
        if (src[i] && src[i] != o->df_conflict_entry)
            add_entry(o, src[i], 0, 0);
    return 0;
}

/* NEEDSWORK: give this a better name and share with tree-walk.c */
static int name_compare(const char *a, int a_len,
                        const char *b, int b_len)
{
    int len = (a_len < b_len) ? a_len : b_len;
    int cmp = memcmp(a, b, len);
    if (cmp)
        return cmp;
    return (a_len - b_len);
}

/*
 * The tree traversal is looking at name p.  If we have a matching entry,
 * return it.  If name p is a directory in the index, do not return
 * anything, as we will want to match it when the traversal descends into
 * the directory.
 */
static int find_cache_pos(struct traverse_info *info,
                          const struct name_entry *p)
{
    int pos;
    struct unpack_trees_options *o = info->data;
    struct index_state *index = o->src_index;
    int pfxlen = info->pathlen;
    int p_len = p->pathlen;

    for (pos = o->cache_bottom; pos < index->cache_nr; pos++) {
        struct cache_entry *ce = index->cache[pos];
        const char *ce_name, *ce_slash;
        int cmp, ce_len;

        if (ce->ce_flags & CE_UNPACKED) {
            /*
             * cache_bottom entry is already unpacked, so
             * we can never match it; don't check it
             * again.
             */
            if (pos == o->cache_bottom)
                ++o->cache_bottom;
            continue;
        }
        if (!ce_in_traverse_path(ce, info))
            continue;
        ce_name = ce->name + pfxlen;
        ce_slash = strchr(ce_name, '/');
        if (ce_slash)
            ce_len = ce_slash - ce_name;
        else
            ce_len = ce_namelen(ce) - pfxlen;
        cmp = name_compare(p->path, p_len, ce_name, ce_len);
        /*
         * Exact match; if we have a directory we need to
         * delay returning it.
         */
        if (!cmp)
            return ce_slash ? -2 - pos : pos;
        if (0 < cmp)
            continue; /* keep looking */
        /*
         * ce_name sorts after p->path; could it be that we
         * have files under p->path directory in the index?
         * E.g.  ce_name == "t-i", and p->path == "t"; we may
         * have "t/a" in the index.
         */
        if (p_len < ce_len && !memcmp(ce_name, p->path, p_len) &&
            ce_name[p_len] < '/')
            continue; /* keep looking */
        break;
    }
    return -1;
}

static struct cache_entry *find_cache_entry(struct traverse_info *info,
                                            const struct name_entry *p)
{
    int pos = find_cache_pos(info, p);
    struct unpack_trees_options *o = info->data;

    if (0 <= pos)
        return o->src_index->cache[pos];
    else
        return NULL;
}

static void debug_path(struct traverse_info *info)
{
    if (info->prev) {
        debug_path(info->prev);
        if (*info->prev->name.path)
            putchar('/');
    }
    printf("%s", info->name.path);
}

static void debug_name_entry(int i, struct name_entry *n)
{
    printf("ent#%d %06o %s\n", i,
           n->path ? n->mode : 0,
           n->path ? n->path : "(missing)");
}

static void debug_unpack_callback(int n,
                                  unsigned long mask,
                                  unsigned long dirmask,
                                  struct name_entry *names,
                                  struct traverse_info *info)
{
    int i;
    printf("* unpack mask %lu, dirmask %lu, cnt %d ",
           mask, dirmask, n);
    debug_path(info);
    putchar('\n');
    for (i = 0; i < n; i++)
        debug_name_entry(i, names + i);
}

static int unpack_callback(int n, unsigned long mask, unsigned long dirmask, struct name_entry *names, struct traverse_info *info)
{
    struct cache_entry *src[MAX_UNPACK_TREES + 1] = { NULL, };
    struct unpack_trees_options *o = info->data;
    const struct name_entry *p = names;

    /* Find first entry with a real name (we could use "mask" too) */
    while (!p->mode)
        p++;

    if (o->debug_unpack)
        debug_unpack_callback(n, mask, dirmask, names, info);

    /* Are we supposed to look at the index too? */
    if (o->merge) {
        while (1) {
            int cmp;
            struct cache_entry *ce;

            if (o->diff_index_cached)
                ce = next_cache_entry(o);
            else
                ce = find_cache_entry(info, p);

            if (!ce)
                break;
            cmp = compare_entry(ce, info, p);
            if (cmp < 0) {
                if (unpack_index_entry(ce, o) < 0)
                    return -1;
                continue;
            }
            if (!cmp) {
                if (ce_stage(ce)) {
                    /*
                     * If we skip unmerged index
                     * entries, we'll skip this
                     * entry *and* the tree
                     * entries associated with it!
                     */
                    if (o->skip_unmerged) {
                        add_same_unmerged(ce, o);
                        return mask;
                    }
                }
                src[0] = ce;
            }
            break;
        }
    }

    if (unpack_nondirectories(n, mask, dirmask, src, names, info) < 0)
        return -1;

    if (src[0]) {
        if (ce_stage(src[0]))
            mark_ce_used_same_name(src[0], o);
        else
            mark_ce_used(src[0], o);
    }

    /* Now handle any directories.. */
    if (dirmask) {
        unsigned long conflicts = mask & ~dirmask;
        if (o->merge) {
            conflicts <<= 1;
            if (src[0])
                conflicts |= 1;
        }

        /*
         * This is an optimization that relies on cache tree.
         * Skip it for now.
         */
#if 0
        /* special case: "diff-index --cached" looking at a tree */
        if (o->diff_index_cached &&
            n == 1 && dirmask == 1 && S_ISDIR(names->mode)) {
            int matches;
            matches = cache_tree_matches_traversal(o->src_index->cache_tree,
                                                   names, info);
            /*
             * Everything under the name matches; skip the
             * entire hierarchy.  diff_index_cached codepath
             * special cases D/F conflicts in such a way that
             * it does not do any look-ahead, so this is safe.
             */
            if (matches) {
                o->cache_bottom += matches;
                return mask;
            }
        }
#endif

        if (traverse_trees_recursive(n, dirmask, conflicts,
                                     names, info) < 0)
            return -1;
        return mask;
    }

    return mask;
}

static void setup_traverse_info(struct traverse_info *info, const char *base)
{
    int pathlen = strlen(base);
    static struct traverse_info dummy;

    memset(info, 0, sizeof(*info));
    if (pathlen && base[pathlen-1] == '/')
        pathlen--;
    info->pathlen = pathlen ? pathlen + 1 : 0;
    info->name.path = base;
    /* info->name.sha1 = NULL; */
    if (pathlen)
        info->prev = &dummy;
}

int unpack_trees(unsigned len, struct tree_desc *t, struct unpack_trees_options *o)
{
    int ret = 0;
    static struct cache_entry *dfc;

    memset(&o->result, 0, sizeof(o->result));
    o->result.initialized = 1;
    o->result.timestamp.sec = o->src_index->timestamp.sec;
    o->result.timestamp.nsec = o->src_index->timestamp.nsec;
    o->merge_size = len;
    mark_all_ce_unused(o->src_index);

    if (!dfc)
        dfc = calloc(1, cache_entry_size(0));
    o->df_conflict_entry = dfc;

    if (len) {
        struct traverse_info info;

        setup_traverse_info(&info, "");
        info.fn = unpack_callback;
        info.data = o;
        info.show_all_errors = o->show_all_errors;

        if (traverse_trees(len, t, &info) < 0)
            goto return_failed;
    }

    /* Any left-over entries in the index? */
    if (o->merge) {
        while (1) {
            struct cache_entry *ce = next_cache_entry(o);
            if (!ce)
                break;
            if (unpack_index_entry(ce, o) < 0)
                goto return_failed;
        }
    }
    mark_all_ce_unused(o->src_index);

    if (o->trivial_merges_only && o->nontrivial_merge) {
        ret = -1;
    }

    /* o->src_index = NULL; */
    /* ret = check_updates(o) ? (-2) : 0; */
    /* if (o->dst_index) */
    /*      *o->dst_index = o->result; */

done:
    return ret;

return_failed:
    /* if (o->show_all_errors) */
    /*      display_error_msgs(o); */
    mark_all_ce_unused(o->src_index);
    ret = -1;
    goto done;
}

/* Here come the merge functions */

static int reject_merge(struct cache_entry *ce, struct unpack_trees_options *o)
{
    return add_rejected_path(o, ERROR_WOULD_OVERWRITE, ce->name);
}

static int same(struct cache_entry *a, struct cache_entry *b)
{
    if (!!a != !!b)
        return 0;
    if (!a && !b)
        return 1;
    if ((a->ce_flags | b->ce_flags) & CE_CONFLICTED)
        return 0;
    return a->ce_mode == b->ce_mode &&
        !hashcmp(a->sha1, b->sha1);
}


/*
 * When a CE gets turned into an unmerged entry, we
 * want it to be up-to-date
 */
static int verify_uptodate_1(struct cache_entry *ce,
                             struct unpack_trees_options *o,
                             enum unpack_trees_error_types error_type)
{
#if 0
    char full_path[SEAF_PATH_MAX];
    struct stat st;

    if (o->index_only || (!((ce->ce_flags & CE_VALID) || ce_skip_worktree(ce)) && (o->reset || ce_uptodate(ce))))
        return 0;

    snprintf(full_path, SEAF_PATH_MAX, "%s/%s", o->base, ce->name);
    if (!g_lstat (full_path, &st)) {
        unsigned changed = ie_match_stat(o->src_index, ce, &st, CE_MATCH_IGNORE_VALID|CE_MATCH_IGNORE_SKIP_WORKTREE);
        if (!changed)
            return 0;
        /*
         * NEEDSWORK: the current default policy is to allow
         * submodule to be out of sync wrt the supermodule
         * index.  This needs to be tightened later for
         * submodules that are marked to be automatically
         * checked out.
         */
        if (S_ISGITLINK(ce->ce_mode))
            return 0;
        errno = 0;
    }
    if (errno == ENOENT)
        return 0;
    return o->gently ? -1 :
        add_rejected_path(o, error_type, ce->name);
#endif
    return 0;
}

static int verify_uptodate(struct cache_entry *ce,
                           struct unpack_trees_options *o)
{
    /* if (!o->skip_sparse_checkout && (ce->ce_flags & CE_NEW_SKIP_WORKTREE)) */
    /*      return 0; */
    return verify_uptodate_1(ce, o, ERROR_NOT_UPTODATE_FILE);
}

static void invalidate_ce_path(struct cache_entry *ce, struct unpack_trees_options *o)
{
#if 0
    if (ce)
        cache_tree_invalidate_path(o->src_index->cache_tree, ce->name);
#endif
}

#if 0
/*
 * Check that checking out ce->sha1 in subdir ce->name is not
 * going to overwrite any working files.
 *
 * Currently, git does not checkout subprojects during a superproject
 * checkout, so it is not going to overwrite anything.
 */
static int verify_clean_submodule(struct cache_entry *ce,
                                  enum unpack_trees_error_types error_type,
                                  struct unpack_trees_options *o)
{
    return 0;
}

static int verify_clean_subdirectory(struct cache_entry *ce,
                                     enum unpack_trees_error_types error_type,
                                     struct unpack_trees_options *o)
{
    /*
     * we are about to extract "ce->name"; we would not want to lose
     * anything in the existing directory there.
     */
    int namelen;
    int i;
    struct dir_struct d;
    char *pathbuf;
    int cnt = 0;
    unsigned char sha1[20];

    /*
     * First let's make sure we do not have a local modification
     * in that directory.
     */
    namelen = strlen(ce->name);
    for (i = locate_in_src_index(ce, o);
         i < o->src_index->cache_nr;
         i++) {
        struct cache_entry *ce2 = o->src_index->cache[i];
        int len = ce_namelen(ce2);
        if (len < namelen ||
            strncmp(ce->name, ce2->name, namelen) ||
            ce2->name[namelen] != '/')
            break;
        /*
         * ce2->name is an entry in the subdirectory to be
         * removed.
         */
        if (!ce_stage(ce2)) {
            if (verify_uptodate(ce2, o))
                return -1;
            add_entry(o, ce2, CE_REMOVE, 0);
            mark_ce_used(ce2, o);
        }
        cnt++;
    }

    /*
     * Then we need to make sure that we do not lose a locally
     * present file that is not ignored.
     */
    pathbuf = malloc(namelen + 2);
    memcpy(pathbuf, ce->name, namelen);
    strcpy(pathbuf+namelen, "/");

    memset(&d, 0, sizeof(d));
    i = read_directory(&d, pathbuf, namelen+1, NULL);
    if (i)
        return o->gently ? -1 :
            add_rejected_path(o, ERROR_NOT_UPTODATE_DIR, ce->name);
    free(pathbuf);
    return cnt;
}

static int check_ok_to_remove(const char *name, int len, int dtype,
                              struct cache_entry *ce, struct stat *st,
                              enum unpack_trees_error_types error_type,
                              struct unpack_trees_options *o)
{
    struct cache_entry *result;

    if (S_ISDIR(st->st_mode)) {
        /*
         * We are checking out path "foo" and
         * found "foo/." in the working tree.
         * This is tricky -- if we have modified
         * files that are in "foo/" we would lose
         * them.
         */
        if (verify_clean_subdirectory(ce, error_type, o) < 0)
            return -1;
        return 0;
    }

    /*
     * The previous round may already have decided to
     * delete this path, which is in a subdirectory that
     * is being replaced with a blob.
     */
    result = index_name_exists(&o->result, name, len, 0);
    if (result) {
        if (result->ce_flags & CE_REMOVE)
            return 0;
    }

    return o->gently ? -1 :
        add_rejected_path(o, error_type, name);
}
#endif

/*
 * We do not want to remove or overwrite a working tree file that
 * is not tracked, unless it is ignored.
 */
static int verify_absent_1(struct cache_entry *ce,
                           enum unpack_trees_error_types error_type,
                           struct unpack_trees_options *o)
{
#if 0
    char full_path[SEAF_PATH_MAX];
    struct stat st;

    if (o->index_only || o->reset || !o->update)
        return 0;

    snprintf (full_path, SEAF_PATH_MAX, "%s/%s", o->base, ce->name);
    if (!g_lstat (full_path, &st) && S_ISREG(st.st_mode))
        return o->gently ? -1:
            add_rejected_path(o, error_type, ce->name);
    /* return check_ok_to_remove(ce->name, ce_namelen(ce), */
    /*              ce_to_dtype(ce), ce, &st, */
    /*              error_type, o); */
#endif
    return 0;
}

static int verify_absent(struct cache_entry *ce,
                         enum unpack_trees_error_types error_type,
                         struct unpack_trees_options *o)
{
    /* if (!o->skip_sparse_checkout && (ce->ce_flags & CE_NEW_SKIP_WORKTREE)) */
    /*      return 0; */
    return verify_absent_1(ce, error_type, o);
}

static int merged_entry(struct cache_entry *merge, struct cache_entry *old,
                        struct unpack_trees_options *o)
{
    int update = CE_UPDATE;

    if (!old) {
        /*
         * New index entries. In sparse checkout, the following
         * verify_absent() will be delayed until after
         * traverse_trees() finishes in unpack_trees(), then:
         *
         *  - CE_NEW_SKIP_WORKTREE will be computed correctly
         *  - verify_absent() be called again, this time with
         *    correct CE_NEW_SKIP_WORKTREE
         *
         * verify_absent() call here does nothing in sparse
         * checkout (i.e. o->skip_sparse_checkout == 0)
         */
        update |= CE_ADDED;
        /* merge->ce_flags |= CE_NEW_SKIP_WORKTREE; */

        if (verify_absent(merge, ERROR_WOULD_LOSE_UNTRACKED_OVERWRITTEN, o))
            return -1;
        invalidate_ce_path(merge, o);
    } else if (!(old->ce_flags & CE_CONFLICTED)) {
        /*
         * See if we can re-use the old CE directly?
         * That way we get the uptodate stat info.
         *
         * This also removes the UPDATE flag on a match; otherwise
         * we will end up overwriting local changes in the work tree.
         */
        if (same(old, merge)) {
            copy_cache_entry(merge, old);
            update = 0;
        } else {
            if (verify_uptodate(old, o))
                return -1;
            /* Migrate old flags over */
            /* update |= old->ce_flags & (CE_SKIP_WORKTREE | CE_NEW_SKIP_WORKTREE); */
            invalidate_ce_path(old, o);
        }
    } else {
        /*
         * Previously unmerged entry left as an existence
         * marker by read_index_unmerged();
         */
        invalidate_ce_path(old, o);
    }

    /* We need timestamp when checking out the file later. */
    if (old) {
        merge->ce_ctime = old->ce_ctime;
        merge->ce_mtime = old->ce_mtime;
    }

    add_entry(o, merge, update, CE_STAGEMASK);
    return 1;
}

static int deleted_entry(struct cache_entry *ce, struct cache_entry *old,
                         struct unpack_trees_options *o)
{
    /* Did it exist in the index? */
    if (!old) {
        if (verify_absent(ce, ERROR_WOULD_LOSE_UNTRACKED_REMOVED, o))
            return -1;
        return 0;
    }
    if (!(old->ce_flags & CE_CONFLICTED) && verify_uptodate(old, o))
        return -1;

    /* We need timestamp when checking out the file later. */
    if (old) {
        ce->ce_ctime = old->ce_ctime;
        ce->ce_mtime = old->ce_mtime;
    }

    add_entry(o, ce, CE_REMOVE, CE_STAGEMASK);
    invalidate_ce_path(ce, o);
    return 1;
}

static int keep_entry(struct cache_entry *ce, struct unpack_trees_options *o)
{
    add_entry(o, ce, 0, 0);
    return 1;
}

#if DBRT_DEBUG
static void show_stage_entry(FILE *o,
                             const char *label, const struct cache_entry *ce)
{
    if (!ce)
        fprintf(o, "%s (missing)\n", label);
    else
        fprintf(o, "%s%06o %s %d\t%s\n",
                label,
                ce->ce_mode,
                sha1_to_hex(ce->sha1),
                ce_stage(ce),
                ce->name);
}
#endif

int threeway_merge(struct cache_entry **stages, struct unpack_trees_options *o)
{
    struct cache_entry *index;
    struct cache_entry *head;
    struct cache_entry *remote = stages[o->head_idx + 1];
    int count;
    int head_match = 0;
    int remote_match = 0;

    int df_conflict_head = 0;
    int df_conflict_remote = 0;

    int any_anc_missing = 0;
    int no_anc_exists = 1;
    int i;

    for (i = 1; i < o->head_idx; i++) {
        if (!stages[i] || stages[i] == o->df_conflict_entry)
            any_anc_missing = 1;
        else
            no_anc_exists = 0;
    }

    index = stages[0];
    head = stages[o->head_idx];

    if (head == o->df_conflict_entry) {
        df_conflict_head = 1;
        head = NULL;
    }

    if (remote == o->df_conflict_entry) {
        df_conflict_remote = 1;
        remote = NULL;
    }

    /*
     * First, if there's a #16 situation, note that to prevent #13
     * and #14.
     */
    if (!same(remote, head)) {
        for (i = 1; i < o->head_idx; i++) {
            if (same(stages[i], head)) {
                head_match = i;
            }
            if (same(stages[i], remote)) {
                remote_match = i;
            }
        }
    }

    /*
     * We start with cases where the index is allowed to match
     * something other than the head: #14(ALT) and #2ALT, where it
     * is permitted to match the result instead.
     */
    /* #14, #14ALT, #2ALT */
    if (remote && !df_conflict_head && head_match && !remote_match) {
        /* if (index && !same(index, remote) && !same(index, head)) */
        /*     return o->gently ? -1 : reject_merge(index, o); */
        return merged_entry(remote, index, o);
    }
    /*
     * If we have an entry in the index cache, then we want to
     * make sure that it matches head.
     */
    /* if (index && !same(index, head)) */
    /*     return o->gently ? -1 : reject_merge(index, o); */

    if (head) {
        /* #5ALT, #15 */
        if (same(head, remote))
            return merged_entry(head, index, o);
        /* #13, #3ALT */
        if (!df_conflict_remote && remote_match && !head_match)
            return merged_entry(head, index, o);
    }

    /* #1 */
    if (!head && !remote && any_anc_missing)
        return 0;

    /*
     * Under the "aggressive" rule, we resolve mostly trivial
     * cases that we historically had git-merge-one-file resolve.
     */
    if (o->aggressive) {
        int head_deleted = !head;
        int remote_deleted = !remote;
        struct cache_entry *ce = NULL;

        if (index)
            ce = index;
        else if (head)
            ce = head;
        else if (remote)
            ce = remote;
        else {
            for (i = 1; i < o->head_idx; i++) {
                if (stages[i] && stages[i] != o->df_conflict_entry) {
                    ce = stages[i];
                    break;
                }
            }
        }

        /*
         * Deleted in both.
         * Deleted in one and unchanged in the other.
         */
        if ((head_deleted && remote_deleted) ||
            (head_deleted && remote && remote_match) ||
            (remote_deleted && head && head_match)) {
            if (index)
                return deleted_entry(index, index, o);
            if (ce && !head_deleted) {
                if (verify_absent(ce, ERROR_WOULD_LOSE_UNTRACKED_REMOVED, o))
                    return -1;
            }
            return 0;
        }
        /*
         * Added in both, identically.
         */
        if (no_anc_exists && head && remote && same(head, remote))
            return merged_entry(head, index, o);

    }

    /* Below are "no merge" cases, which require that the index be
     * up-to-date to avoid the files getting overwritten with
     * conflict resolution files.
     */
    if (index) {
        if (verify_uptodate(index, o))
            return -1;
    }

    o->nontrivial_merge = 1;

    /* #2, #3, #4, #6, #7, #9, #10, #11. */
    count = 0;
    if (!head_match || !remote_match) {
        for (i = 1; i < o->head_idx; i++) {
            if (stages[i] && stages[i] != o->df_conflict_entry) {
                keep_entry(stages[i], o);
                count++;
                break;
            }
        }
    }
#if DBRT_DEBUG
    else {
        fprintf(stderr, "read-tree: warning #16 detected\n");
        show_stage_entry(stderr, "head   ", stages[head_match]);
        show_stage_entry(stderr, "remote ", stages[remote_match]);
    }
#endif

    /* We need ctime and mtime of index to handle worktree conflict later. */
    if (head && index) {
        head->ce_ctime = index->ce_ctime;
        head->ce_mtime = index->ce_mtime;
    }

    if (head) { count += keep_entry(head, o); }
    if (remote) { count += keep_entry(remote, o); }
    return count;
}

/*
 * Two-way merge.
 *
 * The rule is to "carry forward" what is in the index without losing
 * information across a "fast-forward", favoring a successful merge
 * over a merge failure when it makes sense.  For details of the
 * "carry forward" rule, please see <Documentation/git-read-tree.txt>.
 *
 */
int twoway_merge(struct cache_entry **src, struct unpack_trees_options *o)
{
    struct cache_entry *current = src[0];
    struct cache_entry *oldtree = src[1];
    struct cache_entry *newtree = src[2];

    if (o->merge_size != 2) {
        g_warning ("Cannot do a twoway merge of %d trees", o->merge_size);
        return -1;
    }

    if (oldtree == o->df_conflict_entry)
        oldtree = NULL;
    if (newtree == o->df_conflict_entry)
        newtree = NULL;

    if (current) {
        if ((!oldtree && !newtree) || /* 4 and 5 */
            (!oldtree && newtree &&
             same(current, newtree)) || /* 6 and 7 */
            (oldtree && newtree &&
             same(oldtree, newtree)) || /* 14 and 15 */
            (oldtree && newtree &&
             !same(oldtree, newtree) && /* 18 and 19 */
             same(current, newtree))) {
            return keep_entry(current, o);
        }
        else if (oldtree && !newtree && same(current, oldtree)) {
            /* 10 or 11 */
            return deleted_entry(oldtree, current, o);
        }
        else if (oldtree && newtree &&
                 same(current, oldtree) && !same(current, newtree)) {
            /* 20 or 21 */
            return merged_entry(newtree, current, o);
        }
        else {
            /* all other failures */
            if (oldtree)
                return o->gently ? -1 : reject_merge(oldtree, o);
            if (current)
                return o->gently ? -1 : reject_merge(current, o);
            if (newtree)
                return o->gently ? -1 : reject_merge(newtree, o);
            return -1;
        }
    }
    else if (newtree) {
        if (oldtree && !o->initial_checkout) {
            /*
             * deletion of the path was staged;
             */
            if (same(oldtree, newtree))
                return 1;
            return reject_merge(oldtree, o);
        }
        return merged_entry(newtree, current, o);
    }
    return deleted_entry(oldtree, current, o);
}

/*
 * One-way merge.
 *
 * The rule is:
 * - take the stat information from stage0, take the data from stage1
 */
int oneway_merge(struct cache_entry **src, struct unpack_trees_options *o)
{
    struct cache_entry *old = src[0];
    struct cache_entry *a = src[1];

    if (o->merge_size != 1) {
        g_warning("Cannot do a oneway merge of %d trees",
                  o->merge_size);
        return -1;
    }

    if (!a || a == o->df_conflict_entry)
        return deleted_entry(old, old, o);

    if (old && same(old, a)) {
        int update = 0;
        if (o->reset && !ce_uptodate(old) && !ce_skip_worktree(old)) {
            struct stat st;
            char full_path[SEAF_PATH_MAX];
            snprintf (full_path, SEAF_PATH_MAX, "%s/%s", o->base, old->name);
            if (g_lstat (full_path, &st) ||
                ie_match_stat(o->src_index, old, &st, CE_MATCH_IGNORE_VALID|CE_MATCH_IGNORE_SKIP_WORKTREE))
                update |= CE_UPDATE;
        }
        add_entry(o, old, update, 0);
        return 0;
    }
    return merged_entry(a, old, o);
}

static const char *unpack_errors[NB_UNPACK_TREES_ERROR_TYPES] = {
    /* ERROR_WOULD_OVERWRITE */
    "%s: Local changes would be overwritten. Cannot %s.\n",

    /* ERROR_NOT_UPTODATE_FILE */
    "%s: Local changes would be overwritten. Cannot %s.\n",

    /* ERROR_NOT_UPTODATE_DIR */
    "%s: Untracked files in this directory would be lost. Cannot %s.\n",

    /* ERROR_WOULD_LOSE_UNTRACKED_OVERWRITTEN */
    "%s: This file is untracked and would be overwritten. Cannot %s.\n",

    /* ERROR_WOULD_LOSE_UNTRACKED_REMOVED */
    "%s: This file is untracked and would be removed. Cannot %s.\n",
};

static const char *opr_str[N_OPR_TYPES] = {
    "checkout",
    "merge",
};

gboolean
get_unpack_trees_error_msgs(struct unpack_trees_options *o, GString *msgbuf, int opr_type)
{
    int e;
    gboolean has_error = FALSE;
    for (e = 0; e < NB_UNPACK_TREES_ERROR_TYPES; e++) {
        GList *rejects = o->unpack_rejects[e];
        GList *rej;
        if (rejects) {
            has_error = TRUE;
            for (rej = rejects; rej; rej = rej->next)
                g_string_append_printf (msgbuf,
                                        unpack_errors[e],
                                        (char *) (rej->data),
                                        opr_str[opr_type]);
            /*
             * Dont need to free strings in the list.
             * They're in ce->name, which will be freeed later.
             */
            string_list_free (rejects);
        }
    }
    return has_error;
}
