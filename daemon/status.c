#include "common.h"
#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "seafile-session.h"
#include "status.h"
#include "fs-mgr.h"
#include "index/index.h"
#include "diff-simple.h"
#include "vc-utils.h"
#include "utils.h"
#include "cdc/cdc.h"

void wt_status_collect_untracked(struct index_state *index,
                                 GList **results,
                                 const char *worktree,
                                 IgnoreFunc ignore_func)
{
    int i;
    struct dir_struct dir;
    DiffEntry *de;

    memset(&dir, 0, sizeof(dir));

    read_directory(&dir, worktree, index);
    for (i = 0; i < dir.nr; i++) {
        struct dir_entry *ent = dir.entries[i];

        if (!ignore_func(ent->name, NULL)) {
            unsigned char sha1[20] = { 0 };
            de = diff_entry_new (DIFF_TYPE_WORKTREE, DIFF_STATUS_ADDED, sha1, ent->name);
            *results = g_list_prepend (*results, de);
        }
        free(ent);
    }

    free(dir.entries);
}

static gboolean
is_empty_dir (const char *path, IgnoreFunc should_ignore)
{
    GDir *dir;
    const char *dname;

    dir = g_dir_open (path, 0, NULL);
    if (!dir) {
        g_warning ("Failed to open dir %s: %s.\n", path, strerror(errno));
        return FALSE;
    }

    int n = 0;
    while ((dname = g_dir_read_name(dir)) != NULL) {
        if (should_ignore(dname, NULL))
            continue;
        ++n;
    }
    g_dir_close (dir);

    return (n == 0);
}

void wt_status_collect_changes_worktree(struct index_state *index,
                                        GList **results,
                                        const char *worktree,
                                        IgnoreFunc ignore_func)
{
    DiffEntry *de;
    int entries, i;

    entries = index->cache_nr;
    for (i = 0; i < entries; i++) {
        char *realpath;
        struct stat st;
        struct cache_entry *ce = index->cache[i];
        int changed = 0;

        if (ce_stage(ce)) {
            int mask = 0;

            mask |= 1 << ce_stage(ce);
            while (i < entries) {
                struct cache_entry *nce = index->cache[i];

                if (strcmp(ce->name, nce->name))
                    break;

                mask |= 1 << ce_stage(nce);
                i++;
            }

            /*
             * Compensate for loop update
             */
            i--;

            de = diff_entry_new (DIFF_TYPE_WORKTREE, DIFF_STATUS_UNMERGED,
                                 ce->sha1, ce->name);
            de->unmerge_state = diff_unmerged_state (mask);
            *results = g_list_prepend (*results, de);

            continue;
        }

        if (ce_uptodate(ce) || ce_skip_worktree(ce))
            continue;

        realpath = g_build_path (PATH_SEPERATOR, worktree, ce->name, NULL);
        if (g_lstat(realpath, &st) < 0) {
            if (errno != ENOENT && errno != ENOTDIR)
                changed = -1;
            changed = 1;
        }

        if (changed) {
            if (changed < 0) {
                g_warning ("Faile to stat %s: %s\n", ce->name, strerror(errno));
                g_free (realpath);
                continue;
            }

            de = diff_entry_new (DIFF_TYPE_WORKTREE, DIFF_STATUS_DELETED,
                                 ce->sha1, ce->name);
            *results = g_list_prepend (*results, de);
            g_free (realpath);
            continue;
        }

        if (S_ISDIR (ce->ce_mode)) {
            if (!S_ISDIR (st.st_mode) ||
                !is_empty_dir (realpath, ignore_func)) {
                de = diff_entry_new (DIFF_TYPE_WORKTREE, DIFF_STATUS_DIR_DELETED,
                                     ce->sha1, ce->name);
                *results = g_list_prepend (*results, de);
            }
            g_free (realpath);
            continue;
        }
        g_free (realpath);

        changed = ie_match_stat (index, ce, &st, 0);
        if (!changed) {
            ce_mark_uptodate (ce);
            continue;
        }

        de = diff_entry_new (DIFF_TYPE_WORKTREE, DIFF_STATUS_MODIFIED,
                             ce->sha1, ce->name);
        *results = g_list_prepend (*results, de);
    }
}

static struct cache_entry *
next_cache_entry(struct index_state *index, int *pos)
{
    while (*pos < index->cache_nr) {
        struct cache_entry *ce = index->cache[*pos];
        (*pos)++;
        if (!(ce->ce_flags & CE_UNPACKED))
            return ce;
    }
    return NULL;
}

void
wt_status_collect_changes_index (struct index_state *index,
                                 GList **results,
                                 SeafRepo *repo)
{
    SeafFSManager *fs_mgr;
    SeafCommit *head;
    int pos = 0;
    DiffEntry *de;

    fs_mgr = repo->manager->seaf->fs_mgr;
    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
            repo->head->commit_id);

    mark_all_ce_unused (index);

    /* if repo is initial, we don't need to check index changes */
    if (strncmp(EMPTY_SHA1, head->root_id, 40) != 0) {
        SeafDir *root;

        /* call diff_index to get status */
        root = seaf_fs_manager_get_seafdir (fs_mgr, head->root_id);
        if (diff_index(index, root, results) < 0)
            g_warning("diff index failed\n");
        seaf_dir_free (root);
        seaf_commit_unref (head);
        return;
    }
    seaf_commit_unref (head);

    while (1) {
        struct cache_entry *ce = next_cache_entry(index, &pos);

        if (!ce || ce_stage(ce))
            break;

        ce->ce_flags |= CE_UNPACKED;
        de = diff_entry_new (DIFF_TYPE_INDEX, DIFF_STATUS_ADDED, ce->sha1, ce->name);
        *results = g_list_prepend (*results, de);
    }
}
