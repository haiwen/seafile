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

struct dir_entry {
    unsigned int len;
    char name[0]; /* more */
};

struct dir_struct {
    int nr, alloc;
    int ignored_nr, ignored_alloc;
   enum {
        DIR_SHOW_IGNORED = 1<<0,
        DIR_SHOW_OTHER_DIRECTORIES = 1<<1,
        DIR_HIDE_EMPTY_DIRECTORIES = 1<<2,
        DIR_NO_GITLINKS = 1<<3,
        DIR_COLLECT_IGNORED = 1<<4
    } flags;
    struct dir_entry **entries;
    struct dir_entry **ignored;
};

static struct dir_entry *
dir_entry_new(const char *pathname, int len)
{
    struct dir_entry *ent;

    ent = malloc(sizeof(*ent) + len + 1);
    ent->len = len;
    memcpy(ent->name, pathname, len);
    ent->name[len] = 0;
    return ent;
}

static struct dir_entry *
dir_add_name(struct dir_struct *dir, const char *pathname, 
             int len, struct index_state *index)
{
    if (index_name_exists(index, pathname, len, 0))
        return NULL;

    ALLOC_GROW(dir->entries, dir->nr+1, dir->alloc);
    return dir->entries[dir->nr++] = dir_entry_new(pathname, len);
}

static inline int 
is_dot_or_dotdot(const char *name)
{
    return (name[0] == '.' &&
            (name[1] == '\0' ||
             (name[1] == '.' && name[2] == '\0')));
}

static int
get_dtype(const char *dname, const char *path)
{
    SeafStat st;
    int dtype = DT_UNKNOWN;
    char *realpath = g_build_path (PATH_SEPERATOR, path, dname, NULL);

    if (!seaf_stat(realpath, &st)) {
        if (S_ISREG(st.st_mode))
            dtype =  DT_REG;
        if (S_ISDIR(st.st_mode))
            dtype = DT_DIR;
    }

    g_free(realpath);
    return dtype;
}

static int 
read_directory_recursive(struct dir_struct *dir,
                         const char *base, int baselen,
                         int check_only,
                         struct index_state *index,
                         const char *worktree,
                         IgnoreFunc ignore_func)
{
    char *realpath = g_build_path (PATH_SEPERATOR, worktree, base, NULL);
    GDir *fdir = g_dir_open (realpath, 0, NULL);
    const char *dname;
    char *nfc_dname;
    int contents = 0;
    int dtype;

    if (fdir) {
        char path[SEAF_PATH_MAX + 1];
        memcpy(path, base, baselen);
        while ((dname = g_dir_read_name(fdir)) != NULL) {
            int len = 0;

#ifdef __APPLE__
            nfc_dname = g_utf8_normalize (dname, -1, G_NORMALIZE_NFC);
#else
            nfc_dname = g_strdup(dname);
#endif

            if (is_dot_or_dotdot(nfc_dname)) {
                g_free (nfc_dname);
                continue;
            }

            if (ignore_func (nfc_dname, NULL)) {
                g_free (nfc_dname);
                continue;
            }

            dtype = get_dtype(nfc_dname, realpath);
            switch (dtype) {
            case DT_REG:
                len = strlen(nfc_dname);
                memcpy(path + baselen, nfc_dname, len + 1);
                len = strlen(path);
                break;
            case DT_DIR:
                len = strlen(nfc_dname);
                memcpy(path + baselen, nfc_dname, len + 1);
                memcpy(path + baselen + len, "/", 2);
                len = strlen(path);
                read_directory_recursive(dir, path, len, 0,
                                         index, worktree, ignore_func);
                g_free (nfc_dname);
                continue;
            default: /* DT_UNKNOWN */
                len = 0;
                break;
            }
            if(len > 0)
                dir_add_name(dir, path, len, index);
            g_free (nfc_dname);
        }
        g_dir_close(fdir);
    }

    g_free(realpath);
    return contents;
}

static int 
cmp_name(const void *p1, const void *p2)
{
    const struct dir_entry *e1 = *(const struct dir_entry **)p1;
    const struct dir_entry *e2 = *(const struct dir_entry **)p2;

    return cache_name_compare(e1->name, e1->len,
                              e2->name, e2->len);
}

static int 
read_directory(struct dir_struct *dir,
               const char *worktree,
               struct index_state *index,
               IgnoreFunc ignore_func)
{
    read_directory_recursive(dir, "", 0, 0, index, worktree, ignore_func);
    qsort(dir->entries, dir->nr, sizeof(struct dir_entry *), cmp_name);
    return dir->nr;
}

void wt_status_collect_untracked(struct index_state *index,
                                 GList **results,
                                 const char *worktree,
                                 IgnoreFunc ignore_func)
{
    int i;
    struct dir_struct dir;
    DiffEntry *de;

    memset(&dir, 0, sizeof(dir));

    read_directory(&dir, worktree, index, ignore_func);
    for (i = 0; i < dir.nr; i++) {
        struct dir_entry *ent = dir.entries[i];
        unsigned char sha1[20] = { 0 };

        de = diff_entry_new (DIFF_TYPE_WORKTREE, DIFF_STATUS_ADDED, sha1, ent->name);
        *results = g_list_prepend (*results, de);

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
        SeafStat st;
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
        if (seaf_stat(realpath, &st) < 0) {
            if (errno != ENOENT && errno != ENOTDIR)
                changed = -1;
            else
                changed = 1;
        }

        if (changed) {
            if (changed < 0) {
                g_warning ("Faile to stat %s: %s\n", ce->name, strerror(errno));
                g_free (realpath);
                continue;
            }

            if (ce->ce_mtime.sec == 0) {
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
            /* if (!S_ISDIR (st.st_mode) || */
            /*     !is_empty_dir (realpath, ignore_func)) { */
            /*     de = diff_entry_new (DIFF_TYPE_WORKTREE, DIFF_STATUS_DIR_DELETED, */
            /*                          ce->sha1, ce->name); */
            /*     *results = g_list_prepend (*results, de); */
            /* } */
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
