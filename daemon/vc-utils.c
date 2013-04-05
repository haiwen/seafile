/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include "log.h"
#include "seafile-error.h"

#include <stdlib.h>
#include <sys/stat.h>
#include <glib/gstdio.h>

#include "seafile-session.h"

#include "utils.h"
#include "fs-mgr.h"
#include "merge.h"
#include "vc-utils.h"
#include "vc-common.h"

static gint
compare_dirents (gconstpointer a, gconstpointer b)
{
    const SeafDirent *denta = a, *dentb = b;

    return strcmp (dentb->name, denta->name);
}

int
commit_trees_cb (struct cache_tree *it, struct cache_entry **cache,
                 int entries, const char *base, int baselen)
{
    SeafDir *seaf_dir;
    GList *dirents = NULL;
    int i;

    for (i = 0; i < entries; i++) {
        SeafDirent *seaf_dent;
        char *dirname;
        struct cache_entry *ce = cache[i];
        struct cache_tree_sub *sub;
        const char *path, *slash;
        int pathlen, entlen;
        const unsigned char *sha1;
        char hex[41];
        unsigned mode;

        if (ce->ce_flags & CE_REMOVE)
            continue; /* entry being removed */

        path = ce->name;
        pathlen = ce_namelen(ce);
        if (pathlen <= baselen || memcmp(base, path, baselen))
            break; /* at the end of this level */

        slash = strchr(path + baselen, '/');
        if (slash) {
            entlen = slash - (path + baselen);
            sub = cache_tree_find_subtree(it, path + baselen, entlen, 0);
            g_assert (sub != NULL);
            /* Skip cache entries in the sub level. */
            i += sub->cache_tree->entry_count - 1;

            sha1 = sub->cache_tree->sha1;
            mode = S_IFDIR;
            dirname = g_strndup(path + baselen, entlen);

            rawdata_to_hex (sha1, hex, 20);
            seaf_dent = seaf_dirent_new (hex, mode, dirname);
            g_free(dirname);

            dirents = g_list_prepend (dirents, seaf_dent);
        } else {
            sha1 = ce->sha1;
            mode = ce->ce_mode;
            entlen = pathlen - baselen;

            dirname = g_strndup(path + baselen, entlen);
            rawdata_to_hex (sha1, hex, 20);
            seaf_dent = seaf_dirent_new (hex, mode, dirname);
            g_free(dirname);

            dirents = g_list_prepend (dirents, seaf_dent);
        }

#if DEBUG
        fprintf(stderr, "cache-tree update-one %o %.*s\n",
                mode, entlen, path + baselen);
#endif
    }

    /* Sort dirents in descending order. */
    dirents = g_list_sort (dirents, compare_dirents);

    seaf_dir = seaf_dir_new (NULL, dirents, 0);
    hex_to_rawdata (seaf_dir->dir_id, it->sha1, 20);

    seaf_dir_save (seaf->fs_mgr, seaf_dir);

#if DEBUG
    for (p = dirents; p; p = p->next) {
        SeafDirent *tmp = (SeafDirent *)p->data;
        fprintf(stderr, "dump dirent name %s id %s\n", tmp->name, tmp->id);
    }
#endif

    seaf_dir_free (seaf_dir);
    return 0;
}

int
update_index (struct index_state *istate, const char *index_path)
{
    char index_shadow[SEAF_PATH_MAX];
    int index_fd;
    int ret = 0;

    snprintf (index_shadow, SEAF_PATH_MAX, "%s.shadow", index_path);
    index_fd = g_open (index_shadow, O_RDWR | O_CREAT | O_TRUNC | O_BINARY, 0666);
    if (index_fd < 0) {
        g_warning ("Failed to open shadow index: %s.\n", strerror(errno));
        return -1;
    }

    if (write_index (istate, index_fd) < 0) {
        g_warning ("Failed to write shadow index: %s.\n", strerror(errno));
        return -1;
    }
    close (index_fd);

    ret = ccnet_rename (index_shadow, index_path);
    if (ret < 0) {
        g_warning ("Failed to update index errno=%d %s\n", errno, strerror(errno));
        return -1;
    }
    return 0;
}

static int
unlink_entry (struct cache_entry *ce, struct unpack_trees_options *o)
{
    char path[SEAF_PATH_MAX];
    SeafStat st;
    int base_len = strlen(o->base);
    int len = ce_namelen(ce);
    int offset;

    if (!len) {
        g_warning ("entry name should not be empty.\n");
        return -1;
    }

    snprintf (path, SEAF_PATH_MAX, "%s/%s", o->base, ce->name);

    if (!S_ISDIR(ce->ce_mode)) {
        /* file doesn't exist in work tree */
        if (seaf_stat (path, &st) < 0 || !S_ISREG(st.st_mode)) {
            return 0;
        }

        /* file has been changed. */
        if (!o->reset &&
            (ce->ce_ctime.sec != st.st_ctime || ce->ce_mtime.sec != st.st_mtime)) {
            g_warning ("File %s is changed. Skip removing the file.\n", path);
            return -1;
        }

        /* first unlink the file. */
        if (g_unlink (path) < 0) {
            g_warning ("Failed to remove %s: %s.\n", path, strerror(errno));
            return -1;
        }
    } else {
        if (seaf_stat (path, &st) < 0 || !S_ISDIR(st.st_mode))
            return 0;

        if (g_rmdir (path) < 0) {
            g_warning ("Failed to remove %s: %s.\n", path, strerror(errno));
            return -1;
        }
    }

    /* then remove all empty directories upwards. */
    offset = base_len + len;
    do {
        if (path[offset] == '/') {
            path[offset] = '\0';
            int ret = g_rmdir (path);
            if (ret < 0 && errno == ENOTEMPTY) {
                break;
            } else if (ret < 0) {
                g_warning ("Failed to remove %s: %s.\n", path, strerror(errno));
                return -1;
            }
        }
    } while (--offset > base_len);

    return 0;
}

int
compare_file_content (const char *path, SeafStat *st, const unsigned char *ce_sha1,
                      SeafileCrypt *crypt)
{
    CDCFileDescriptor cdc;
    unsigned char sha1[20];

    memset (&cdc, 0, sizeof(cdc));
    cdc.block_sz = calculate_chunk_size (st->st_size);
    cdc.block_min_sz = cdc.block_sz >> 2;
    cdc.block_max_sz = cdc.block_sz << 2;
    cdc.write_block = seafile_write_chunk;
    if (filename_chunk_cdc (path, &cdc, crypt, FALSE) < 0) {
        g_warning ("Failed to chunk file.\n");
        return -1;
    }
    memcpy (sha1, cdc.file_sum, 20);

    char id1[41], id2[41];
    rawdata_to_hex (sha1, id1, 20);
    rawdata_to_hex (ce_sha1, id2, 20);
    printf ("id1: %s, id2: %s.\n", id1, id2);

    return hashcmp (sha1, ce_sha1);
}

static int
checkout_entry (struct cache_entry *ce,
                struct unpack_trees_options *o,
                gboolean recover_merge,
                const char *conflict_suffix)
{
    int base_len = strlen(o->base);
    int len = ce_namelen(ce);
    int full_len;
    char path[SEAF_PATH_MAX];
    int offset;
    SeafStat st;
    char file_id[41];

    if (!len) {
        g_warning ("entry name should not be empty.\n");
        return -1;
    }

    snprintf (path, SEAF_PATH_MAX, "%s/", o->base);

    /* first create all leading directories. */
    full_len = base_len + len + 1;
    offset = base_len + 1;
    while (offset < full_len) {
        do {
            path[offset] = ce->name[offset-base_len-1];
            offset++;
        } while (offset < full_len && ce->name[offset-base_len-1] != '/');
        if (offset >= full_len)
            break;
        path[offset] = 0;

        if (seaf_stat (path, &st) == 0 && S_ISDIR(st.st_mode))
            continue;
        
        if (ccnet_mkdir (path, 0777) < 0) {
            g_warning ("Failed to create directory %s.\n", path);
            return -1;
        }
    }
    path[offset] = 0;

    if (!S_ISDIR(ce->ce_mode)) {
        /* In case that we're replacing an empty dir with a file,
         * we need first to remove the empty dir.
         */
        if (seaf_stat (path, &st) == 0 && S_ISDIR(st.st_mode)) {
            if (g_rmdir (path) < 0) {
                g_warning ("Failed to remove dir %s: %s\n", path, strerror(errno));
                /* Don't quit since we can handle conflict later. */
            }
        }
    } else {
        /* For simplicity, we just don't checkout the empty dir if there is
         * already a file with the same name in the worktree.
         * This implies, you can't remove a file then create an empty directory
         * with the same name. But it's a rare requirement.
         */
        if (g_mkdir (path, 0777) < 0) {
            g_warning ("Failed to create empty dir %s.\n", path);
        }
        return 0;
    }

    if (!o->reset && seaf_stat (path, &st) == 0 && S_ISREG(st.st_mode) &&
        (ce->ce_ctime.sec != st.st_ctime || ce->ce_mtime.sec != st.st_mtime))
    {
        /* If we're recovering an interrupted merge, we don't know whether
         * the file was changed by checkout or by the user. So we have to
         * calculate the sha1 for that file and compare it with the one in
         * cache entry.
         */
        if (!recover_merge || 
            compare_file_content (path, &st, ce->sha1, o->crypt) != 0) {
            g_warning ("File %s is changed. Checkout to conflict file.\n", path);
        } else {
            /* Recover merge and file content matches index entry.
             * We were interrupted before updating the index, update index
             * entry timestamp now.
             */
            goto update_cache;
        }
    }

    /* then checkout the file. */
    gboolean conflicted = FALSE;
    rawdata_to_hex (ce->sha1, file_id, 20);
    if (seaf_fs_manager_checkout_file (seaf->fs_mgr, file_id,
                                       path, ce->ce_mode,
                                       o->crypt,
                                       conflict_suffix,
                                       &conflicted) < 0) {
        g_warning ("Failed to checkout file %s.\n", path);
        return -1;
    }

    if (conflicted)
        return 0;

update_cache:
    /* finally fill cache_entry info */
    /* Only update index if we checked out the file without any error
     * or conflicts. The timestamp of the entry will remain 0 if error
     * or conflicted.
     */
    seaf_stat (path, &st);
    fill_stat_cache_info (ce, &st);

    return 0;
}

int
update_worktree (struct unpack_trees_options *o,
                 gboolean recover_merge,
                 const char *conflict_head_id,
                 const char *default_conflict_suffix,
                 int *finished_entries)
{
    struct index_state *result = &o->result;
    int i;
    struct cache_entry *ce;
    char *conflict_suffix = NULL;
    int errs = 0;

    for (i = 0; i < result->cache_nr; ++i) {
        ce = result->cache[i];
        if (ce->ce_flags & CE_WT_REMOVE)
            errs |= unlink_entry (ce, o);
    }

    for (i = 0; i < result->cache_nr; ++i) {
        ce = result->cache[i];
        if (ce->ce_flags & CE_UPDATE) {
            if (conflict_head_id) {
                conflict_suffix = get_last_changer_of_file (conflict_head_id,
                                                            ce->name);
                if (!conflict_suffix)
                    conflict_suffix = g_strdup(default_conflict_suffix);
            }
            errs |= checkout_entry (ce, o, recover_merge, conflict_suffix);
            g_free (conflict_suffix);
        }
        if (finished_entries)
            *finished_entries = *finished_entries + 1;
    }

    if (errs != 0)
        return -1;
    return 0;
}

#ifdef WIN32

static gboolean
do_check_file_locked (const char *path, const char *worktree)
{
    char *real_path;
    HANDLE handle;
    wchar_t *path_w;

    real_path = g_build_path(PATH_SEPERATOR, worktree, path, NULL);
    path_w = wchar_from_utf8 (real_path);
    g_free (real_path);

    handle = CreateFileW (path_w,
                          GENERIC_WRITE,
                          0,
                          NULL,
                          OPEN_EXISTING,
                          0,
                          NULL);
    g_free (path_w);
    if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle (handle);
    } else if (GetLastError() == ERROR_SHARING_VIOLATION) {
        return TRUE;
    }

    return FALSE;
}

gboolean
files_locked_on_windows (struct index_state *index, const char *worktree)
{
    gboolean ret = FALSE;
    int i, entries;
    struct cache_entry *ce;

    entries = index->cache_nr;
    for (i = 0; i < entries; ++i) {
        ce = index->cache[i];
        if (ce_stage(ce)) {
            int mask = 0;

            mask |= 1 << (ce_stage(ce) - 1);
            while (i < entries) {
                struct cache_entry *nce = index->cache[i];

                if (strcmp(ce->name, nce->name))
                    break;

                mask |= 1 << (ce_stage(nce) - 1);
                i++;
            }
            i--;

            /* Check unmerged cases that can potentially
               update or remove current files in the worktree.
            */
            if (mask == 7 ||    /* both changed */
                mask == 6 ||    /* both added */
                mask == 3)      /* others removed */
            {
                if (do_check_file_locked (ce->name, worktree))
                    ret = TRUE;
                    break;
            }
        } else if (ce->ce_flags & CE_UPDATE ||
                   ce->ce_flags & CE_WT_REMOVE) {
            if (do_check_file_locked (ce->name, worktree)) {
                ret = TRUE;
                break;
            }
        }
    }

    return ret;
}

#endif  /* WIN32 */

void
fill_seafile_blocks (const unsigned char *sha1, BlockList *bl)
{
    char file_id[41];
    Seafile *seafile;
    int i;

    rawdata_to_hex (sha1, file_id, 20);
    seafile = seaf_fs_manager_get_seafile (seaf->fs_mgr, file_id);
    if (!seafile) {
        g_warning ("Failed to find file %s.\n", file_id);
        return;
    }

    for (i = 0; i < seafile->n_blocks; ++i)
        block_list_insert (bl, seafile->blk_sha1s[i]);

    seafile_unref (seafile);
}

void
collect_new_blocks_from_index (struct index_state *index, BlockList *bl)
{
    int i;
    struct cache_entry *ce;

    for (i = 0; i < index->cache_nr; ++i) {
        ce = index->cache[i];
        if (ce->ce_flags & CE_UPDATE)
            fill_seafile_blocks (ce->sha1, bl);
    }
}
