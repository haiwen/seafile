/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#define DEBUG_FLAG SEAFILE_DEBUG_MERGE
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
            g_return_val_if_fail (sub != NULL, -1);
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

#if defined WIN32 || defined __APPLE__

/*
 * If the names are different case-sensitively but the same case-insensitively,
 * it's a case conflict.
 * Note that the names are in UTF-8, so we use UTF-8 function to compare them.
 */
static gboolean
case_conflict_utf8 (const char *name1, const char *name2)
{
    char *casefold1, *casefold2;
    gboolean ret;

    if (strcmp (name1, name2) == 0)
        return FALSE;

    casefold1 = g_utf8_casefold (name1, -1);
    casefold2 = g_utf8_casefold (name2, -1);
    ret = (g_utf8_collate (casefold1, casefold2) == 0);

    g_free (casefold1);
    g_free (casefold2);

    return ret;
}

static gboolean
case_conflict_exists (const char *dir_path, const char *new_dname)
{
    GDir *dir;
    const char *dname;
    gboolean is_case_conflict = FALSE;
    GError *error = NULL;

    dir = g_dir_open (dir_path, 0, &error);
    if (!dir && error) {
        seaf_warning ("Failed to open dir %s: %s.\n", dir_path, error->message);
        g_error_free (error);
        return FALSE;
    }

    while (1) {
        dname = g_dir_read_name (dir);
        if (!dname)
            break;

#ifdef __APPLE__
        char *norm_dname = g_utf8_normalize (dname, -1, G_NORMALIZE_NFC);
        if (case_conflict_utf8 (norm_dname, new_dname)) {
            is_case_conflict = TRUE;
            g_free (norm_dname);
            break;
        }
        g_free (norm_dname);
#else
        if (case_conflict_utf8 (dname, new_dname)) {
            is_case_conflict = TRUE;
            break;
        }
#endif
    }
    g_dir_close (dir);

    return is_case_conflict;
}

/*
 * If files "test (case conflict 1).txt" and "Test (case conflict 2).txt" exist,
 * and we have to checkout "TEST.txt", it will be checked out to "TEST
 * (case conflict 3).txt".
 */
static char *
gen_case_conflict_free_dname (const char *dir_path, const char *dname)
{
    char *copy = g_strdup (dname);
    GString *buf = g_string_new (NULL);
    char ret_dname[256];
    char *dot, *ext;
    int cnt = 1;

    dot = strrchr (copy, '.');

    while (cnt < 255) {
        if (dot != NULL) {
            *dot = '\0';
            ext = dot + 1;
            snprintf (ret_dname, sizeof(ret_dname), "%s (case conflict %d).%s",
                      copy, cnt, ext);
            g_string_printf (buf, "%s/%s (case conflict %d).%s",
                             dir_path, copy, cnt, ext);
        } else {
            snprintf (ret_dname, sizeof(ret_dname), "%s (case conflict %d)",
                      copy, cnt);
            g_string_printf (buf, "%s/%s (case conflict %d)",
                             dir_path, copy, cnt);
        }

        if (g_access (buf->str, F_OK) != 0)
            break;

        g_string_truncate (buf, 0);
        ++cnt;
    }

    g_free (copy);
    g_string_free (buf, TRUE);

    return g_strdup(ret_dname);
}

/*
 * @conflict_hash: conflicting_dir_path -> conflict_free_dname
 * @no_conflict_hash: a hash table to remember dirs that have no case conflict.
 */
static char *
build_case_conflict_free_path (const char *worktree,
                               const char *ce_name,
                               GHashTable *conflict_hash,
                               GHashTable *no_conflict_hash,
                               gboolean *is_case_conflict)
{
    GString *buf = g_string_new (worktree);
    char **components, *ptr;
    guint i, n_comps;
    static int dummy;

    components = g_strsplit (ce_name, "/", -1);
    n_comps = g_strv_length (components);
    for (i = 0; i < n_comps; ++i) {
        char *path = NULL, *dname = NULL, *case_conflict_free_path = NULL;
        SeafStat st;

        ptr = components[i];

        path = g_build_path ("/", buf->str, ptr, NULL);
        /* If path doesn't exist, case conflict is not possible. */
        if (seaf_stat (path, &st) < 0) {
            if (i != n_comps - 1) {
                if (g_mkdir (path, 0777) < 0) {
                    seaf_warning ("Failed to create dir %s.\n", path);
                    g_free (path);
                    goto error;
                }
            }
            g_string_append_printf (buf, "/%s", ptr);
            g_free (path);
            continue;
        }

        dname = g_hash_table_lookup (conflict_hash, path);
        if (dname) {
            /* We've detected (and fixed) case conflict for this dir before. */
            *is_case_conflict = TRUE;
            g_free (path);
            g_string_append_printf (buf, "/%s", dname);
            continue;
        }

        if (g_hash_table_lookup (no_conflict_hash, path) != NULL) {
            /* We've confirmed this dir has no case conflict before. */
            g_free (path);
            g_string_append_printf (buf, "/%s", ptr);
            continue;
        }

        /* No luck in the hash tables, we have to run case conflict detection. */
        if (!case_conflict_exists (buf->str, ptr)) {
            /* No case conflict. */
            if (i != n_comps - 1)
                g_hash_table_insert (no_conflict_hash,
                                     g_strdup(path),
                                     &dummy);
            g_free (path);
            g_string_append_printf (buf, "/%s", ptr);
            continue;
        }

        *is_case_conflict = TRUE;

        /* If case conflict, create a conflict free path and
         * remember it in the hash table.
         */

        dname = gen_case_conflict_free_dname (buf->str, ptr);

        case_conflict_free_path = g_build_path ("/", buf->str, dname, NULL);
        if (i != n_comps - 1) {
            if (g_mkdir (case_conflict_free_path, 0777) < 0) {
                seaf_warning ("Failed to create dir %s.\n", case_conflict_free_path);
                g_free (path);
                g_free (dname);
                g_free (case_conflict_free_path);
                goto error;
            }

            g_hash_table_insert (conflict_hash, g_strdup(path), g_strdup(dname));
        }

        g_string_append_printf (buf, "/%s", dname);

        g_free (path);
        g_free (dname);
        g_free (case_conflict_free_path);
    }

    g_strfreev (components);
    return g_string_free (buf, FALSE);

error:
    g_strfreev (components);
    return NULL;
}

#endif  /* defined WIN32 || defined __APPLE__ */

#ifdef __linux__

static char *
build_checkout_path (const char *worktree, const char *ce_name, int len)
{
    int base_len = strlen(worktree);
    int full_len;
    char path[SEAF_PATH_MAX];
    int offset;
    SeafStat st;

    if (!len) {
        g_warning ("entry name should not be empty.\n");
        return NULL;
    }

    snprintf (path, SEAF_PATH_MAX, "%s/", worktree);

    /* first create all leading directories. */
    full_len = base_len + len + 1;
    offset = base_len + 1;
    while (offset < full_len) {
        do {
            path[offset] = ce_name[offset-base_len-1];
            offset++;
        } while (offset < full_len && ce_name[offset-base_len-1] != '/');
        if (offset >= full_len)
            break;
        path[offset] = 0;

        if (seaf_stat (path, &st) == 0 && S_ISDIR(st.st_mode))
            continue;
        
        if (ccnet_mkdir (path, 0777) < 0) {
            g_warning ("Failed to create directory %s.\n", path);
            return NULL;
        }
    }
    path[offset] = 0;

    return g_strdup(path);
}

#endif  /* __linux__ */

static int
checkout_entry (struct cache_entry *ce,
                struct unpack_trees_options *o,
                gboolean recover_merge,
                const char *conflict_suffix,
                GHashTable *conflict_hash,
                GHashTable *no_conflict_hash)
{
    char *path_in, *path;
    SeafStat st;
    char file_id[41];
    gboolean case_conflict = FALSE;
    gboolean force_conflict = FALSE;

    path_in = g_build_path ("/", o->base, ce->name, NULL);
#ifndef __linux__
    path = build_case_conflict_free_path (o->base, ce->name,
                                          conflict_hash, no_conflict_hash,
                                          &case_conflict);
#else
    path = build_checkout_path (o->base, ce->name, ce_namelen(ce));
#endif

    g_free (path_in);
    if (!path)
        return -1;

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
        g_free (path);
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
            force_conflict = TRUE;
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
                                       force_conflict,
                                       &conflicted) < 0) {
        g_warning ("Failed to checkout file %s.\n", path);
        g_free (path);
        return -1;
    }

    /* If case conflict, this file has been checked out to another path.
     * Remove the current entry, otherwise it won't be removed later
     * since it's timestamp is 0.
     */
    if (case_conflict) {
        ce->ce_flags |= CE_REMOVE;
        g_free (path);
        return 0;
    }

    if (conflicted) {
        g_free (path);
        return 0;
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
    GHashTable *conflict_hash, *no_conflict_hash;

    for (i = 0; i < result->cache_nr; ++i) {
        ce = result->cache[i];
        if (ce->ce_flags & CE_WT_REMOVE)
            errs |= unlink_entry (ce, o);
    }

    conflict_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           g_free, g_free);
    no_conflict_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                              g_free, NULL);

    for (i = 0; i < result->cache_nr; ++i) {
        ce = result->cache[i];
        if (ce->ce_flags & CE_UPDATE) {
            if (conflict_head_id) {
                conflict_suffix = get_last_changer_of_file (conflict_head_id,
                                                            ce->name);
                if (!conflict_suffix)
                    conflict_suffix = g_strdup(default_conflict_suffix);
            }
            errs |= checkout_entry (ce, o, recover_merge,
                                    conflict_suffix,
                                    conflict_hash, no_conflict_hash);
            g_free (conflict_suffix);
        }
        if (finished_entries)
            *finished_entries = *finished_entries + 1;
    }

    g_hash_table_destroy (conflict_hash);
    g_hash_table_destroy (no_conflict_hash);

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
