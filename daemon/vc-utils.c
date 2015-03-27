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
#include "index/index.h"

static gint
compare_dirents (gconstpointer a, gconstpointer b)
{
    const SeafDirent *denta = a, *dentb = b;

    return strcmp (dentb->name, denta->name);
}

int
commit_trees_cb (const char *repo_id, int version,
                 const char *worktree,
                 struct cache_tree *it, struct cache_entry **cache,
                 int entries, const char *base, int baselen)
{
    SeafDir *seaf_dir;
    GList *dirents = NULL, *ptr;
    int i;

    for (i = 0; i < entries; i++) {
        SeafDirent *seaf_dent;
        char *name;
        struct cache_entry *ce = cache[i];
        struct cache_tree_sub *sub;
        const char *path, *slash;
        int pathlen, entlen;
        const unsigned char *sha1;
        char hex[41];
        unsigned mode;
        guint64 mtime;
        gint64 size;
        char *modifier;

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
            mtime = sub->cache_tree->mtime;
            mode = S_IFDIR;
            name = g_strndup(path + baselen, entlen);

            rawdata_to_hex (sha1, hex, 20);
            seaf_dent = seaf_dirent_new (dir_version_from_repo_version(version),
                                         hex, mode, name, mtime, NULL, -1);
            g_free(name);

            dirents = g_list_prepend (dirents, seaf_dent);
        } else {
            sha1 = ce->sha1;
            mode = ce->ce_mode;
            mtime = ce->ce_mtime.sec;
            size = ce->ce_size;
            modifier = ce->modifier;
            entlen = pathlen - baselen;
            name = g_strndup(path + baselen, entlen);
            rawdata_to_hex (sha1, hex, 20);

            if (version > 0) {
                seaf_dent =
                    seaf_dirent_new (dir_version_from_repo_version(version),
                                     hex, mode, name, mtime, modifier, size);
            } else {
                seaf_dent = seaf_dirent_new (0, hex, mode, name, 0, NULL, -1);
            }

            g_free(name);

            dirents = g_list_prepend (dirents, seaf_dent);
        }

#if DEBUG
        fprintf(stderr, "cache-tree update-one %o %.*s\n",
                mode, entlen, path + baselen);
#endif
    }

    /* Sort dirents in descending order. */
    dirents = g_list_sort (dirents, compare_dirents);

    seaf_dir = seaf_dir_new (NULL, dirents, dir_version_from_repo_version(version));
    hex_to_rawdata (seaf_dir->dir_id, it->sha1, 20);

    /* Dir's mtime is the latest of all dir entires. */
    guint64 dir_mtime = 0;
    SeafDirent *dent;
    for (ptr = dirents; ptr; ptr = ptr->next) {
        dent = ptr->data;
        if (dent->mtime > dir_mtime)
            dir_mtime = dent->mtime;
    }
    it->mtime = dir_mtime;

    if (!seaf_fs_manager_object_exists (seaf->fs_mgr,
                                        repo_id, version,
                                        seaf_dir->dir_id))
        seaf_dir_save (seaf->fs_mgr, repo_id, version, seaf_dir);

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
    index_fd = seaf_util_create (index_shadow, O_RDWR | O_CREAT | O_TRUNC | O_BINARY,
                                 0666);
    if (index_fd < 0) {
        g_warning ("Failed to open shadow index: %s.\n", strerror(errno));
        return -1;
    }

    if (write_index (istate, index_fd) < 0) {
        g_warning ("Failed to write shadow index: %s.\n", strerror(errno));
        close (index_fd);
        return -1;
    }
    close (index_fd);

    ret = seaf_util_rename (index_shadow, index_path);
    if (ret < 0) {
        g_warning ("Failed to update index errno=%d %s\n", errno, strerror(errno));
        return -1;
    }
    return 0;
}

#ifndef WIN32

int
seaf_remove_empty_dir (const char *path)
{
    SeafStat st;
    GDir *dir;
    const char *dname;
    char *full_path;
    GError *error = NULL;

    if (seaf_stat (path, &st) < 0 || !S_ISDIR(st.st_mode))
        return 0;

    if (seaf_util_rmdir (path) < 0) {
        dir = g_dir_open (path, 0, &error);
        if (!dir) {
            seaf_warning ("Failed to open dir %s: %s.\n", path, error->message);
            return -1;
        }

        /* Remove all ignored hidden files. */
        while ((dname = g_dir_read_name (dir)) != NULL) {
            if (seaf_repo_manager_is_ignored_hidden_file(dname)) {
                full_path = g_build_path ("/", path, dname, NULL);
                if (seaf_util_unlink (full_path) < 0)
                    seaf_warning ("Failed to remove file %s: %s.\n",
                                  full_path, strerror(errno));
                g_free (full_path);
            }
        }

        g_dir_close (dir);

        if (seaf_util_rmdir (path) < 0) {
            seaf_warning ("Failed to remove dir %s: %s.\n", path, strerror(errno));
            return -1;
        }
    }

    return 0;
}

#else

static int
remove_hidden_file (wchar_t *parent, WIN32_FIND_DATAW *fdata,
                    void *user_data, gboolean *stop)
{
    char *dname = NULL;
    wchar_t *subpath_w = NULL;
    char *subpath = NULL;

    dname = g_utf16_to_utf8 (fdata->cFileName, -1, NULL, NULL, NULL);

    if (!(fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
        seaf_repo_manager_is_ignored_hidden_file(dname)) {
        subpath_w = g_new0 (wchar_t, wcslen(parent) + wcslen(fdata->cFileName) + 2);
        wcscpy (subpath_w, parent);
        wcscat (subpath_w, L"\\");
        wcscat (subpath_w, fdata->cFileName);

        if (!DeleteFileW (subpath_w)) {
            subpath = g_utf16_to_utf8 (subpath_w, -1, NULL, NULL, NULL);
            seaf_warning ("Failed to remove file %s: %lu.\n", subpath, GetLastError());
            g_free (subpath);
        }

        g_free (subpath_w);
    }

    g_free (dname);
    return 0;
}

int
seaf_remove_empty_dir (const char *path)
{
    wchar_t *path_w = NULL;
    WIN32_FILE_ATTRIBUTE_DATA attrs;
    int ret = 0;

    path_w = win32_long_path (path);

    if (!GetFileAttributesExW (path_w, GetFileExInfoStandard, &attrs)) {
        goto out;
    }

    if (!(attrs.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        goto out;
    }

    if (RemoveDirectoryW (path_w))
        goto out;

    if (GetLastError() == ERROR_DIR_NOT_EMPTY) {
        traverse_directory_win32 (path_w, remove_hidden_file, NULL);
        if (!RemoveDirectoryW (path_w)) {
            seaf_warning ("Failed to remove dir %s: %lu.\n", path, GetLastError());
            ret = -1;
        }
    } else {
        seaf_warning ("Failed to remove dir %s: %lu.\n", path, GetLastError());
        ret = -1;
    }

out:
    g_free (path_w);
    return ret;
}

#endif  /* WIN32 */

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
            (ce->current_mtime != st.st_mtime)) {
            g_warning ("File %s is changed. Skip removing the file.\n", path);
            return -1;
        }

        /* first unlink the file. */
        if (seaf_util_unlink (path) < 0) {
            g_warning ("Failed to remove %s: %s.\n", path, strerror(errno));
            return -1;
        }
    } else {
        if (seaf_remove_empty_dir (path) < 0) {
            g_warning ("Failed to remove dir %s: %s.\n", path, strerror(errno));
            return -1;
        }
    }

    /* then remove all empty directories upwards. */
    offset = base_len + len;
    do {
        if (path[offset] == '/') {
            path[offset] = '\0';
            int ret = seaf_remove_empty_dir (path);
            if (ret < 0) {
                break;
            }
        }
    } while (--offset > base_len);

    return 0;
}

int
compare_file_content (const char *path, SeafStat *st, const unsigned char *ce_sha1,
                      SeafileCrypt *crypt, int repo_version)
{
    CDCFileDescriptor cdc;
    unsigned char sha1[20];

    if (st->st_size == 0) {
        memset (sha1, 0, 20);
    } else {
        memset (&cdc, 0, sizeof(cdc));
        cdc.block_sz = calculate_chunk_size (st->st_size);
        cdc.block_min_sz = cdc.block_sz >> 2;
        cdc.block_max_sz = cdc.block_sz << 2;
        cdc.write_block = seafile_write_chunk;
        if (filename_chunk_cdc (path, &cdc, crypt, FALSE) < 0) {
            g_warning ("Failed to chunk file.\n");
            return -1;
        }

        if (repo_version > 0)
            seaf_fs_manager_calculate_seafile_id_json (repo_version, &cdc, sha1);
        else
            memcpy (sha1, cdc.file_sum, 20);

        if (cdc.blk_sha1s)
            free (cdc.blk_sha1s);
    }

#if 0
    char id1[41], id2[41];
    rawdata_to_hex (sha1, id1, 20);
    rawdata_to_hex (ce_sha1, id2, 20);
    seaf_debug ("id1: %s, id2: %s.\n", id1, id2);
#endif

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

#ifndef WIN32

static gboolean
case_conflict_exists (const char *dir_path, const char *new_dname,
                      char **conflict_dname)
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

        char *norm_dname = g_utf8_normalize (dname, -1, G_NORMALIZE_NFC);
        if (case_conflict_utf8 (norm_dname, new_dname)) {
            is_case_conflict = TRUE;
            *conflict_dname = norm_dname;
            break;
        }
        g_free (norm_dname);
    }
    g_dir_close (dir);

    return is_case_conflict;
}

#else

typedef struct CaseConflictData {
    const char *new_dname;
    gboolean is_case_conflict;
    char *conflict_dname;
} CaseConflictData;

static int
check_case_conflict_cb (wchar_t *parent, WIN32_FIND_DATAW *fdata,
                        void *user_data, gboolean *stop)
{
    CaseConflictData *data = user_data;
    char *dname = NULL;

    dname = g_utf16_to_utf8 (fdata->cFileName, -1, NULL, NULL, NULL);

    if (case_conflict_utf8 (dname, data->new_dname)) {
        data->is_case_conflict = TRUE;
        data->conflict_dname = g_strdup(dname);
        *stop = TRUE;
    }

    g_free (dname);
    return 0;
}

static gboolean
case_conflict_exists (const char *dir_path, const char *new_dname,
                      char **conflict_dname)
{
    wchar_t *dir_path_w = win32_long_path (dir_path);
    gboolean is_case_conflict = FALSE;
    CaseConflictData data;

    memset (&data, 0, sizeof(data));
    data.new_dname = new_dname;

    if (traverse_directory_win32 (dir_path_w, check_case_conflict_cb, &data) < 0)
        goto out;

    is_case_conflict = data.is_case_conflict;
    *conflict_dname = data.conflict_dname;

out:
    g_free (dir_path_w);
    return is_case_conflict;
}

#endif  /* WIN32 */

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

        if (!seaf_util_exists (buf->str))
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
char *
build_case_conflict_free_path (const char *worktree,
                               const char *ce_name,
                               GHashTable *conflict_hash,
                               GHashTable *no_conflict_hash,
                               gboolean *is_case_conflict,
                               gboolean is_rename)
{
    GString *buf = g_string_new (worktree);
    char **components, *ptr;
    guint i, n_comps;
    static int dummy;
    char *conflict_dname = NULL;

    components = g_strsplit (ce_name, "/", -1);
    n_comps = g_strv_length (components);
    for (i = 0; i < n_comps; ++i) {
        char *path = NULL, *dname = NULL;
        SeafStat st;

        ptr = components[i];

        path = g_build_path ("/", buf->str, ptr, NULL);
        /* If path doesn't exist, case conflict is not possible. */
        if (seaf_stat (path, &st) < 0) {
            if (i != n_comps - 1) {
                if (seaf_util_mkdir (path, 0777) < 0) {
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
        if (!case_conflict_exists (buf->str, ptr, &conflict_dname)) {
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

        if (!is_rename) {
            dname = gen_case_conflict_free_dname (buf->str, ptr);

            char *case_conflict_free_path = g_build_path ("/", buf->str, dname, NULL);
            if (i != n_comps - 1) {
                if (seaf_util_mkdir (case_conflict_free_path, 0777) < 0) {
                    seaf_warning ("Failed to create dir %s.\n",
                                  case_conflict_free_path);
                    g_free (path);
                    g_free (dname);
                    g_free (case_conflict_free_path);
                    goto error;
                }

                g_hash_table_insert (conflict_hash, g_strdup(path), g_strdup(dname));
            }

            g_string_append_printf (buf, "/%s", dname);

            g_free (dname);
            g_free (case_conflict_free_path);
        } else {
            char *src_path = g_build_path ("/", buf->str, conflict_dname, NULL);

            if (i != (n_comps - 1) && seaf_util_rename (src_path, path) < 0) {
                seaf_warning ("Failed to rename %s to %s: %s.\n",
                              src_path, path, strerror(errno));
                g_free (path);
                g_free (src_path);
                goto error;
            }

            /* Since the exsiting dir in the worktree has been renamed,
             * there is no more case conflict.
             */
            g_hash_table_insert (no_conflict_hash, g_strdup(path), &dummy);

            g_string_append_printf (buf, "/%s", ptr);

            g_free (src_path);
        }

        g_free (conflict_dname);
        g_free (path);
    }

    g_strfreev (components);
    return g_string_free (buf, FALSE);

error:
    g_strfreev (components);
    return NULL;
}

#endif  /* defined WIN32 || defined __APPLE__ */

#ifdef __linux__

char *
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
        
        if (seaf_util_mkdir (path, 0777) < 0) {
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
                const char *conflict_head_id,
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
                                          &case_conflict,
                                          FALSE);
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
            if (seaf_util_rmdir (path) < 0) {
                g_warning ("Failed to remove dir %s: %s\n", path, strerror(errno));
                /* Don't quit since we can handle conflict later. */
            }
        }
    } else {
        if (seaf_util_mkdir (path, 0777) < 0) {
            g_warning ("Failed to create empty dir %s in checkout.\n", path);
            g_free (path);
            return -1;
        }
        if (ce->ce_mtime.sec != 0 &&
            seaf_set_file_time (path, ce->ce_mtime.sec) < 0) {
            g_warning ("Failed to set mtime for %s.\n", path);
        }
        goto update_cache;
    }

    if (!o->reset && seaf_stat (path, &st) == 0 && S_ISREG(st.st_mode) &&
        (ce->current_mtime != st.st_mtime))
    {
        /* If we're recovering an interrupted merge, we don't know whether
         * the file was changed by checkout or by the user. So we have to
         * calculate the sha1 for that file and compare it with the one in
         * cache entry.
         */
        if (!recover_merge || 
            compare_file_content (path, &st, ce->sha1, o->crypt, o->version) != 0) {
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
    if (seaf_fs_manager_checkout_file (seaf->fs_mgr,
                                       o->repo_id,
                                       o->version,
                                       file_id,
                                       path,
                                       ce->ce_mode,
                                       ce->ce_mtime.sec,
                                       o->crypt,
                                       ce->name,
                                       conflict_head_id,
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
            errs |= checkout_entry (ce, o, recover_merge,
                                    conflict_head_id,
                                    conflict_hash, no_conflict_hash);
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

int
delete_path (const char *worktree, const char *name,
             unsigned int mode, gint64 old_mtime)
{
    char path[SEAF_PATH_MAX];
    SeafStat st;
    int len = strlen(name);

    if (!len) {
        g_warning ("entry name should not be empty.\n");
        return -1;
    }

    snprintf (path, SEAF_PATH_MAX, "%s/%s", worktree, name);

    if (!S_ISDIR(mode)) {
        /* file doesn't exist in work tree */
        if (seaf_stat (path, &st) < 0 || !S_ISREG(st.st_mode)) {
            return 0;
        }

        /* file has been changed. */
        if (old_mtime != st.st_mtime) {
            g_warning ("File %s is changed. Skip removing the file.\n", path);
            return -1;
        }

        /* first unlink the file. */
        if (seaf_util_unlink (path) < 0) {
            g_warning ("Failed to remove %s: %s.\n", path, strerror(errno));
            return -1;
        }
    } else {
        if (seaf_remove_empty_dir (path) < 0) {
            g_warning ("Failed to remove dir %s: %s.\n", path, strerror(errno));
            return -1;
        }
    }

    /* then remove all empty directories upwards. */
    /* offset = base_len + len; */
    /* do { */
    /*     if (path[offset] == '/') { */
    /*         path[offset] = '\0'; */
    /*         int ret = seaf_remove_empty_dir (path); */
    /*         if (ret < 0) { */
    /*             break; */
    /*         } */
    /*     } */
    /* } while (--offset > base_len); */

    return 0;
}

#ifdef WIN32

static gboolean
check_file_locked (const wchar_t *path_w)
{
    HANDLE handle;

    handle = CreateFileW (path_w,
                          GENERIC_WRITE,
                          0,
                          NULL,
                          OPEN_EXISTING,
                          0,
                          NULL);
    if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle (handle);
    } else if (GetLastError() == ERROR_SHARING_VIOLATION) {
        return TRUE;
    }

    return FALSE;
}

gboolean
do_check_file_locked (const char *path, const char *worktree)
{
    char *real_path;
    wchar_t *real_path_w;
    gboolean ret;
    real_path = g_build_path(PATH_SEPERATOR, worktree, path, NULL);
    real_path_w = win32_long_path (real_path);
    ret = check_file_locked (real_path_w);
    g_free (real_path);
    g_free (real_path_w);
    return ret;
}

static gboolean
check_dir_locked (const wchar_t *path_w)
{
    HANDLE handle;

    handle = CreateFileW (path_w,
                          GENERIC_WRITE,
                          0,
                          NULL,
                          OPEN_EXISTING,
                          FILE_FLAG_BACKUP_SEMANTICS,
                          NULL);
    if (handle != INVALID_HANDLE_VALUE) {
        CloseHandle (handle);
    } else if (GetLastError() == ERROR_SHARING_VIOLATION) {
        return TRUE;
    }

    return FALSE;
}

static gboolean
check_dir_locked_recursive (const wchar_t *path_w)
{
    WIN32_FIND_DATAW fdata;
    HANDLE handle;
    wchar_t *pattern;
    wchar_t *sub_path_w;
    char *path, *sub_path;
    int path_len_w;
    DWORD error;
    gboolean ret = FALSE;

    if (check_dir_locked (path_w))
        return TRUE;

    path = g_utf16_to_utf8 (path_w, -1, NULL, NULL, NULL);

    path_len_w = wcslen(path_w);

    pattern = g_new0 (wchar_t, (path_len_w + 3));
    wcscpy (pattern, path_w);
    wcscat (pattern, L"\\*");

    handle = FindFirstFileW (pattern, &fdata);
    if (handle == INVALID_HANDLE_VALUE) {
        seaf_warning ("FindFirstFile failed %s: %lu.\n",
                      path, GetLastError());
        goto out;
    }

    do {
        if (wcscmp (fdata.cFileName, L".") == 0 ||
            wcscmp (fdata.cFileName, L"..") == 0)
            continue;

        sub_path_w = g_new0 (wchar_t, path_len_w + wcslen(fdata.cFileName) + 2);
        wcscpy (sub_path_w, path_w);
        wcscat (sub_path_w, L"\\");
        wcscat (sub_path_w, fdata.cFileName);

        if (fdata.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (check_dir_locked_recursive (sub_path_w)) {
                ret = TRUE;
                g_free (sub_path_w);
                goto out;
            }
        } else {
            if (check_file_locked (sub_path_w)) {
                ret = TRUE;
                g_free (sub_path_w);
                goto out;
            }
        }

        g_free (sub_path_w);
    } while (FindNextFileW (handle, &fdata) != 0);

    error = GetLastError();
    if (error != ERROR_NO_MORE_FILES) {
        seaf_warning ("FindNextFile failed %s: %lu.\n",
                      path, error);
    }

    FindClose (handle);

out:
    g_free (path);
    g_free (pattern);
    return ret;
}

gboolean
do_check_dir_locked (const char *path, const char *worktree)
{
    char *real_path = g_build_path (PATH_SEPERATOR, worktree, path, NULL);
    wchar_t *real_path_w = win32_long_path (real_path);
    gboolean ret = check_dir_locked_recursive (real_path_w);
    g_free (real_path);
    g_free (real_path_w);
    return ret;
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
fill_seafile_blocks (const char *repo_id, int version,
                     const unsigned char *sha1, BlockList *bl)
{
    char file_id[41];
    Seafile *seafile;
    int i;

    rawdata_to_hex (sha1, file_id, 20);
    seafile = seaf_fs_manager_get_seafile (seaf->fs_mgr, repo_id, version, file_id);
    if (!seafile) {
        g_warning ("Failed to find file %s.\n", file_id);
        return;
    }

    for (i = 0; i < seafile->n_blocks; ++i)
        block_list_insert (bl, seafile->blk_sha1s[i]);

    seafile_unref (seafile);
}

void
collect_new_blocks_from_index (const char *repo_id, int version,
                               struct index_state *index, BlockList *bl)
{
    int i;
    struct cache_entry *ce;

    for (i = 0; i < index->cache_nr; ++i) {
        ce = index->cache[i];
        if (ce->ce_flags & CE_UPDATE)
            fill_seafile_blocks (repo_id, version, ce->sha1, bl);
    }
}
