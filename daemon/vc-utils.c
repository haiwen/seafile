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
        seaf_warning ("Failed to open shadow index: %s.\n", strerror(errno));
        return -1;
    }

    if (write_index (istate, index_fd) < 0) {
        seaf_warning ("Failed to write shadow index: %s.\n", strerror(errno));
        close (index_fd);
        return -1;
    }
    close (index_fd);

    ret = seaf_util_rename (index_shadow, index_path);
    if (ret < 0) {
        seaf_warning ("Failed to update index errno=%d %s\n", errno, strerror(errno));
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
        (!dname || seaf_repo_manager_is_ignored_hidden_file(dname))) {
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
compute_file_id_with_cdc (const char *path, SeafStat *st,
                          SeafileCrypt *crypt, int repo_version,
                          uint32_t blk_avg_size, uint32_t blk_min_size, uint32_t blk_max_size,
                          unsigned char sha1[])
{
    CDCFileDescriptor cdc;

    memset (&cdc, 0, sizeof(cdc));
    cdc.block_sz = blk_avg_size;
    cdc.block_min_sz = blk_min_size;
    cdc.block_max_sz = blk_max_size;
    cdc.write_block = seafile_write_chunk;
    if (filename_chunk_cdc (path, &cdc, crypt, FALSE) < 0) {
        seaf_warning ("Failed to chunk file.\n");
        return -1;
    }

    if (repo_version > 0)
        seaf_fs_manager_calculate_seafile_id_json (repo_version, &cdc, sha1);
    else
        memcpy (sha1, cdc.file_sum, 20);

    if (cdc.blk_sha1s)
        free (cdc.blk_sha1s);

    return 0;
}

int
compare_file_content (const char *path, SeafStat *st, const unsigned char *ce_sha1,
                      SeafileCrypt *crypt, int repo_version)
{
    unsigned char sha1[20];

    if (st->st_size == 0) {
        memset (sha1, 0, 20);
        return hashcmp (sha1, ce_sha1);
    } else {
        if (seaf->cdc_average_block_size == 0) {
            if (compute_file_id_with_cdc (path, st, crypt, repo_version,
                                          CDC_AVERAGE_BLOCK_SIZE,
                                          CDC_MIN_BLOCK_SIZE,
                                          CDC_MAX_BLOCK_SIZE,
                                          sha1) < 0) {
                return -1;
            }
        } else {
            if (compute_file_id_with_cdc (path, st, crypt, repo_version,
                                          seaf->cdc_average_block_size,
                                          seaf->cdc_average_block_size >> 1,
                                          seaf->cdc_average_block_size << 1,
                                          sha1) < 0) {
                return -1;
            }            
        }
        if (hashcmp (sha1, ce_sha1) == 0)
            return 0;

        /* Compare with old cdc block size. */
        uint32_t block_size = calculate_chunk_size (st->st_size);
        if (compute_file_id_with_cdc (path, st, crypt, repo_version,
                                      block_size,
                                      block_size >> 2,
                                      block_size << 2,
                                      sha1) < 0) {
            return -1;
        }
        return hashcmp (sha1, ce_sha1);
    }
}

char *
build_checkout_path (const char *worktree, const char *ce_name, int len)
{
    int base_len = strlen(worktree);
    int full_len;
    int offset;
    SeafStat st;

    if (!len) {
        seaf_warning ("entry name should not be empty.\n");
        return NULL;
    }

    GString *path = g_string_new ("");

    g_string_append_printf (path, "%s/", worktree);

    /* first create all leading directories. */
    full_len = base_len + len + 1;
    offset = base_len + 1;
    while (offset < full_len) {
        do {
            g_string_append_c (path, ce_name[offset-base_len-1]);
            offset++;
        } while (offset < full_len && ce_name[offset-base_len-1] != '/');
        if (offset >= full_len)
            break;

        if (seaf_stat (path->str, &st) == 0 && S_ISDIR(st.st_mode))
            continue;
        
        if (seaf_util_mkdir (path->str, 0777) < 0) {
            g_string_free (path, TRUE);
            seaf_warning ("Failed to create directory %s.\n", path->str);
            return NULL;
        }
    }

    return g_string_free (path, FALSE);
}

int
delete_path (const char *worktree, const char *name,
             unsigned int mode, gint64 old_mtime)
{
    char path[SEAF_PATH_MAX];
    SeafStat st;
    int len = strlen(name);

    if (!len) {
        seaf_warning ("entry name should not be empty.\n");
        return -1;
    }

    snprintf (path, SEAF_PATH_MAX, "%s/%s", worktree, name);

    if (!S_ISDIR(mode)) {
        /* file doesn't exist in work tree */
        if (seaf_stat (path, &st) < 0 || !S_ISREG(st.st_mode)) {
            return 0;
        }

        /* file has been changed. */
        if (!is_eml_file (name) && (old_mtime != st.st_mtime)) {
            seaf_warning ("File %s is changed. Skip removing the file.\n", path);
            return -1;
        }

        /* first unlink the file. */
        if (seaf_util_unlink (path) < 0) {
            seaf_warning ("Failed to remove %s: %s.\n", path, strerror(errno));
            return -1;
        }
    } else {
        if (seaf_remove_empty_dir (path) < 0) {
            seaf_warning ("Failed to remove dir %s: %s.\n", path, strerror(errno));
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
check_file_locked (const wchar_t *path_w, gboolean locked_on_server)
{
    HANDLE handle;
    /* If the file is locked on server, its local access right has been set to
     * read-only. So trying to test GENERIC_WRITE access will certainly return
     * ACCESS_DENIED. In this case, we can only test for GENERIC_READ.
     * MS Office seems to gain exclusive read/write access to the file. So even
     * trying read access can return a SHARING_VIOLATION error.
     */
    DWORD access_mode = locked_on_server ? GENERIC_READ : GENERIC_WRITE;

    handle = CreateFileW (path_w,
                          access_mode,
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
do_check_file_locked (const char *path, const char *worktree, gboolean locked_on_server)
{
    char *real_path;
    wchar_t *real_path_w;
    gboolean ret;
    real_path = g_build_path(PATH_SEPERATOR, worktree, path, NULL);
    real_path_w = win32_long_path (real_path);
    ret = check_file_locked (real_path_w, locked_on_server);
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
    char *path;
    int path_len_w;
    DWORD error;
    gboolean ret = FALSE;

    if (check_dir_locked (path_w))
        return TRUE;

    path = g_utf16_to_utf8 (path_w, -1, NULL, NULL, NULL);
    if (!path)
        return FALSE;

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
            if (check_file_locked (sub_path_w, FALSE)) {
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

out:
    FindClose (handle);
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
                if (do_check_file_locked (ce->name, worktree, FALSE)) {
                    ret = TRUE;
                    break;
                }
            }
        } else if (ce->ce_flags & CE_UPDATE ||
                   ce->ce_flags & CE_WT_REMOVE) {
            if (do_check_file_locked (ce->name, worktree, FALSE)) {
                ret = TRUE;
                break;
            }
        }
    }

    return ret;
}

#endif  /* WIN32 */

#ifdef __APPLE__

/* On Mac, we only check whether an office file is opened and locked.
 * The detection is done by checking ~$* tmp file.
 */
gboolean
do_check_file_locked (const char *path, const char *worktree, gboolean locked_on_server)
{
#define OFFICE_FILE_PATTERN ".*\\.(docx|xlsx|pptx|doc|xls|ppt|vsdx)"
    char *dir_name = NULL, *file_name = NULL;
    char *fullpath = NULL;
    char *tmp_name = NULL;
    int ret = FALSE;

    if (!g_regex_match_simple (OFFICE_FILE_PATTERN, path, 0, 0))
        return FALSE;

    dir_name = g_path_get_dirname (path);
    if (strcmp (dir_name, ".") == 0) {
        g_free (dir_name);
        dir_name = g_strdup("");
    }
    file_name = g_path_get_basename (path);

    tmp_name = g_strconcat ("~$", file_name, NULL);
    fullpath = g_build_path ("/", worktree, dir_name, tmp_name, NULL);
    if (g_file_test (fullpath, G_FILE_TEST_IS_REGULAR)) {
        ret = TRUE;
        goto out;
    }
    g_free (tmp_name);
    g_free (fullpath);

    /* Sometimes the first two characters are replaced by ~$. */

    if (g_utf8_strlen(file_name, -1) < 2)
        goto out;

    char *ptr = g_utf8_find_next_char(g_utf8_find_next_char (file_name, NULL), NULL);
    tmp_name = g_strconcat ("~$", ptr, NULL);
    fullpath = g_build_path ("/", worktree, dir_name, tmp_name, NULL);
    if (g_file_test (fullpath, G_FILE_TEST_IS_REGULAR)) {
        ret = TRUE;
        goto out;
    }

out:
    g_free (fullpath);
    g_free (tmp_name);
    g_free (dir_name);
    g_free (file_name);
    return ret;
}

#endif
