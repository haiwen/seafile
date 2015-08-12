/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x500
#endif

#include "common.h"

#ifdef WIN32
#include <windows.h>
#endif

#include "utils.h"

#include "log.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "block-backend.h"
#include "obj-store.h"


struct _BHandle {
    char    *store_id;
    int     version;
    char    block_id[41];
#ifdef WIN32
    HANDLE  fh;
#else
    int     fd;
#endif
    int     rw_type;
    char    *tmp_file;
};

typedef struct {
    char          *v0_block_dir;
    int            v0_block_dir_len;
    char          *block_dir;
    int            block_dir_len;
    char          *tmp_dir;
    int            tmp_dir_len;
} FsPriv;

static char *
get_block_path (BlockBackend *bend,
                const char *block_sha1,
                char path[],
                const char *store_id,
                int version);

static int
open_tmp_file (BlockBackend *bend,
               const char *basename,
               char **path);

static BHandle *
block_backend_fs_open_block (BlockBackend *bend,
                             const char *store_id,
                             int version,
                             const char *block_id,
                             int rw_type)
{
    BHandle *handle;
#ifdef WIN32
    HANDLE h = INVALID_HANDLE_VALUE;
#else
    int fd = -1;
#endif
    char *tmp_file;

    g_return_val_if_fail (block_id != NULL, NULL);
    g_return_val_if_fail (strlen(block_id) == 40, NULL);
    g_return_val_if_fail (rw_type == BLOCK_READ || rw_type == BLOCK_WRITE, NULL);

    if (rw_type == BLOCK_READ) {
        char path[SEAF_PATH_MAX];
        get_block_path (bend, block_id, path, store_id, version);
#ifdef WIN32
        wchar_t *wpath = g_utf8_to_utf16 (path, -1, NULL, NULL, NULL);
        h = CreateFileW (wpath,
                         GENERIC_READ,
                         FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                         NULL,
                         OPEN_EXISTING,
                         0,
                         NULL);
        g_free (wpath);
        if (h == INVALID_HANDLE_VALUE) {
            seaf_warning ("[block bend] failed to open block %s:%s for read: %lu\n ",
                          store_id, block_id, GetLastError());
            return NULL;
        }
#else
        fd = g_open (path, O_RDONLY | O_BINARY, 0);
        if (fd < 0) {
            seaf_warning ("[block bend] failed to open block %s:%s for read: %s\n",
                          store_id, block_id, strerror(errno));
            return NULL;
        }
#endif
    } else {
#ifdef WIN32
        h = open_tmp_file (bend, block_id, &tmp_file);
        if (h == INVALID_HANDLE_VALUE) {
            seaf_warning ("[block bend] failed to open block %s:%s for write: %lu\n",
                          store_id, block_id, GetLastError());
            return NULL;
        }
#else
        fd = open_tmp_file (bend, block_id, &tmp_file);
        if (fd < 0) {
            seaf_warning ("[block bend] failed to open block %s:%s for write: %s\n",
                          store_id, block_id, strerror(errno));
            return NULL;
        }
#endif
    }

    handle = g_new0(BHandle, 1);
#ifdef WIN32
    handle->fh = h;
#else
    handle->fd = fd;
#endif
    memcpy (handle->block_id, block_id, 41);
    handle->rw_type = rw_type;
    if (rw_type == BLOCK_WRITE)
        handle->tmp_file = tmp_file;
    if (store_id)
        handle->store_id = g_strdup(store_id);
    handle->version = version;

    return handle;
}

static int
block_backend_fs_read_block (BlockBackend *bend,
                             BHandle *handle,
                             void *buf, int len)
{
#ifdef WIN32
    DWORD n;
    if (!ReadFile (handle->fh, buf, len, &n, NULL)) {
        seaf_warning ("Failed to read block %s:%s: %lu\n",
                      handle->store_id, handle->block_id, GetLastError());
        return -1;
    }
    return (int)n;
#else
    return (readn (handle->fd, buf, len));
#endif
}

static int
block_backend_fs_write_block (BlockBackend *bend,
                              BHandle *handle,
                              const void *buf, int len)
{
#ifdef WIN32
    DWORD n;
    if (!WriteFile (handle->fh, buf, len, &n, NULL)) {
        seaf_warning ("Failed to write block %s:%s: %lu\n",
                      handle->store_id, handle->block_id, GetLastError());
        return -1;
    }
    return (int)n;
#else
    return (writen (handle->fd, buf, len));
#endif
}

static int
block_backend_fs_close_block (BlockBackend *bend,
                              BHandle *handle)
{
    int ret = 0;

#ifdef WIN32
    if (!CloseHandle (handle->fh)) {
        seaf_warning ("Failed to close block %s:%s: %lu\n",
                      handle->store_id, handle->block_id, GetLastError());
        ret = -1;
    }
#else
    ret = close (handle->fd);
#endif

    return ret;
}

static void
block_backend_fs_block_handle_free (BlockBackend *bend,
                                    BHandle *handle)
{
    if (handle->rw_type == BLOCK_WRITE) {
        /* make sure the tmp file is removed even on failure. */
        g_unlink (handle->tmp_file);
        g_free (handle->tmp_file);
    }
    g_free (handle->store_id);
    g_free (handle);
}

static int
create_parent_path (BlockBackend *bend,
                    const char *store_id,
                    const char *block_id)
{
    FsPriv *priv = bend->be_priv;
    /* store_id(36) + / + block_prefix(2) + '\0' */
    char new_path[40];

    snprintf (new_path, sizeof(new_path), "%s/%.2s", store_id, block_id);

    return seaf_util_mkdir_with_parents (priv->block_dir, new_path, 0777);
}

static int
block_backend_fs_commit_block (BlockBackend *bend,
                               BHandle *handle)
{
    char path[SEAF_PATH_MAX];

    g_return_val_if_fail (handle->rw_type == BLOCK_WRITE, -1);

    get_block_path (bend, handle->block_id, path, handle->store_id, handle->version);

    if (create_parent_path (bend, handle->store_id, handle->block_id) < 0) {
        seaf_warning ("Failed to create parent path for block %s:%s.\n",
                      handle->store_id, handle->block_id);
        return -1;
    }

    if (g_rename (handle->tmp_file, path) < 0) {
        seaf_warning ("[block bend] failed to commit block %s:%s: %s\n",
                      handle->store_id, handle->block_id, strerror(errno));
        return -1;
    }

    return 0;
}
    
static gboolean
block_backend_fs_block_exists (BlockBackend *bend,
                               const char *store_id,
                               int version,
                               const char *block_sha1)
{
    char block_path[SEAF_PATH_MAX];

    get_block_path (bend, block_sha1, block_path, store_id, version);
    if (g_access (block_path, F_OK) == 0)
        return TRUE;
    else
        return FALSE;
}

static int
block_backend_fs_remove_block (BlockBackend *bend,
                               const char *store_id,
                               int version,
                               const char *block_id)
{
    char path[SEAF_PATH_MAX];

    get_block_path (bend, block_id, path, store_id, version);

    return seaf_util_unlink (path);
}

static BMetadata *
block_backend_fs_stat_block (BlockBackend *bend,
                             const char *store_id,
                             int version,
                             const char *block_id)
{
    char path[SEAF_PATH_MAX];
    SeafStat st;
    BMetadata *block_md;

    get_block_path (bend, block_id, path, store_id, version);
    if (seaf_stat (path, &st) < 0) {
        seaf_warning ("[block bend] Failed to stat block %s:%s at %s: %s.\n",
                      store_id, block_id, path, strerror(errno));
        return NULL;
    }
    block_md = g_new0(BMetadata, 1);
    memcpy (block_md->id, block_id, 40);
    block_md->size = (uint32_t) st.st_size;

    return block_md;
}

static BMetadata *
block_backend_fs_stat_block_by_handle (BlockBackend *bend,
                                       BHandle *handle)
{
    SeafStat st;
    BMetadata *block_md;

    if (seaf_fstat (handle->fd, &st) < 0) {
        seaf_warning ("[block bend] Failed to stat block %s:%s.\n",
                      handle->store_id, handle->block_id);
        return NULL;
    }
    block_md = g_new0(BMetadata, 1);
    memcpy (block_md->id, handle->block_id, 40);
    block_md->size = (uint32_t) st.st_size;

    return block_md;
}

static int
block_backend_fs_foreach_block (BlockBackend *bend,
                                const char *store_id,
                                int version,
                                SeafBlockFunc process,
                                void *user_data)
{
    FsPriv *priv = bend->be_priv;
    char *block_dir = NULL;
    int dir_len;
    GDir *dir1 = NULL, *dir2;
    const char *dname1, *dname2;
    char block_id[128];
    char path[SEAF_PATH_MAX], *pos;
    int ret = 0;

#if defined MIGRATION
    if (version > 0)
        block_dir = g_build_filename (priv->block_dir, store_id, NULL);
    else
        block_dir = g_strdup(priv->v0_block_dir);
#else
    block_dir = g_build_filename (priv->block_dir, store_id, NULL);
#endif
    dir_len = strlen (block_dir);

    dir1 = g_dir_open (block_dir, 0, NULL);
    if (!dir1) {
        goto out;
    }

    memcpy (path, block_dir, dir_len);
    pos = path + dir_len;

    while ((dname1 = g_dir_read_name(dir1)) != NULL) {
        snprintf (pos, sizeof(path) - dir_len, "/%s", dname1);

        dir2 = g_dir_open (path, 0, NULL);
        if (!dir2) {
            seaf_warning ("Failed to open block dir %s.\n", path);
            continue;
        }

        while ((dname2 = g_dir_read_name(dir2)) != NULL) {
            snprintf (block_id, sizeof(block_id), "%s%s", dname1, dname2);
            if (!process (store_id, version, block_id, user_data)) {
                g_dir_close (dir2);
                goto out;
            }
        }
        g_dir_close (dir2);
    }

out:
    if (dir1)
        g_dir_close (dir1);
    g_free (block_dir);

    return ret;
}

static int
block_backend_fs_copy (BlockBackend *bend,
                       const char *src_store_id,
                       int src_version,
                       const char *dst_store_id,
                       int dst_version,
                       const char *block_id)
{
    char src_path[SEAF_PATH_MAX];
    char dst_path[SEAF_PATH_MAX];

    get_block_path (bend, block_id, src_path, src_store_id, src_version);
    get_block_path (bend, block_id, dst_path, dst_store_id, dst_version);

    if (g_file_test (dst_path, G_FILE_TEST_EXISTS))
        return 0;

    if (create_parent_path (bend, dst_store_id, block_id) < 0) {
        seaf_warning ("Failed to create dst path %s for block %s.\n",
                      dst_path, block_id);
        return -1;
    }

#ifdef WIN32
    if (!CreateHardLink (dst_path, src_path, NULL)) {
        seaf_warning ("Failed to link %s to %s: %d.\n",
                      src_path, dst_path, GetLastError());
        return -1;
    }
    return 0;
#else
    int ret = link (src_path, dst_path);
    if (ret < 0 && errno != EEXIST) {
        seaf_warning ("Failed to link %s to %s: %s.\n",
                      src_path, dst_path, strerror(errno));
        return -1;
    }
    return ret;
#endif
}

static int
block_backend_fs_remove_store (BlockBackend *bend, const char *store_id)
{
    FsPriv *priv = bend->be_priv;
    char *block_dir = NULL;
    GDir *dir1, *dir2;
    const char *dname1, *dname2;
    char *path1, *path2;

    block_dir = g_build_filename (priv->block_dir, store_id, NULL);

    dir1 = g_dir_open (block_dir, 0, NULL);
    if (!dir1) {
        g_free (block_dir);
        return 0;
    }

    while ((dname1 = g_dir_read_name(dir1)) != NULL) {
        path1 = g_build_filename (block_dir, dname1, NULL);

        dir2 = g_dir_open (path1, 0, NULL);
        if (!dir2) {
            seaf_warning ("Failed to open block dir %s.\n", path1);
            g_dir_close (dir1);
            g_free (path1);
            return -1;
        }

        while ((dname2 = g_dir_read_name(dir2)) != NULL) {
            path2 = g_build_filename (path1, dname2, NULL);
            g_unlink (path2);
            g_free (path2);
        }
        g_dir_close (dir2);

        g_rmdir (path1);
        g_free (path1);
    }

    g_dir_close (dir1);
    g_rmdir (block_dir);
    g_free (block_dir);

    return 0;
}

static char *
get_block_path (BlockBackend *bend,
                const char *block_sha1,
                char path[],
                const char *store_id,
                int version)
{
    FsPriv *priv = bend->be_priv;
    char *pos = path;
    int n;

#if defined MIGRATION
    if (version > 0) {
        n = snprintf (path, SEAF_PATH_MAX, "%s/%s/", priv->block_dir, store_id);
        pos += n;
    } else {
        memcpy (pos, priv->v0_block_dir, priv->v0_block_dir_len);
        pos[priv->v0_block_dir_len] = '/';
        pos += priv->v0_block_dir_len + 1;
    }
#else
    n = snprintf (path, SEAF_PATH_MAX, "%s/%s/", priv->block_dir, store_id);
    pos += n;
#endif

    memcpy (pos, block_sha1, 2);
    pos[2] = '/';
    pos += 3;

    memcpy (pos, block_sha1 + 2, 41 - 2);

    return path;
}

#ifdef WIN32
static HANDLE
open_tmp_file (BlockBackend *bend,
               const char *basename,
               char **path)
{
    FsPriv *priv = bend->be_priv;
    wchar_t temp_filename_w[MAX_PATH];
    wchar_t *temp_path_w, *prefix_str_w;
    HANDLE h = INVALID_HANDLE_VALUE;

    temp_path_w = g_utf8_to_utf16 (priv->tmp_dir, -1, NULL, NULL, NULL);
    prefix_str_w = g_utf8_to_utf16 (basename, -1, NULL, NULL, NULL);

    if (!GetTempFileNameW (temp_path_w, prefix_str_w, 0, temp_filename_w)) {
        seaf_warning ("Failed to GetTempFileNameW: %lu\n", GetLastError());
        goto out;
    }

    h = CreateFileW (temp_filename_w,
                     GENERIC_WRITE,
                     0,
                     NULL,
                     CREATE_ALWAYS,
                     FILE_ATTRIBUTE_NORMAL,
                     NULL);
    if (h == INVALID_HANDLE_VALUE) {
        seaf_warning ("Failed to CreateFileW: %lu\n", GetLastError());
        goto out;
    }

    *path = g_utf16_to_utf8 (temp_filename_w, -1, NULL, NULL, NULL);

out:
    g_free (temp_path_w);
    g_free (prefix_str_w);
    return h;
}
#else
static int
open_tmp_file (BlockBackend *bend,
               const char *basename,
               char **path)
{
    FsPriv *priv = bend->be_priv;
    int fd;

    *path = g_strdup_printf ("%s/%s.XXXXXX", priv->tmp_dir, basename);
    fd = g_mkstemp (*path);
    if (fd < 0)
        g_free (*path);

    return fd;
}
#endif

BlockBackend *
block_backend_fs_new (const char *seaf_dir, const char *tmp_dir)
{
    BlockBackend *bend;
    FsPriv *priv;

    bend = g_new0(BlockBackend, 1);
    priv = g_new0(FsPriv, 1);
    bend->be_priv = priv;

    priv->v0_block_dir = g_build_filename (seaf_dir, "blocks", NULL);
    priv->v0_block_dir_len = strlen(priv->v0_block_dir);

    priv->block_dir = g_build_filename (seaf_dir, "storage", "blocks", NULL);
    priv->block_dir_len = strlen (priv->block_dir);

    priv->tmp_dir = g_strdup (tmp_dir);
    priv->tmp_dir_len = strlen (tmp_dir);

    if (g_mkdir_with_parents (priv->block_dir, 0777) < 0) {
        seaf_warning ("Block dir %s does not exist and"
                   " is unable to create\n", priv->block_dir);
        goto onerror;
    }

    if (g_mkdir_with_parents (tmp_dir, 0777) < 0) {
        seaf_warning ("Blocks tmp dir %s does not exist and"
                   " is unable to create\n", tmp_dir);
        goto onerror;
    }

    bend->open_block = block_backend_fs_open_block;
    bend->read_block = block_backend_fs_read_block;
    bend->write_block = block_backend_fs_write_block;
    bend->commit_block = block_backend_fs_commit_block;
    bend->close_block = block_backend_fs_close_block;
    bend->exists = block_backend_fs_block_exists;
    bend->remove_block = block_backend_fs_remove_block;
    bend->stat_block = block_backend_fs_stat_block;
    bend->stat_block_by_handle = block_backend_fs_stat_block_by_handle;
    bend->block_handle_free = block_backend_fs_block_handle_free;
    bend->foreach_block = block_backend_fs_foreach_block;
    bend->remove_store = block_backend_fs_remove_store;
    bend->copy = block_backend_fs_copy;

    return bend;

onerror:
    g_free (bend);
    g_free (bend->be_priv);

    return NULL;
}
