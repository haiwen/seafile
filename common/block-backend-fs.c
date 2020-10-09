/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x500
#endif

#include "common.h"

#include "utils.h"

#include "log.h"

#include <sys/stat.h>
#include <fcntl.h>
#ifndef WIN32
#include <dirent.h>
#endif

#include "block-backend.h"
#include "obj-store.h"


struct _BHandle {
    char    *store_id;
    int     version;
    char    block_id[41];
    int     fd;
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
    int fd = -1;
    char *tmp_file;

    g_return_val_if_fail (block_id != NULL, NULL);
    g_return_val_if_fail (strlen(block_id) == 40, NULL);
    g_return_val_if_fail (rw_type == BLOCK_READ || rw_type == BLOCK_WRITE, NULL);

    if (rw_type == BLOCK_READ) {
        char path[SEAF_PATH_MAX];
        get_block_path (bend, block_id, path, store_id, version);
        fd = g_open (path, O_RDONLY | O_BINARY, 0);
        if (fd < 0) {
            ccnet_warning ("[block bend] failed to open block %s for read: %s\n",
                           block_id, strerror(errno));
            return NULL;
        }
    } else {
        fd = open_tmp_file (bend, block_id, &tmp_file);
        if (fd < 0) {
            ccnet_warning ("[block bend] failed to open block %s for write: %s\n",
                           block_id, strerror(errno));
            return NULL;
        }
    }

    handle = g_new0(BHandle, 1);
    handle->fd = fd;
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
    return (readn (handle->fd, buf, len));
}

static int
block_backend_fs_write_block (BlockBackend *bend,
                                BHandle *handle,
                                const void *buf, int len)
{
    return (writen (handle->fd, buf, len));
}

static int
block_backend_fs_close_block (BlockBackend *bend,
                                BHandle *handle)
{
    int ret;

    ret = close (handle->fd);

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
create_parent_path (const char *path)
{
    char *dir = g_path_get_dirname (path);
    if (!dir)
        return -1;

    if (g_file_test (dir, G_FILE_TEST_EXISTS)) {
        g_free (dir);
        return 0;
    }

    if (g_mkdir_with_parents (dir, 0777) < 0) {
        seaf_warning ("Failed to create object parent path: %s.\n", dir);
        g_free (dir);
        return -1;
    }

    g_free (dir);
    return 0;
}

static int
block_backend_fs_commit_block (BlockBackend *bend,
                               BHandle *handle)
{
    char path[SEAF_PATH_MAX];

    g_return_val_if_fail (handle->rw_type == BLOCK_WRITE, -1);

    get_block_path (bend, handle->block_id, path, handle->store_id, handle->version);

    if (create_parent_path (path) < 0) {
        seaf_warning ("Failed to create path for block %s:%s.\n",
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

    return g_unlink (path);
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

    if (create_parent_path (dst_path) < 0) {
        seaf_warning ("Failed to create dst path %s for block %s.\n",
                      dst_path, block_id);
        return -1;
    }

#ifdef WIN32
    if (!CreateHardLinkA (dst_path, src_path, NULL)) {
        seaf_warning ("Failed to link %s to %s: %lu.\n",
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
            g_free (block_dir);
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
