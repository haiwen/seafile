/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "utils.h"

#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include "block-backend.h"
#include "obj-store.h"


struct _BHandle {
    char    block_id[41];
    int     fd;
    int     rw_type;
    char    *tmp_file;
};

typedef struct {
    char          *block_dir;
    int            block_dir_len;
    char          *tmp_dir;
    int            tmp_dir_len;
} FsPriv;

static char *
get_block_path (BlockBackend *bend,
                const char *block_sha1,
                char path[]);

static int
open_tmp_file (BlockBackend *bend,
               const char *basename,
               char **path);

static BHandle *
block_backend_fs_open_block (BlockBackend *bend,
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
        get_block_path (bend, block_id, path);
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
    g_free (handle);
}

static int
block_backend_fs_commit_block (BlockBackend *bend,
                               BHandle *handle)
{
    char path[SEAF_PATH_MAX];

    g_return_val_if_fail (handle->rw_type == BLOCK_WRITE, -1);

    get_block_path (bend, handle->block_id, path);
    if (ccnet_rename (handle->tmp_file, path) < 0) {
        g_warning ("[block bend] failed to commit block %s: %s\n",
                   handle->block_id, strerror(errno));
        return -1;
    }

    return 0;
}
    
static gboolean
block_backend_fs_block_exists (BlockBackend *bend, const char *block_sha1)
{
    char block_path[SEAF_PATH_MAX];

    get_block_path (bend, block_sha1, block_path);
    if (g_access (block_path, F_OK) == 0)
        return TRUE;
    else
        return FALSE;
}

static int
block_backend_fs_remove_block (BlockBackend *bend,
                                 const char *block_id)
{
    char path[SEAF_PATH_MAX];

    get_block_path (bend, block_id, path);

    return g_unlink (path);
}

static BMetadata *
block_backend_fs_stat_block (BlockBackend *bend,
                             const char *block_id)
{
    char path[SEAF_PATH_MAX];
    SeafStat st;
    BMetadata *block_md;

    get_block_path (bend, block_id, path);
    if (seaf_stat (path, &st) < 0) {
        g_warning ("[block bend] Failed to stat block %s.\n", block_id);
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
        g_warning ("[block bend] Failed to stat block %s.\n", handle->block_id);
        return NULL;
    }
    block_md = g_new0(BMetadata, 1);
    memcpy (block_md->id, handle->block_id, 40);
    block_md->size = (uint32_t) st.st_size;

    return block_md;
}

static int
block_backend_fs_foreach_block (BlockBackend *bend,
                                SeafBlockFunc process,
                                void *user_data)
{
    FsPriv *priv = bend->be_priv;
    char *block_dir = priv->block_dir;
    int dir_len = priv->block_dir_len;
    GDir *dir1, *dir2;
    const char *dname1, *dname2;
    char block_id[128];
    char path[SEAF_PATH_MAX], *pos;
    int ret = 0;

    dir1 = g_dir_open (block_dir, 0, NULL);
    if (!dir1) {
        g_warning ("Failed to open object dir %s.\n", block_dir);
        return -1;
    }

    memcpy (path, block_dir, dir_len);
    pos = path + dir_len;

    while ((dname1 = g_dir_read_name(dir1)) != NULL) {
        snprintf (pos, sizeof(path) - dir_len, "/%s", dname1);

        dir2 = g_dir_open (path, 0, NULL);
        if (!dir2) {
            g_warning ("Failed to open object dir %s.\n", path);
            continue;
        }

        while ((dname2 = g_dir_read_name(dir2)) != NULL) {
            snprintf (block_id, sizeof(block_id), "%s%s", dname1, dname2);
            if (!process (block_id, user_data)) {
                g_dir_close (dir2);
                goto out;
            }
        }
        g_dir_close (dir2);
    }

out:
    g_dir_close (dir1);

    return ret;
}

static char *
get_block_path (BlockBackend *bend,
                const char *block_sha1,
                char path[])
{
    FsPriv *priv = bend->be_priv;
    char *pos = path;

    memcpy (pos, priv->block_dir, priv->block_dir_len);
    pos[priv->block_dir_len] = '/';
    pos += priv->block_dir_len + 1;

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

static void
init_block_dir (BlockBackend *bend)
{
    FsPriv *priv = bend->be_priv;
    int i;
    int len = priv->block_dir_len;
    char path[SEAF_PATH_MAX];
    char *pos;

    memcpy (path, priv->block_dir, len);
    pos = path + len;

    /*
     * Create 256 sub-directories.
     */
    for (i = 0; i < 256; ++i) {
        snprintf (pos, sizeof(path) - len, "/%02x", i);
        if (g_access (path, F_OK) != 0)
            g_mkdir (path, 0777);
    }
}

BlockBackend *
block_backend_fs_new (const char *block_dir, const char *tmp_dir)
{
    BlockBackend *bend;
    FsPriv *priv;

    bend = g_new0(BlockBackend, 1);
    priv = g_new0(FsPriv, 1);
    bend->be_priv = priv;

    priv->block_dir = g_strdup (block_dir);
    priv->tmp_dir = g_strdup (tmp_dir);
    priv->block_dir_len = strlen (block_dir);
    priv->tmp_dir_len = strlen (tmp_dir);

    if (checkdir_with_mkdir (block_dir) < 0) {
        g_warning ("[Block Backend] Blocks dir %s does not exist and"
                   " is unable to create\n", block_dir);
        goto onerror;
    }

    if (checkdir_with_mkdir (tmp_dir) < 0) {
        g_warning ("[Block Backend] Blocks tmp dir %s does not exist and"
                   " is unable to create\n", block_dir);
        goto onerror;
    }

    init_block_dir (bend);

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

    return bend;

onerror:
    g_free (bend);
    g_free (bend->be_priv);

    return NULL;
}
