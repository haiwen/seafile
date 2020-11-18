/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "utils.h"
#include "block-mgr.h"
#include "log.h"

#include <stdio.h>
#include <errno.h>
#ifndef WIN32
#include <unistd.h>
#include <dirent.h>
#endif
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <glib/gstdio.h>

#include "block-backend.h"

#define SEAF_BLOCK_DIR "blocks"


extern BlockBackend *
block_backend_fs_new (const char *block_dir, const char *tmp_dir);


SeafBlockManager *
seaf_block_manager_new (struct _SeafileSession *seaf,
                        const char *seaf_dir)
{
    SeafBlockManager *mgr;

    mgr = g_new0 (SeafBlockManager, 1);
    mgr->seaf = seaf;

    mgr->backend = block_backend_fs_new (seaf_dir, seaf->tmp_file_dir);
    if (!mgr->backend) {
        seaf_warning ("[Block mgr] Failed to load backend.\n");
        goto onerror;
    }

    return mgr;

onerror:
    g_free (mgr);

    return NULL;
}

int
seaf_block_manager_init (SeafBlockManager *mgr)
{
    return 0;
}


BlockHandle *
seaf_block_manager_open_block (SeafBlockManager *mgr,
                               const char *store_id,
                               int version,
                               const char *block_id,
                               int rw_type)
{
    if (!store_id || !is_uuid_valid(store_id) ||
        !block_id || !is_object_id_valid(block_id))
        return NULL;

    return mgr->backend->open_block (mgr->backend,
                                     store_id, version,
                                     block_id, rw_type);
}

int
seaf_block_manager_read_block (SeafBlockManager *mgr,
                               BlockHandle *handle,
                               void *buf, int len)
{
    return mgr->backend->read_block (mgr->backend, handle, buf, len);
}

int
seaf_block_manager_write_block (SeafBlockManager *mgr,
                                BlockHandle *handle,
                                const void *buf, int len)
{
    return mgr->backend->write_block (mgr->backend, handle, buf, len);
}

int
seaf_block_manager_close_block (SeafBlockManager *mgr,
                                BlockHandle *handle)
{
    return mgr->backend->close_block (mgr->backend, handle);
}

void
seaf_block_manager_block_handle_free (SeafBlockManager *mgr,
                                      BlockHandle *handle)
{
    mgr->backend->block_handle_free (mgr->backend, handle);
}

int
seaf_block_manager_commit_block (SeafBlockManager *mgr,
                                 BlockHandle *handle)
{
    return mgr->backend->commit_block (mgr->backend, handle);
}
    
gboolean seaf_block_manager_block_exists (SeafBlockManager *mgr,
                                          const char *store_id,
                                          int version,
                                          const char *block_id)
{
    if (!store_id || !is_uuid_valid(store_id) ||
        !block_id || !is_object_id_valid(block_id))
        return FALSE;

    return mgr->backend->exists (mgr->backend, store_id, version, block_id);
}

int
seaf_block_manager_remove_block (SeafBlockManager *mgr,
                                 const char *store_id,
                                 int version,
                                 const char *block_id)
{
    if (!store_id || !is_uuid_valid(store_id) ||
        !block_id || !is_object_id_valid(block_id))
        return -1;

    return mgr->backend->remove_block (mgr->backend, store_id, version, block_id);
}

BlockMetadata *
seaf_block_manager_stat_block (SeafBlockManager *mgr,
                               const char *store_id,
                               int version,
                               const char *block_id)
{
    if (!store_id || !is_uuid_valid(store_id) ||
        !block_id || !is_object_id_valid(block_id))
        return NULL;

    return mgr->backend->stat_block (mgr->backend, store_id, version, block_id);
}

BlockMetadata *
seaf_block_manager_stat_block_by_handle (SeafBlockManager *mgr,
                                         BlockHandle *handle)
{
    return mgr->backend->stat_block_by_handle (mgr->backend, handle);
}

int
seaf_block_manager_foreach_block (SeafBlockManager *mgr,
                                  const char *store_id,
                                  int version,
                                  SeafBlockFunc process,
                                  void *user_data)
{
    return mgr->backend->foreach_block (mgr->backend,
                                        store_id, version,
                                        process, user_data);
}

int
seaf_block_manager_copy_block (SeafBlockManager *mgr,
                               const char *src_store_id,
                               int src_version,
                               const char *dst_store_id,
                               int dst_version,
                               const char *block_id)
{
    if (strcmp (block_id, EMPTY_SHA1) == 0)
        return 0;

    return mgr->backend->copy (mgr->backend,
                               src_store_id,
                               src_version,
                               dst_store_id,
                               dst_version,
                               block_id);
}

static gboolean
get_block_number (const char *store_id,
                  int version,
                  const char *block_id,
                  void *data)
{
    guint64 *n_blocks = data;

    ++(*n_blocks);

    return TRUE;
}

guint64
seaf_block_manager_get_block_number (SeafBlockManager *mgr,
                                     const char *store_id,
                                     int version)
{
    guint64 n_blocks = 0;

    seaf_block_manager_foreach_block (mgr, store_id, version,
                                      get_block_number, &n_blocks);

    return n_blocks;
}

gboolean
seaf_block_manager_verify_block (SeafBlockManager *mgr,
                                 const char *store_id,
                                 int version,
                                 const char *block_id,
                                 gboolean *io_error)
{
    BlockHandle *h;
    char buf[10240];
    int n;
    GChecksum *cs;
    const char *check_id;
    gboolean ret;

    h = seaf_block_manager_open_block (mgr,
                                       store_id, version,
                                       block_id, BLOCK_READ);
    if (!h) {
        seaf_warning ("Failed to open block %s:%.8s.\n", store_id, block_id);
        *io_error = TRUE;
        return FALSE;
    }

    cs = g_checksum_new (G_CHECKSUM_SHA1);
    while (1) {
        n = seaf_block_manager_read_block (mgr, h, buf, sizeof(buf));
        if (n < 0) {
            seaf_warning ("Failed to read block %s:%.8s.\n", store_id, block_id);
            *io_error = TRUE;
            g_checksum_free (cs);
            return FALSE;
        }
        if (n == 0)
            break;

        g_checksum_update (cs, (guchar *)buf, n);
    }

    seaf_block_manager_close_block (mgr, h);
    seaf_block_manager_block_handle_free (mgr, h);

    check_id = g_checksum_get_string (cs);

    if (strcmp (check_id, block_id) == 0)
        ret = TRUE;
    else
        ret = FALSE;

    g_checksum_free (cs);
    return ret;
}

int
seaf_block_manager_remove_store (SeafBlockManager *mgr,
                                 const char *store_id)
{
    return mgr->backend->remove_store (mgr->backend, store_id);
}
