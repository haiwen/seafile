
#include "common.h"
#include "log.h"
#include "block-backend.h"

#ifdef HAVE_RADOS

#include <rados/librados.h>
#include <event2/buffer.h>

#include "utils.h"

#define CEPH_COMMIT_EA_NAME "commit"
#define MAX_BUFFER_SIZE 1 << 20 /* Buffer 1MB data */

struct _BHandle {
    char block_id[41];
    int rw_type;
    uint64_t off;
    /* We need to cache data because it's not efficient to
     * read/write data in small pieces for Rados.
     */
    struct evbuffer *buffer;
};

typedef struct {
    char *ceph_config;
    char *poolname;
    rados_t cluster;
    rados_ioctx_t io;
} CephPriv;

BHandle *
block_backend_ceph_open_block (BlockBackend *bend,
                               const char *block_id,
                               int rw_type)
{
    BHandle *handle;

    g_return_val_if_fail (block_id != NULL, NULL);
    g_return_val_if_fail (strlen(block_id) == 40, NULL);
    g_return_val_if_fail (rw_type == BLOCK_READ || rw_type == BLOCK_WRITE, NULL);

    handle = g_new0(BHandle, 1);
    memcpy (handle->block_id, block_id, 41);
    handle->rw_type = rw_type;
    handle->off = 0;
    handle->buffer = evbuffer_new ();

    return handle;
}

int
block_backend_ceph_read_block (BlockBackend *bend, BHandle *handle,
                               void *buf, int len)
{
    CephPriv *priv = bend->be_priv;
    char *tmp_buf;
    int ret;

    if (len <= evbuffer_get_length (handle->buffer)) {
        evbuffer_remove (handle->buffer, buf, len);
        return len;
    }

    tmp_buf = g_new (char, MAX_BUFFER_SIZE);

    do {
        ret = rados_read (priv->io, handle->block_id,
                          tmp_buf, MAX_BUFFER_SIZE, handle->off);
        if (ret == 0) {
            g_free (tmp_buf);
            if (evbuffer_get_length (handle->buffer) != 0)
                return evbuffer_remove (handle->buffer, buf, len);
            else
                return 0;
        } else if (ret < 0) {
            g_free (tmp_buf);
            return ret;
        }
        handle->off += ret;

        if (evbuffer_add (handle->buffer, tmp_buf, ret) < 0) {
            seaf_warning ("[block bend] Failed to add to buffer.\n");
            g_free (tmp_buf);
            return -1;
        }
    } while (len > evbuffer_get_length (handle->buffer));

    g_free (tmp_buf);

    return evbuffer_remove (handle->buffer, buf, len);
}

static int
write_all (rados_ioctx_t io,
           const char *block_id,
           char *in_buf,
           size_t in_len,
           uint64_t in_off)
{
    char *buf = in_buf;
    size_t len = in_len;
    uint64_t off = in_off;
    int n;

    do {
        n = rados_write (io, block_id, buf, len, off);
        if (n < 0)
            return -1;
        buf += n;
        len -= n;
        off += n;
    } while (len > 0);

    return in_len;
}

static int
flush_buffer (rados_ioctx_t io, BlockHandle *handle)
{
    char *tmp_buf;
    size_t buf_len;
    int ret;

    buf_len = evbuffer_get_length (handle->buffer);

    tmp_buf = g_new (char, buf_len);
    if (!tmp_buf) {
        seaf_warning ("[block bend] Not enough memory.\n");
        return -1;
    }
    evbuffer_remove (handle->buffer, tmp_buf, buf_len);

    ret = write_all (io, handle->block_id, tmp_buf, buf_len, handle->off);
    if (ret < 0) {
        seaf_warning ("[block bend] Failed to read block %s.\n",
                       handle->block_id);
        g_free (tmp_buf);
        return ret;
    }
    handle->off += ret;

    g_free (tmp_buf);
    return ret;
}

int
block_backend_ceph_write_block (BlockBackend *bend,
                                BHandle *handle,
                                const void *buf, int len)
{
    CephPriv *priv = bend->be_priv;

    if (evbuffer_add (handle->buffer, buf, len) < 0) {
        seaf_warning ("[block bend] Failed to add to buffer.\n");
        return -1;
    }

    if (evbuffer_get_length (handle->buffer) < MAX_BUFFER_SIZE)
        return len;

    return flush_buffer (priv->io, handle);
}

int
block_backend_ceph_close_block (BlockBackend *bend, BHandle *handle)
{
    CephPriv *priv = bend->be_priv;

    if (handle->rw_type == BLOCK_WRITE &&
        evbuffer_get_length (handle->buffer) != 0)
        return flush_buffer (priv->io, handle);

    return 0;
}

void
block_backend_ceph_block_handle_free (BlockBackend *bend, BHandle *handle)
{
    evbuffer_free (handle->buffer);
    g_free (handle);
}

int
block_backend_ceph_commit_block (BlockBackend *bend, BHandle *handle)
{
    CephPriv *priv = bend->be_priv;
    char *key = CEPH_COMMIT_EA_NAME;
    char *value = "1";
    int err;

    g_return_val_if_fail (handle->rw_type == BLOCK_WRITE, -1);

    err = rados_setxattr (priv->io, handle->block_id, key,
                          value, strlen(value));
    if (err < 0) {
        ccnet_warning ("[block bend] Failed to commit block %s: %s\n",
                       handle->block_id, strerror(-err));
        return -1;
    }

    return 0;
}

/*
 * There is no a good method to check whether a block has existed or not.
 * So we call rados_getxattr().  If we cannot get 'commit' attribute, it
 * means that some data are written in this block, but this operation
 * hasn't finished.
 */
gboolean
block_backend_ceph_block_exists (BlockBackend *bend, const char *block_sha1)
{
    CephPriv *priv = bend->be_priv;
    char buf[2];
    int err;

    err = rados_getxattr (priv->io, block_sha1, CEPH_COMMIT_EA_NAME, buf, sizeof(buf));
    if (err < 0) {
        return FALSE;
    }

    /* XXX: extend attribute doesn't contain NULL-terminator.  Thus, we should
     * take care of it.
     */
    buf[1] = '\0';  /* only for safty */
    if (strncmp(buf, "1", 1))
        return FALSE;

    return TRUE;
}

int
block_backend_ceph_remove_block (BlockBackend *bend,
                                 const char *block_id)
{
    CephPriv *priv = bend->be_priv;
    int err;

    /* 
     * Extend attribute will be removed when the block is removed.  So we don't
     * need to call rados_rmxattr.
     */
    err = rados_remove (priv->io, block_id);
    if (err < 0) {
        ccnet_warning ("[block bend] Failed to remove block %s.\n", block_id);
        return -1;
    }

    return 0;
}

BMetadata *
block_backend_ceph_stat_block (BlockBackend *bend,
                               const char *block_id)
{
    CephPriv *priv = bend->be_priv;
    BMetadata *block_md;
    int err;
    uint64_t size;
    time_t mtime;

    err = rados_stat (priv->io, block_id, &size, &mtime);
    if (err < 0) {
        ccnet_warning ("[Block bend] Failed to stat block %s.\n", block_id);
        return NULL;
    }
    block_md = g_new0(BMetadata, 1);
    memcpy (block_md->id, block_id, 40);
    block_md->size = (uint32_t)size;

    return block_md;
}

BMetadata *
block_backend_ceph_stat_block_by_handle (BlockBackend *bend,
                                         BHandle *handle)
{
    return block_backend_ceph_stat_block(bend, handle->block_id);
}

int
block_backend_ceph_foreach_block (BlockBackend *bend,
                                  SeafBlockFunc process,
                                  void *user_data)
{
    return 0;
}

static int ceph_init (CephPriv *priv, const char *ceph_conf,
                      const char *poolname)
{
    int err;

    err = rados_create(&priv->cluster, NULL);
    if (err < 0) {
        ccnet_warning ("[Block backend] Cannot create a cluster handle\n");
        return -1;
    }

    err = rados_conf_read_file(priv->cluster, ceph_conf);
    if (err < 0) {
        ccnet_warning ("[Block backend] Cannot read config file\n");
        return -1;
    }

    err = rados_connect(priv->cluster);
    if (err < 0) {
        ccnet_warning ("[Block backend] Cannot connect to cluster\n");
        return -1;
    }

    err = rados_ioctx_create(priv->cluster, poolname, &priv->io);
    if (err < 0) {
        ccnet_warning ("[block bend] failed to open rados pool %s.\n",
                      poolname);
        rados_shutdown (priv->cluster);
        return -1;
    }

    priv->ceph_config = g_strdup (ceph_conf);
    priv->poolname = g_strdup (poolname);

    return 0;
}

BlockBackend *
block_backend_ceph_new (const char *ceph_conf, const char *poolname)
{
    BlockBackend *bend;
    CephPriv *priv;

    bend = g_new0(BlockBackend, 1);
    priv = g_new0(CephPriv, 1);
    bend->be_priv = priv;

    if (ceph_init(priv, ceph_conf, poolname) < 0) {
        g_warning ("[Block backend] Failed to init ceph: pool name is %s.\n",
                   poolname);
        goto error;
    }

    bend->open_block = block_backend_ceph_open_block;
    bend->read_block = block_backend_ceph_read_block;
    bend->write_block = block_backend_ceph_write_block;
    bend->commit_block = block_backend_ceph_commit_block;
    bend->close_block = block_backend_ceph_close_block;
    bend->exists = block_backend_ceph_block_exists;
    bend->remove_block = block_backend_ceph_remove_block;
    bend->stat_block = block_backend_ceph_stat_block;
    bend->stat_block_by_handle = block_backend_ceph_stat_block_by_handle;
    bend->block_handle_free = block_backend_ceph_block_handle_free;
    bend->foreach_block = block_backend_ceph_foreach_block;

    return bend;

error:
    g_free(priv);
    g_free(bend);

    return NULL;
}

#else

BlockBackend *
block_backend_ceph_new (const char *ceph_conf, const char *poolname)
{
    seaf_warning ("Rados backend is not enabled.\n");
    return NULL;
}

#endif
