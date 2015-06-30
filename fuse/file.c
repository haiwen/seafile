#include "common.h"

#define FUSE_USE_VERSION  26
#include <fuse.h>

#include <glib.h>
#include <glib-object.h>

#include <ccnet.h>
#include <seaf-db.h>

#include "log.h"
#include "utils.h"

#include "seaf-fuse.h"

int read_file(SeafileSession *seaf,
              const char *store_id, int version,
              Seafile *file,
              char *buf, size_t size,
              off_t offset, struct fuse_file_info *info)
{
    BlockHandle *handle = NULL;;
    BlockMetadata *bmd;
    char *blkid;
    char *ptr;
    off_t off = 0, nleft;
    int i, n, ret = -EIO;

    for (i = 0; i < file->n_blocks; i++) {
        blkid = file->blk_sha1s[i];

        bmd = seaf_block_manager_stat_block(seaf->block_mgr, store_id, version, blkid);
        if (!bmd)
            return -EIO;

        if (offset < off + bmd->size) {
            g_free (bmd);
            break;
        }

        off += bmd->size;
        g_free (bmd);
    }

    /* beyond the file size */
    if (i == file->n_blocks)
        return 0;

    nleft = size;
    ptr = buf;
    while (nleft > 0 && i < file->n_blocks) {
        blkid = file->blk_sha1s[i];

        handle = seaf_block_manager_open_block(seaf->block_mgr,
                                               store_id, version,
                                               blkid, BLOCK_READ);
        if (!handle) {
            seaf_warning ("Failed to open block %s:%s.\n", store_id, blkid);
            return -EIO;
        }

        /* trim the offset in a block */
        if (offset > off) {
            char *tmp = (char *)malloc(sizeof(char) * (offset - off));
            if (!tmp)
                return -ENOMEM;

            n = seaf_block_manager_read_block(seaf->block_mgr, handle,
                                              tmp, offset-off);
            if (n != offset - off) {
                seaf_warning ("Failed to read block %s:%s.\n", store_id, blkid);
                free (tmp);
                goto out;
            }

            off += n;
            free(tmp);
        }

        if ((n = seaf_block_manager_read_block(seaf->block_mgr,
                                               handle, ptr, nleft)) < 0) {
            seaf_warning ("Failed to read block %s:%s.\n", store_id, blkid);
            goto out;
        }

        nleft -= n;
        ptr += n;
        off += n;
        ++i;

        /* At this point we should have read all the content of the block or
         * have read up to @size bytes. So it's safe to close the block.
         */
        seaf_block_manager_close_block(seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
    }

    return size - nleft;

out:
    if (handle) {
        seaf_block_manager_close_block(seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
    }
    return ret;
}
