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
#include "seafile-session.h"

int read_file(SeafileSession *seaf, Seafile *file, char *buf, size_t size,
              off_t offset, struct fuse_file_info *info)
{
    BlockHandle *handle = NULL;;
    BlockMetadata *bmd;
    char *blkid, *tmp;
    off_t off = 0, nleft;
    int i, n, ret = -EIO;

    for (i = 0; i < file->n_blocks; i++) {
        blkid = file->blk_sha1s[i];

        bmd = seaf_block_manager_stat_block(seaf->block_mgr, blkid);
        if (!bmd)
            return -EIO;

        if (offset <= off + bmd->size)
            break;

        off += bmd->size;
    }

    /* beyond the i_size */
    if (i == file->n_blocks)
        return 0;

    handle = seaf_block_manager_open_block(seaf->block_mgr, blkid, BLOCK_READ);
    if (!handle)
        return -EIO;

    /* trim the offset in a block */
    if (offset > off) {
        tmp = (char *)malloc(sizeof(char) * (offset - off));
        if (!tmp)
            return -ENOMEM;

        n = seaf_block_manager_read_block(seaf->block_mgr, handle, tmp, offset-off);
        if (n != offset - off)
            goto out;

        free(tmp);
    }

    tmp = buf;
    nleft = size;
    while (nleft > 0) {
        if ((n = seaf_block_manager_read_block(seaf->block_mgr,
                                               handle, tmp, nleft)) < 0)
            goto out;
        else if (n == 0)
            break;

        nleft -= n;
        tmp += n;
    }

    return size - nleft;

out:
    if (handle)
        seaf_block_manager_close_block(seaf->block_mgr, handle);
    return ret;
}
