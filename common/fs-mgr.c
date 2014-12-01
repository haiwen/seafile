/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#ifndef WIN32
    #include <arpa/inet.h>
#endif

#include <openssl/sha.h>
#include <searpc-utils.h>

#include "seafile-session.h"
#include "seafile-error.h"
#include "fs-mgr.h"
#include "block-mgr.h"
#include "utils.h"
#include "seaf-utils.h"
#include "log.h"
#include "../common/seafile-crypt.h"

#ifndef SEAFILE_SERVER
#include "../daemon/vc-utils.h"
#include "vc-common.h"
#endif  /* SEAFILE_SERVER */

#include "db.h"

#define SEAF_TMP_EXT "~"

struct _SeafFSManagerPriv {
    /* GHashTable      *seafile_cache; */
    GHashTable      *bl_cache;
};

typedef struct SeafileOndisk {
    guint32          type;
    guint64          file_size;
    unsigned char    block_ids[0];
} __attribute__((gcc_struct, __packed__)) SeafileOndisk;

typedef struct DirentOndisk {
    guint32 mode;
    char    id[40];
    guint32 name_len;
    char    name[0];
} __attribute__((gcc_struct, __packed__)) DirentOndisk;

typedef struct SeafdirOndisk {
    guint32 type;
    char    dirents[0];
} __attribute__((gcc_struct, __packed__)) SeafdirOndisk;

#ifndef SEAFILE_SERVER
uint32_t
calculate_chunk_size (uint64_t total_size);
static int
write_seafile (SeafFSManager *fs_mgr,
               const char *repo_id, int version,
               CDCFileDescriptor *cdc,
               unsigned char *obj_sha1);
#endif  /* SEAFILE_SERVER */

SeafFSManager *
seaf_fs_manager_new (SeafileSession *seaf,
                     const char *seaf_dir)
{
    SeafFSManager *mgr = g_new0 (SeafFSManager, 1);

    mgr->seaf = seaf;

    mgr->obj_store = seaf_obj_store_new (seaf, "fs");
    if (!mgr->obj_store) {
        g_free (mgr);
        return NULL;
    }

    mgr->priv = g_new0(SeafFSManagerPriv, 1);

    return mgr;
}

int
seaf_fs_manager_init (SeafFSManager *mgr)
{
#ifdef SEAFILE_SERVER

#ifdef FULL_FEATURE
    if (seaf_obj_store_init (mgr->obj_store, TRUE, seaf->ev_mgr) < 0) {
        g_warning ("[fs mgr] Failed to init fs object store.\n");
        return -1;
    }
#else
    if (seaf_obj_store_init (mgr->obj_store, FALSE, NULL) < 0) {
        g_warning ("[fs mgr] Failed to init fs object store.\n");
        return -1;
    }
#endif

#else
    if (seaf_obj_store_init (mgr->obj_store, TRUE, seaf->ev_mgr) < 0) {
        g_warning ("[fs mgr] Failed to init fs object store.\n");
        return -1;
    }
#endif

    return 0;
}

#ifndef SEAFILE_SERVER
static int
checkout_block (const char *repo_id,
                int version,
                const char *block_id,
                int wfd,
                SeafileCrypt *crypt)
{
    SeafBlockManager *block_mgr = seaf->block_mgr;
    BlockHandle *handle;
    BlockMetadata *bmd;
    char *dec_out = NULL;
    int dec_out_len = -1;
    char *blk_content = NULL;

    handle = seaf_block_manager_open_block (block_mgr,
                                            repo_id, version,
                                            block_id, BLOCK_READ);
    if (!handle) {
        g_warning ("Failed to open block %s\n", block_id);
        return -1;
    }

    /* first stat the block to get its size */
    bmd = seaf_block_manager_stat_block_by_handle (block_mgr, handle);
    if (!bmd) {
        g_warning ("can't stat block %s.\n", block_id);
        goto checkout_blk_error;
    }

    /* empty file, skip it */
    if (bmd->size == 0) {
        seaf_block_manager_close_block (block_mgr, handle);
        seaf_block_manager_block_handle_free (block_mgr, handle);
        return 0;
    }

    blk_content = (char *)malloc (bmd->size * sizeof(char));

    /* read the block to prepare decryption */
    if (seaf_block_manager_read_block (block_mgr, handle,
                                       blk_content, bmd->size) != bmd->size) {
        g_warning ("Error when reading from block %s.\n", block_id);
        goto checkout_blk_error;
    }

    if (crypt != NULL) {

        /* An encrypted block size must be a multiple of
           ENCRYPT_BLK_SIZE
        */
        if (bmd->size % ENCRYPT_BLK_SIZE != 0) {
            g_warning ("Error: An invalid encrypted block, %s \n", block_id);
            goto checkout_blk_error;
        }

        /* decrypt the block */
        int ret = seafile_decrypt (&dec_out,
                                   &dec_out_len,
                                   blk_content,
                                   bmd->size,
                                   crypt);

        if (ret != 0) {
            g_warning ("Decryt block %s failed. \n", block_id);
            goto checkout_blk_error;
        }

        /* write the decrypted content */
        ret = writen (wfd, dec_out, dec_out_len);


        if (ret !=  dec_out_len) {
            g_warning ("Failed to write the decryted block %s.\n",
                       block_id);
            goto checkout_blk_error;
        }

        g_free (blk_content);
        g_free (dec_out);

    } else {
        /* not an encrypted block */
        if (writen(wfd, blk_content, bmd->size) != bmd->size) {
            g_warning ("Failed to write the decryted block %s.\n",
                       block_id);
            goto checkout_blk_error;
        }
        g_free (blk_content);
    }

    g_free (bmd);
    seaf_block_manager_close_block (block_mgr, handle);
    seaf_block_manager_block_handle_free (block_mgr, handle);
    return 0;

checkout_blk_error:

    if (blk_content)
        free (blk_content);
    if (dec_out)
        g_free (dec_out);
    if (bmd)
        g_free (bmd);

    seaf_block_manager_close_block (block_mgr, handle);
    seaf_block_manager_block_handle_free (block_mgr, handle);
    return -1;
}

int
seaf_fs_manager_checkout_file (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *file_id,
                               const char *file_path,
                               guint32 mode,
                               guint64 mtime,
                               SeafileCrypt *crypt,
                               const char *in_repo_path,
                               const char *conflict_head_id,
                               gboolean force_conflict,
                               gboolean *conflicted)
{
    Seafile *seafile;
    char *blk_id;
    int wfd;
    int i;
    char *tmp_path;
    char *conflict_path;

    *conflicted = FALSE;

    seafile = seaf_fs_manager_get_seafile (mgr, repo_id, version, file_id);
    if (!seafile) {
        g_warning ("File %s does not exist.\n", file_id);
        return -1;
    }

    tmp_path = g_strconcat (file_path, SEAF_TMP_EXT, NULL);

    wfd = g_open (tmp_path, O_WRONLY | O_TRUNC | O_CREAT | O_BINARY, mode & ~S_IFMT);
    if (wfd < 0) {
        g_warning ("Failed to open file %s for checkout: %s.\n",
                   tmp_path, strerror(errno));
        goto bad;
    }

    for (i = 0; i < seafile->n_blocks; ++i) {
        blk_id = seafile->blk_sha1s[i];
        if (checkout_block (repo_id, version, blk_id, wfd, crypt) < 0)
            goto bad;
    }

    close (wfd);
    wfd = -1;

    if (force_conflict || ccnet_rename (tmp_path, file_path) < 0) {
        *conflicted = TRUE;
        conflict_path = gen_conflict_path_wrapper (repo_id, version,
                                                   conflict_head_id, in_repo_path,
                                                   file_path);
        if (!conflict_path)
            goto bad;

        seaf_warning ("Cannot update %s, creating conflict file %s.\n",
                      file_path, conflict_path);

        /* First try to rename the local version to a conflict file,
         * this will preserve the version from the server.
         * If this fails, fall back to checking out the server version
         * to the conflict file.
         */
        if (ccnet_rename (file_path, conflict_path) == 0) {
            if (ccnet_rename (tmp_path, file_path) < 0) {
                g_free (conflict_path);
                goto bad;
            }
        } else {
            if (ccnet_rename (tmp_path, conflict_path) < 0) {
                g_free (conflict_path);
                goto bad;
            }
        }

        g_free (conflict_path);
    } else if (mtime > 0) {
        /* !force_conflict && ccnet_rename() == 0
         * Set the checked out file mtime to what it has to be.
         */
        if (seaf_set_file_time (file_path, mtime) < 0) {
            seaf_warning ("Failed to set mtime for %s.\n", file_path);
        }
    }

    g_free (tmp_path);
    seafile_unref (seafile);
    return 0;

bad:
    if (wfd >= 0)
        close (wfd);
    /* Remove the tmp file if it still exists, in case that rename fails. */
    g_unlink (tmp_path);
    g_free (tmp_path);
    seafile_unref (seafile);
    return -1;
}

#endif /* SEAFILE_SERVER */

static void *
create_seafile_v0 (CDCFileDescriptor *cdc, int *ondisk_size, char *seafile_id)
{
    SeafileOndisk *ondisk;

    rawdata_to_hex (cdc->file_sum, seafile_id, 20);

    *ondisk_size = sizeof(SeafileOndisk) + cdc->block_nr * 20;
    ondisk = (SeafileOndisk *)g_new0 (char, *ondisk_size);

    ondisk->type = htonl(SEAF_METADATA_TYPE_FILE);
    ondisk->file_size = hton64 (cdc->file_size);
    memcpy (ondisk->block_ids, cdc->blk_sha1s, cdc->block_nr * 20);

    return ondisk;
}

static void *
create_seafile_json (int repo_version,
                     CDCFileDescriptor *cdc,
                     int *ondisk_size,
                     char *seafile_id)
{
    json_t *object, *block_id_array;

    object = json_object ();

    json_object_set_int_member (object, "type", SEAF_METADATA_TYPE_FILE);
    json_object_set_int_member (object, "version",
                                seafile_version_from_repo_version(repo_version));

    json_object_set_int_member (object, "size", cdc->file_size);

    block_id_array = json_array ();
    int i;
    uint8_t *ptr = cdc->blk_sha1s;
    char block_id[41];
    for (i = 0; i < cdc->block_nr; ++i) {
        rawdata_to_hex (ptr, block_id, 20);
        json_array_append_new (block_id_array, json_string(block_id));
        ptr += 20;
    }
    json_object_set_new (object, "block_ids", block_id_array);

    char *data = json_dumps (object, JSON_SORT_KEYS);
    *ondisk_size = strlen(data);

    /* The seafile object id is sha1 hash of the json object. */
    unsigned char sha1[20];
    calculate_sha1 (sha1, data, *ondisk_size);
    rawdata_to_hex (sha1, seafile_id, 20);

    json_decref (object);
    return data;
}

void
seaf_fs_manager_calculate_seafile_id_json (int repo_version,
                                           CDCFileDescriptor *cdc,
                                           guint8 *file_id_sha1)
{
    json_t *object, *block_id_array;

    object = json_object ();

    json_object_set_int_member (object, "type", SEAF_METADATA_TYPE_FILE);
    json_object_set_int_member (object, "version",
                                seafile_version_from_repo_version(repo_version));

    json_object_set_int_member (object, "size", cdc->file_size);

    block_id_array = json_array ();
    int i;
    uint8_t *ptr = cdc->blk_sha1s;
    char block_id[41];
    for (i = 0; i < cdc->block_nr; ++i) {
        rawdata_to_hex (ptr, block_id, 20);
        json_array_append_new (block_id_array, json_string(block_id));
        ptr += 20;
    }
    json_object_set_new (object, "block_ids", block_id_array);

    char *data = json_dumps (object, JSON_SORT_KEYS);
    int ondisk_size = strlen(data);

    /* The seafile object id is sha1 hash of the json object. */
    calculate_sha1 (file_id_sha1, data, ondisk_size);

    json_decref (object);
    free (data);
}

static int
write_seafile (SeafFSManager *fs_mgr,
               const char *repo_id,
               int version,
               CDCFileDescriptor *cdc,
               unsigned char *obj_sha1)
{
    int ret = 0;
    char seafile_id[41];
    void *ondisk;
    int ondisk_size;

    if (version > 0) {
        ondisk = create_seafile_json (version, cdc, &ondisk_size, seafile_id);

        guint8 *compressed;
        int outlen;

        if (seaf_compress (ondisk, ondisk_size, &compressed, &outlen) < 0) {
            seaf_warning ("Failed to compress seafile obj %s.\n", seafile_id);
            ret = -1;
            free (ondisk);
            goto out;
        }

        if (seaf_obj_store_write_obj (fs_mgr->obj_store, repo_id, version, seafile_id,
                                      compressed, outlen, FALSE) < 0)
            ret = -1;
        g_free (compressed);
        free (ondisk);
    } else {
        ondisk = create_seafile_v0 (cdc, &ondisk_size, seafile_id);

        if (seaf_obj_store_write_obj (fs_mgr->obj_store, repo_id, version, seafile_id,
                                      ondisk, ondisk_size, FALSE) < 0)
            ret = -1;
        g_free (ondisk);
    }

out:
    if (ret == 0)
        hex_to_rawdata (seafile_id, obj_sha1, 20);

    return ret;
}

uint32_t
calculate_chunk_size (uint64_t total_size)
{
    const uint64_t GiB = 1073741824;
    const uint64_t MiB = 1048576;

    if (total_size >= (8 * GiB)) return 8 * MiB;
    if (total_size >= (4 * GiB)) return 4 * MiB;
    if (total_size >= (2 * GiB)) return 2 * MiB;

    return 1 * MiB;
}

static int
do_write_chunk (const char *repo_id, int version,
                uint8_t *checksum, const char *buf, int len)
{
    SeafBlockManager *blk_mgr = seaf->block_mgr;
    char chksum_str[41];
    BlockHandle *handle;
    int n;

    rawdata_to_hex (checksum, chksum_str, 20);

    /* Don't write if the block already exists. */
    if (seaf_block_manager_block_exists (seaf->block_mgr,
                                         repo_id, version,
                                         chksum_str))
        return 0;

    handle = seaf_block_manager_open_block (blk_mgr,
                                            repo_id, version,
                                            chksum_str, BLOCK_WRITE);
    if (!handle) {
        g_warning ("Failed to open block %s.\n", chksum_str);
        return -1;
    }

    n = seaf_block_manager_write_block (blk_mgr, handle, buf, len);
    if (n < 0) {
        g_warning ("Failed to write chunk %s.\n", chksum_str);
        seaf_block_manager_close_block (blk_mgr, handle);
        seaf_block_manager_block_handle_free (blk_mgr, handle);
        return -1;
    }

    seaf_block_manager_close_block (blk_mgr, handle);

    if (seaf_block_manager_commit_block (blk_mgr, handle) < 0) {
        g_warning ("failed to commit chunk %s.\n", chksum_str);
        seaf_block_manager_block_handle_free (blk_mgr, handle);
        return -1;
    }

    seaf_block_manager_block_handle_free (blk_mgr, handle);
    return 0;
}

/* write the chunk and store its checksum */
int
seafile_write_chunk (const char *repo_id,
                     int version,
                     CDCDescriptor *chunk,
                     SeafileCrypt *crypt,
                     uint8_t *checksum,
                     gboolean write_data)
{
    SHA_CTX ctx;
    int ret = 0;

    /* Encrypt before write to disk if needed, and we don't encrypt
     * empty files. */
    if (crypt != NULL && chunk->len) {
        char *encrypted_buf = NULL;         /* encrypted output */
        int enc_len = -1;                /* encrypted length */

        ret = seafile_encrypt (&encrypted_buf, /* output */
                               &enc_len,      /* output len */
                               chunk->block_buf, /* input */
                               chunk->len,       /* input len */
                               crypt);
        if (ret != 0) {
            g_warning ("Error: failed to encrypt block\n");
            return -1;
        }

        SHA1_Init (&ctx);
        SHA1_Update (&ctx, encrypted_buf, enc_len);
        SHA1_Final (checksum, &ctx);

        if (write_data)
            ret = do_write_chunk (repo_id, version, checksum, encrypted_buf, enc_len);
        g_free (encrypted_buf);
    } else {
        /* not a encrypted repo, go ahead */
        SHA1_Init (&ctx);
        SHA1_Update (&ctx, chunk->block_buf, chunk->len);
        SHA1_Final (checksum, &ctx);

        if (write_data)
            ret = do_write_chunk (repo_id, version, checksum, chunk->block_buf, chunk->len);
    }

    return ret;
}

static void
create_cdc_for_empty_file (CDCFileDescriptor *cdc)
{
    memset (cdc, 0, sizeof(CDCFileDescriptor));
}

int
seaf_fs_manager_index_blocks (SeafFSManager *mgr,
                              const char *repo_id,
                              int version,
                              const char *file_path,
                              unsigned char sha1[],
                              gint64 *size,
                              SeafileCrypt *crypt,
                              gboolean write_data)
{
    SeafStat sb;
    CDCFileDescriptor cdc;

    if (seaf_stat (file_path, &sb) < 0) {
        g_warning ("Bad file %s: %s.\n", file_path, strerror(errno));
        return -1;
    }

    g_return_val_if_fail (S_ISREG(sb.st_mode), -1);

    if (sb.st_size == 0) {
        /* handle empty file. */
        memset (sha1, 0, 20);
        create_cdc_for_empty_file (&cdc);
    } else {
        memset (&cdc, 0, sizeof(cdc));
        cdc.block_sz = calculate_chunk_size (sb.st_size);
        cdc.block_min_sz = cdc.block_sz >> 2;
        cdc.block_max_sz = cdc.block_sz << 2;
        cdc.write_block = seafile_write_chunk;
        memcpy (cdc.repo_id, repo_id, 36);
        cdc.version = version;
        if (filename_chunk_cdc (file_path, &cdc, crypt, write_data) < 0) {
            g_warning ("Failed to chunk file with CDC.\n");
            return -1;
        }

        if (write_data && write_seafile (mgr, repo_id, version, &cdc, sha1) < 0) {
            g_warning ("Failed to write seafile for %s.\n", file_path);
            return -1;
        }
    }

    *size = (gint64)sb.st_size;

    if (cdc.blk_sha1s)
        free (cdc.blk_sha1s);

    return 0;
}

static int
check_and_write_block (const char *repo_id, int version,
                       const char *path, unsigned char *sha1, const char *block_id)
{
    char *content;
    gsize len;
    GError *error = NULL;
    int ret = 0;

    if (!g_file_get_contents (path, &content, &len, &error)) {
        if (error) {
            seaf_warning ("Failed to read %s: %s.\n", path, error->message);
            g_clear_error (&error);
            return -1;
        }
    }

    SHA_CTX block_ctx;
    unsigned char checksum[20];

    SHA1_Init (&block_ctx);
    SHA1_Update (&block_ctx, content, len);
    SHA1_Final (checksum, &block_ctx);

    if (memcmp (checksum, sha1, 20) != 0) {
        seaf_warning ("Block id %s doesn't match content.\n", block_id);
        ret = -1;
        goto out;
    }

    if (do_write_chunk (repo_id, version, sha1, content, len) < 0) {
        ret = -1;
        goto out;
    }

out:
    g_free (content);
    return ret;
}

static int
check_and_write_file_blocks (CDCFileDescriptor *cdc, GList *paths, GList *blockids)
{
    GList *ptr, *q;
    SHA_CTX file_ctx;
    int ret = 0;

    SHA1_Init (&file_ctx);
    for (ptr = paths, q = blockids; ptr; ptr = ptr->next, q = q->next) {
        char *path = ptr->data;
        char *blk_id = q->data;
        unsigned char sha1[20];

        hex_to_rawdata (blk_id, sha1, 20);
        ret = check_and_write_block (cdc->repo_id, cdc->version, path, sha1, blk_id);
        if (ret < 0)
            goto out;

        memcpy (cdc->blk_sha1s + cdc->block_nr * CHECKSUM_LENGTH,
                sha1, CHECKSUM_LENGTH);
        cdc->block_nr++;

        SHA1_Update (&file_ctx, sha1, 20);
    }

    SHA1_Final (cdc->file_sum, &file_ctx);

out:
    return ret;
}

static int
init_file_cdc (CDCFileDescriptor *cdc,
               const char *repo_id, int version,
               int block_nr, gint64 file_size)
{
    memset (cdc, 0, sizeof(CDCFileDescriptor));

    cdc->file_size = file_size;

    cdc->blk_sha1s =  (uint8_t *)calloc (sizeof(uint8_t), block_nr * CHECKSUM_LENGTH);
    if (!cdc->blk_sha1s) {
        seaf_warning ("Failed to alloc block sha1 array.\n");
        return -1;
    }

    memcpy (cdc->repo_id, repo_id, 36);
    cdc->version = version;

    return 0;
}

int
seaf_fs_manager_index_file_blocks (SeafFSManager *mgr,
                                   const char *repo_id,
                                   int version,
                                   GList *paths,
                                   GList *blockids,
                                   unsigned char sha1[],
                                   gint64 file_size)
{
    int ret = 0;
    CDCFileDescriptor cdc;

    if (!paths) {
        /* handle empty file. */
        memset (sha1, 0, 20);
        create_cdc_for_empty_file (&cdc);
    } else {
        int block_nr = g_list_length (paths);

        if (init_file_cdc (&cdc, repo_id, version, block_nr, file_size) < 0) {
            ret = -1;
            goto out;
        }

        if (check_and_write_file_blocks (&cdc, paths, blockids) < 0) {
            seaf_warning ("Failed to check and write file blocks.\n");
            ret = -1;
            goto out;
        }

        if (write_seafile (mgr, repo_id, version, &cdc, sha1) < 0) {
            seaf_warning ("Failed to write seafile.\n");
            ret = -1;
            goto out;
        }
    }

out:
    if (cdc.blk_sha1s)
        free (cdc.blk_sha1s);

    return ret;
}

void
seafile_ref (Seafile *seafile)
{
    ++seafile->ref_count;
}

static void
seafile_free (Seafile *seafile)
{
    int i;

    if (seafile->blk_sha1s) {
        for (i = 0; i < seafile->n_blocks; ++i)
            g_free (seafile->blk_sha1s[i]);
        g_free (seafile->blk_sha1s);
    }

    g_free (seafile);
}

void
seafile_unref (Seafile *seafile)
{
    if (!seafile)
        return;

    if (--seafile->ref_count <= 0)
        seafile_free (seafile);
}

static Seafile *
seafile_from_v0_data (const char *id, const void *data, int len)
{
    const SeafileOndisk *ondisk = data;
    Seafile *seafile;
    int id_list_len, n_blocks;

    if (len < sizeof(SeafileOndisk)) {
        g_warning ("[fs mgr] Corrupt seafile object %s.\n", id);
        return NULL;
    }

    if (ntohl(ondisk->type) != SEAF_METADATA_TYPE_FILE) {
        g_warning ("[fd mgr] %s is not a file.\n", id);
        return NULL;
    }

    id_list_len = len - sizeof(SeafileOndisk);
    if (id_list_len % 20 != 0) {
        g_warning ("[fs mgr] Corrupt seafile object %s.\n", id);
        return NULL;
    }
    n_blocks = id_list_len / 20;

    seafile = g_new0 (Seafile, 1);

    seafile->object.type = SEAF_METADATA_TYPE_FILE;
    seafile->version = 0;
    memcpy (seafile->file_id, id, 41);
    seafile->file_size = ntoh64 (ondisk->file_size);
    seafile->n_blocks = n_blocks;

    seafile->blk_sha1s = g_new0 (char*, seafile->n_blocks);
    const unsigned char *blk_sha1_ptr = ondisk->block_ids;
    int i;
    for (i = 0; i < seafile->n_blocks; ++i) {
        char *blk_sha1 = g_new0 (char, 41);
        seafile->blk_sha1s[i] = blk_sha1;
        rawdata_to_hex (blk_sha1_ptr, blk_sha1, 20);
        blk_sha1_ptr += 20;
    }

    seafile->ref_count = 1;
    return seafile;
}

static Seafile *
seafile_from_json_object (const char *id, json_t *object)
{
    json_t *block_id_array = NULL;
    int type;
    int version;
    guint64 file_size;
    Seafile *seafile = NULL;

    /* Sanity checks. */
    type = json_object_get_int_member (object, "type");
    if (type != SEAF_METADATA_TYPE_FILE) {
        seaf_warning ("Object %s is not a file.\n", id);
        return NULL;
    }

    version = (int) json_object_get_int_member (object, "version");
    if (version < 1) {
        seaf_warning ("Seafile object %s version should be > 0, version is %d.\n",
                      id, version);
        return NULL;
    }

    file_size = (guint64) json_object_get_int_member (object, "size");

    block_id_array = json_object_get (object, "block_ids");
    if (!block_id_array) {
        seaf_warning ("No block id array in seafile object %s.\n", id);
        return NULL;
    }

    seafile = g_new0 (Seafile, 1);

    seafile->object.type = SEAF_METADATA_TYPE_FILE;

    memcpy (seafile->file_id, id, 40);
    seafile->version = version;
    seafile->file_size = file_size;
    seafile->n_blocks = json_array_size (block_id_array);
    seafile->blk_sha1s = g_new0 (char *, seafile->n_blocks);

    int i;
    json_t *block_id_obj;
    const char *block_id;
    for (i = 0; i < seafile->n_blocks; ++i) {
        block_id_obj = json_array_get (block_id_array, i);
        block_id = json_string_value (block_id_obj);
        if (!block_id) {
            seafile_free (seafile);
            return NULL;
        }
        seafile->blk_sha1s[i] = g_strdup(block_id);
    }

    seafile->ref_count = 1;

    return seafile;
}

static Seafile *
seafile_from_json (const char *id, void *data, int len)
{
    guint8 *decompressed;
    int outlen;
    json_t *object = NULL;
    json_error_t error;
    Seafile *seafile;

    if (seaf_decompress (data, len, &decompressed, &outlen) < 0) {
        seaf_warning ("Failed to decompress seafile object %s.\n", id);
        return NULL;
    }

    object = json_loadb ((const char *)decompressed, outlen, 0, &error);
    g_free (decompressed);
    if (!object) {
        if (error.text)
            g_warning ("Failed to load seafile json object: %s.\n", error.text);
        else
            g_warning ("Failed to load seafile json object.\n");
        return NULL;
    }

    seafile = seafile_from_json_object (id, object);

    json_decref (object);
    return seafile;
}

static Seafile *
seafile_from_data (const char *id, void *data, int len, gboolean is_json)
{
    if (is_json)
        return seafile_from_json (id, data, len);
    else
        return seafile_from_v0_data (id, data, len);
}

Seafile *
seaf_fs_manager_get_seafile (SeafFSManager *mgr,
                             const char *repo_id,
                             int version,
                             const char *file_id)
{
    void *data;
    int len;
    Seafile *seafile;

#if 0
    seafile = g_hash_table_lookup (mgr->priv->seafile_cache, file_id);
    if (seafile) {
        seafile_ref (seafile);
        return seafile;
    }
#endif

    if (memcmp (file_id, EMPTY_SHA1, 40) == 0) {
        seafile = g_new0 (Seafile, 1);
        memset (seafile->file_id, '0', 40);
        seafile->ref_count = 1;
        return seafile;
    }

    if (seaf_obj_store_read_obj (mgr->obj_store, repo_id, version,
                                 file_id, &data, &len) < 0) {
        g_warning ("[fs mgr] Failed to read file %s.\n", file_id);
        return NULL;
    }

    seafile = seafile_from_data (file_id, data, len, (version > 0));
    g_free (data);

#if 0
    /*
     * Add to cache. Also increase ref count.
     */
    seafile_ref (seafile);
    g_hash_table_insert (mgr->priv->seafile_cache, g_strdup(file_id), seafile);
#endif

    return seafile;
}

static guint8 *
seafile_to_v0_data (Seafile *file, int *len)
{
    SeafileOndisk *ondisk;

    *len = sizeof(SeafileOndisk) + file->n_blocks * 20;
    ondisk = (SeafileOndisk *)g_new0 (char, *len);

    ondisk->type = htonl(SEAF_METADATA_TYPE_FILE);
    ondisk->file_size = hton64 (file->file_size);

    guint8 *ptr = ondisk->block_ids;
    int i;
    for (i = 0; i < file->n_blocks; ++i) {
        hex_to_rawdata (file->blk_sha1s[i], ptr, 20);
        ptr += 20;
    }

    return (guint8 *)ondisk;
}

static guint8 *
seafile_to_json (Seafile *file, int *len)
{
    json_t *object, *block_id_array;

    object = json_object ();

    json_object_set_int_member (object, "type", SEAF_METADATA_TYPE_FILE);
    json_object_set_int_member (object, "version", file->version);

    json_object_set_int_member (object, "size", file->file_size);

    block_id_array = json_array ();
    int i;
    for (i = 0; i < file->n_blocks; ++i) {
        json_array_append_new (block_id_array, json_string(file->blk_sha1s[i]));
    }
    json_object_set_new (object, "block_ids", block_id_array);

    char *data = json_dumps (object, JSON_SORT_KEYS);
    *len = strlen(data);

    unsigned char sha1[20];
    calculate_sha1 (sha1, data, *len);
    rawdata_to_hex (sha1, file->file_id, 20);

    json_decref (object);
    return (guint8 *)data;
}

static guint8 *
seafile_to_data (Seafile *file, int *len)
{
    if (file->version > 0) {
        guint8 *data;
        int orig_len;
        guint8 *compressed;

        data = seafile_to_json (file, &orig_len);
        if (!data)
            return NULL;

        if (seaf_compress (data, orig_len, &compressed, len) < 0) {
            seaf_warning ("Failed to compress file object %s.\n", file->file_id);
            g_free (data);
            return NULL;
        }
        g_free (data);
        return compressed;
    } else
        return seafile_to_v0_data (file, len);
}

int
seafile_save (SeafFSManager *fs_mgr,
              const char *repo_id,
              int version,
              Seafile *file)
{
    guint8 *data;
    int len;
    int ret = 0;

    data = seafile_to_data (file, &len);
    if (!data)
        return -1;

    if (seaf_obj_store_write_obj (fs_mgr->obj_store, repo_id, version, file->file_id,
                                  data, len, FALSE) < 0)
        ret = -1;

    g_free (data);
    return ret;
}

static void compute_dir_id_v0 (SeafDir *dir, GList *entries)
{
    SHA_CTX ctx;
    GList *p;
    uint8_t sha1[20];
    SeafDirent *dent;
    guint32 mode_le;

    /* ID for empty dirs is EMPTY_SHA1. */
    if (entries == NULL) {
        memset (dir->dir_id, '0', 40);
        return;
    }

    SHA1_Init (&ctx);
    for (p = entries; p; p = p->next) {
        dent = (SeafDirent *)p->data;
        SHA1_Update (&ctx, dent->id, 40);
        SHA1_Update (&ctx, dent->name, dent->name_len);
        /* Convert mode to little endian before compute. */
        if (G_BYTE_ORDER == G_BIG_ENDIAN)
            mode_le = GUINT32_SWAP_LE_BE (dent->mode);
        else
            mode_le = dent->mode;
        SHA1_Update (&ctx, &mode_le, sizeof(mode_le));
    }
    SHA1_Final (sha1, &ctx);

    rawdata_to_hex (sha1, dir->dir_id, 20);
}

SeafDir *
seaf_dir_new (const char *id, GList *entries, int version)
{
    SeafDir *dir;

    dir = g_new0(SeafDir, 1);

    dir->version = version;
    if (id != NULL) {
        memcpy(dir->dir_id, id, 40);
        dir->dir_id[40] = '\0';
    } else if (version == 0) {
        compute_dir_id_v0 (dir, entries);
    }
    dir->entries = entries;

    if (dir->entries != NULL)
        dir->ondisk = seaf_dir_to_data (dir, &dir->ondisk_size);
    else
        memcpy (dir->dir_id, EMPTY_SHA1, 40);

    return dir;
}

void
seaf_dir_free (SeafDir *dir)
{
    if (dir == NULL)
        return;

    GList *ptr = dir->entries;
    while (ptr) {
        seaf_dirent_free ((SeafDirent *)ptr->data);
        ptr = ptr->next;
    }

    g_list_free (dir->entries);
    g_free (dir->ondisk);
    g_free(dir);
}

SeafDirent *
seaf_dirent_new (int version, const char *sha1, int mode, const char *name,
                 gint64 mtime, const char *modifier, gint64 size)
{
    SeafDirent *dent;

    dent = g_new0 (SeafDirent, 1);
    dent->version = version;
    memcpy(dent->id, sha1, 40);
    dent->id[40] = '\0';
    dent->mode = mode;
    dent->name = g_strdup(name);
    dent->name_len = strlen(name);

    if (version > 0) {
        dent->mtime = mtime;
        if (S_ISREG(mode)) {
            dent->modifier = g_strdup(modifier);
            dent->size = size;
        }
    }

    return dent;
}

void 
seaf_dirent_free (SeafDirent *dent)
{
    if (!dent)
        return;
    g_free (dent->name);
    g_free (dent->modifier);
    g_free (dent);
}

SeafDirent *
seaf_dirent_dup (SeafDirent *dent)
{
    SeafDirent *new_dent;

    new_dent = g_memdup (dent, sizeof(SeafDirent));
    new_dent->name = g_strdup(dent->name);
    new_dent->modifier = g_strdup(dent->modifier);

    return new_dent;
}

static SeafDir *
seaf_dir_from_v0_data (const char *dir_id, const uint8_t *data, int len)
{
    SeafDir *root;
    SeafDirent *dent;
    const uint8_t *ptr;
    int remain;
    int dirent_base_size;
    guint32 meta_type;
    guint32 name_len;

    ptr = data;
    remain = len;

    meta_type = get32bit (&ptr);
    remain -= 4;
    if (meta_type != SEAF_METADATA_TYPE_DIR) {
        g_warning ("Data does not contain a directory.\n");
        return NULL;
    }

    root = g_new0(SeafDir, 1);
    root->object.type = SEAF_METADATA_TYPE_DIR;
    root->version = 0;
    memcpy(root->dir_id, dir_id, 40);
    root->dir_id[40] = '\0';

    dirent_base_size = 2 * sizeof(guint32) + 40;
    while (remain > dirent_base_size) {
        dent = g_new0(SeafDirent, 1);

        dent->version = 0;
        dent->mode = get32bit (&ptr);
        memcpy (dent->id, ptr, 40);
        dent->id[40] = '\0';
        ptr += 40;
        name_len = get32bit (&ptr);
        remain -= dirent_base_size;
        if (remain >= name_len) {
            dent->name_len = MIN (name_len, SEAF_DIR_NAME_LEN - 1);
            dent->name = g_strndup((const char *)ptr, dent->name_len);
            ptr += dent->name_len;
            remain -= dent->name_len;
        } else {
            g_warning ("Bad data format for dir objcet %s.\n", dir_id);
            g_free (dent);
            goto bad;
        }

        root->entries = g_list_prepend (root->entries, dent);
    }

    root->entries = g_list_reverse (root->entries);

    return root;

bad:
    seaf_dir_free (root);
    return NULL;
}

static SeafDirent *
parse_dirent (const char *dir_id, int version, json_t *object)
{
    guint32 mode;
    const char *id;
    const char *name;
    gint64 mtime;
    const char *modifier;
    gint64 size;

    mode = (guint32) json_object_get_int_member (object, "mode");

    id = json_object_get_string_member (object, "id");
    if (!id) {
        seaf_warning ("Dirent id not set for dir object %s.\n", dir_id);
        return NULL;
    }

    name = json_object_get_string_member (object, "name");
    if (!name) {
        seaf_warning ("Dirent name not set for dir object %s.\n", dir_id);
        return NULL;
    }

    mtime = json_object_get_int_member (object, "mtime");
    if (S_ISREG(mode)) {
        modifier = json_object_get_string_member (object, "modifier");
        if (!modifier) {
            seaf_warning ("Dirent modifier not set for dir object %s.\n", dir_id);
            return NULL;
        }
        size = json_object_get_int_member (object, "size");
    }

    SeafDirent *dirent = g_new0 (SeafDirent, 1);
    dirent->version = version;
    dirent->mode = mode;
    memcpy (dirent->id, id, 40);
    dirent->name_len = strlen(name);
    dirent->name = g_strdup(name);
    dirent->mtime = mtime;
    if (S_ISREG(mode)) {
        dirent->modifier = g_strdup(modifier);
        dirent->size = size;
    }

    return dirent;
}

static SeafDir *
seaf_dir_from_json_object (const char *dir_id, json_t *object)
{
    json_t *dirent_array = NULL;
    int type;
    int version;
    SeafDir *dir = NULL;

    /* Sanity checks. */
    type = json_object_get_int_member (object, "type");
    if (type != SEAF_METADATA_TYPE_DIR) {
        seaf_warning ("Object %s is not a dir.\n", dir_id);
        return NULL;
    }

    version = (int) json_object_get_int_member (object, "version");
    if (version < 1) {
        seaf_warning ("Dir object %s version should be > 0, version is %d.\n",
                      dir_id, version);
        return NULL;
    }

    dirent_array = json_object_get (object, "dirents");
    if (!dirent_array) {
        seaf_warning ("No dirents in dir object %s.\n", dir_id);
        return NULL;
    }

    dir = g_new0 (SeafDir, 1);

    dir->object.type = SEAF_METADATA_TYPE_DIR;

    memcpy (dir->dir_id, dir_id, 40);
    dir->version = version;

    size_t n_dirents = json_array_size (dirent_array);
    int i;
    json_t *dirent_obj;
    SeafDirent *dirent;
    for (i = 0; i < n_dirents; ++i) {
        dirent_obj = json_array_get (dirent_array, i);
        dirent = parse_dirent (dir_id, version, dirent_obj);
        if (!dirent) {
            seaf_dir_free (dir);
            return NULL;
        }
        dir->entries = g_list_prepend (dir->entries, dirent);
    }
    dir->entries = g_list_reverse (dir->entries);

    return dir;
}

static SeafDir *
seaf_dir_from_json (const char *dir_id, uint8_t *data, int len)
{
    guint8 *decompressed;
    int outlen;
    json_t *object = NULL;
    json_error_t error;
    SeafDir *dir;

    if (seaf_decompress (data, len, &decompressed, &outlen) < 0) {
        seaf_warning ("Failed to decompress dir object %s.\n", dir_id);
        return NULL;
    }

    object = json_loadb ((const char *)decompressed, outlen, 0, &error);
    g_free (decompressed);
    if (!object) {
        if (error.text)
            g_warning ("Failed to load seafdir json object: %s.\n", error.text);
        else
            g_warning ("Failed to load seafdir json object.\n");
        return NULL;
    }

    dir = seaf_dir_from_json_object (dir_id, object);

    json_decref (object);
    return dir;
}

SeafDir *
seaf_dir_from_data (const char *dir_id, uint8_t *data, int len,
                    gboolean is_json)
{
    if (is_json)
        return seaf_dir_from_json (dir_id, data, len);
    else
        return seaf_dir_from_v0_data (dir_id, data, len);
}

inline static int
ondisk_dirent_size (SeafDirent *dirent)
{
    return sizeof(DirentOndisk) + dirent->name_len;
}

static void *
seaf_dir_to_v0_data (SeafDir *dir, int *len)
{
    SeafdirOndisk *ondisk;
    int dir_ondisk_size = sizeof(SeafdirOndisk);
    GList *dirents = dir->entries;
    GList *ptr;
    SeafDirent *de;
    char *p;
    DirentOndisk *de_ondisk;

    for (ptr = dirents; ptr; ptr = ptr->next) {
        de = ptr->data;
        dir_ondisk_size += ondisk_dirent_size (de);
    }

    *len = dir_ondisk_size;
    ondisk = (SeafdirOndisk *) g_new0 (char, dir_ondisk_size);

    ondisk->type = htonl (SEAF_METADATA_TYPE_DIR);
    p = ondisk->dirents;
    for (ptr = dirents; ptr; ptr = ptr->next) {
        de = ptr->data;
        de_ondisk = (DirentOndisk *) p;

        de_ondisk->mode = htonl(de->mode);
        memcpy (de_ondisk->id, de->id, 40);
        de_ondisk->name_len = htonl (de->name_len);
        memcpy (de_ondisk->name, de->name, de->name_len);

        p += ondisk_dirent_size (de);
    }

    return (void *)ondisk;
}

static void
add_to_dirent_array (json_t *array, SeafDirent *dirent)
{
    json_t *object;

    object = json_object ();
    json_object_set_int_member (object, "mode", dirent->mode);
    json_object_set_string_member (object, "id", dirent->id);
    json_object_set_string_member (object, "name", dirent->name);
    json_object_set_int_member (object, "mtime", dirent->mtime);
    if (S_ISREG(dirent->mode)) {
        json_object_set_string_member (object, "modifier", dirent->modifier);
        json_object_set_int_member (object, "size", dirent->size);
    }

    json_array_append_new (array, object);
}

static void *
seaf_dir_to_json (SeafDir *dir, int *len)
{
    json_t *object, *dirent_array;
    GList *ptr;
    SeafDirent *dirent;

    object = json_object ();

    json_object_set_int_member (object, "type", SEAF_METADATA_TYPE_DIR);
    json_object_set_int_member (object, "version", dir->version);

    dirent_array = json_array ();
    for (ptr = dir->entries; ptr; ptr = ptr->next) {
        dirent = ptr->data;
        add_to_dirent_array (dirent_array, dirent);
    }
    json_object_set_new (object, "dirents", dirent_array);

    char *data = json_dumps (object, JSON_SORT_KEYS);
    *len = strlen(data);

    /* The dir object id is sha1 hash of the json object. */
    unsigned char sha1[20];
    calculate_sha1 (sha1, data, *len);
    rawdata_to_hex (sha1, dir->dir_id, 20);

    json_decref (object);
    return data;
}

void *
seaf_dir_to_data (SeafDir *dir, int *len)
{
    if (dir->version > 0) {
        guint8 *data;
        int orig_len;
        guint8 *compressed;

        data = seaf_dir_to_json (dir, &orig_len);
        if (!data)
            return NULL;

        if (seaf_compress (data, orig_len, &compressed, len) < 0) {
            seaf_warning ("Failed to compress dir object %s.\n", dir->dir_id);
            g_free (data);
            return NULL;
        }

        g_free (data);
        return compressed;
    } else
        return seaf_dir_to_v0_data (dir, len);
}

int
seaf_dir_save (SeafFSManager *fs_mgr,
               const char *repo_id,
               int version,
               SeafDir *dir)
{
    int ret = 0;

    /* Don't need to save empty dir on disk. */
    if (memcmp (dir->dir_id, EMPTY_SHA1, 40) == 0)
        return 0;

    if (seaf_obj_store_write_obj (fs_mgr->obj_store, repo_id, version, dir->dir_id,
                                  dir->ondisk, dir->ondisk_size, FALSE) < 0)
        ret = -1;

    return ret;
}

SeafDir *
seaf_fs_manager_get_seafdir (SeafFSManager *mgr,
                             const char *repo_id,
                             int version,
                             const char *dir_id)
{
    void *data;
    int len;
    SeafDir *dir;

    /* TODO: add hash cache */

    if (memcmp (dir_id, EMPTY_SHA1, 40) == 0) {
        dir = g_new0 (SeafDir, 1);
        memset (dir->dir_id, '0', 40);
        return dir;
    }

    if (seaf_obj_store_read_obj (mgr->obj_store, repo_id, version,
                                 dir_id, &data, &len) < 0) {
        g_warning ("[fs mgr] Failed to read dir %s.\n", dir_id);
        return NULL;
    }

    dir = seaf_dir_from_data (dir_id, data, len, (version > 0));
    g_free (data);

    return dir;
}

static gint
compare_dirents (gconstpointer a, gconstpointer b)
{
    const SeafDirent *denta = a, *dentb = b;

    return strcmp (dentb->name, denta->name);
}

static gboolean
is_dirents_sorted (GList *dirents)
{
    GList *ptr;
    SeafDirent *dent, *dent_n;
    gboolean ret = TRUE;

    for (ptr = dirents; ptr != NULL; ptr = ptr->next) {
        dent = ptr->data;
        if (!ptr->next)
            break;
        dent_n = ptr->next->data;

        /* If dirents are not sorted in descending order, return FALSE. */
        if (strcmp (dent->name, dent_n->name) < 0) {
            ret = FALSE;
            break;
        }
    }

    return ret;
}

SeafDir *
seaf_fs_manager_get_seafdir_sorted (SeafFSManager *mgr,
                                    const char *repo_id,
                                    int version,
                                    const char *dir_id)
{
    SeafDir *dir = seaf_fs_manager_get_seafdir(mgr, repo_id, version, dir_id);

    if (!dir)
        return NULL;

    /* Only some very old dir objects are not sorted. */
    if (version > 0)
        return dir;

    if (!is_dirents_sorted (dir->entries))
        dir->entries = g_list_sort (dir->entries, compare_dirents);

    return dir;
}

static int
parse_metadata_type_v0 (const uint8_t *data, int len)
{
    const uint8_t *ptr = data;

    if (len < sizeof(guint32))
        return SEAF_METADATA_TYPE_INVALID;

    return (int)(get32bit(&ptr));
}

static int
parse_metadata_type_json (const char *obj_id, uint8_t *data, int len)
{
    guint8 *decompressed;
    int outlen;
    json_t *object;
    json_error_t error;
    int type;

    if (seaf_decompress (data, len, &decompressed, &outlen) < 0) {
        seaf_warning ("Failed to decompress fs object %s.\n", obj_id);
        return SEAF_METADATA_TYPE_INVALID;
    }

    object = json_loadb ((const char *)decompressed, outlen, 0, &error);
    g_free (decompressed);
    if (!object) {
        if (error.text)
            g_warning ("Failed to load fs json object: %s.\n", error.text);
        else
            g_warning ("Failed to load fs json object.\n");
        return SEAF_METADATA_TYPE_INVALID;
    }

    type = json_object_get_int_member (object, "type");

    json_decref (object);
    return type;
}

int
seaf_metadata_type_from_data (const char *obj_id,
                              uint8_t *data, int len, gboolean is_json)
{
    if (is_json)
        return parse_metadata_type_json (obj_id, data, len);
    else
        return parse_metadata_type_v0 (data, len);
}

SeafFSObject *
fs_object_from_v0_data (const char *obj_id, const uint8_t *data, int len)
{
    int type = parse_metadata_type_v0 (data, len);

    if (type == SEAF_METADATA_TYPE_FILE)
        return (SeafFSObject *)seafile_from_v0_data (obj_id, data, len);
    else if (type == SEAF_METADATA_TYPE_DIR)
        return (SeafFSObject *)seaf_dir_from_v0_data (obj_id, data, len);
    else {
        seaf_warning ("Invalid object type %d.\n", type);
        return NULL;
    }
}

SeafFSObject *
fs_object_from_json (const char *obj_id, uint8_t *data, int len)
{
    guint8 *decompressed;
    int outlen;
    json_t *object;
    json_error_t error;
    int type;
    SeafFSObject *fs_obj;

    if (seaf_decompress (data, len, &decompressed, &outlen) < 0) {
        seaf_warning ("Failed to decompress fs object %s.\n", obj_id);
        return NULL;
    }

    object = json_loadb ((const char *)decompressed, outlen, 0, &error);
    g_free (decompressed);
    if (!object) {
        if (error.text)
            g_warning ("Failed to load fs json object: %s.\n", error.text);
        else
            g_warning ("Failed to load fs json object.\n");
        return NULL;
    }

    type = json_object_get_int_member (object, "type");

    if (type == SEAF_METADATA_TYPE_FILE)
        fs_obj = (SeafFSObject *)seafile_from_json_object (obj_id, object);
    else if (type == SEAF_METADATA_TYPE_DIR)
        fs_obj = (SeafFSObject *)seaf_dir_from_json_object (obj_id, object);
    else {
        seaf_warning ("Invalid fs type %d.\n", type);
        json_decref (object);
        return NULL;
    }

    json_decref (object);

    return fs_obj;
}

SeafFSObject *
seaf_fs_object_from_data (const char *obj_id,
                          uint8_t *data, int len,
                          gboolean is_json)
{
    if (is_json)
        return fs_object_from_json (obj_id, data, len);
    else
        return fs_object_from_v0_data (obj_id, data, len);
}

void
seaf_fs_object_free (SeafFSObject *obj)
{
    if (!obj)
        return;

    if (obj->type == SEAF_METADATA_TYPE_FILE)
        seafile_unref ((Seafile *)obj);
    else if (obj->type == SEAF_METADATA_TYPE_DIR)
        seaf_dir_free ((SeafDir *)obj);
}

BlockList *
block_list_new ()
{
    BlockList *bl = g_new0 (BlockList, 1);

    bl->block_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    bl->block_ids = g_ptr_array_new_with_free_func (g_free);

    return bl;
}

void
block_list_free (BlockList *bl)
{
    if (bl->block_hash)
        g_hash_table_destroy (bl->block_hash);
    g_ptr_array_free (bl->block_ids, TRUE);
    g_free (bl);
}

void
block_list_insert (BlockList *bl, const char *block_id)
{
    if (g_hash_table_lookup (bl->block_hash, block_id))
        return;

    char *key = g_strdup(block_id);
    g_hash_table_insert (bl->block_hash, key, key);
    g_ptr_array_add (bl->block_ids, g_strdup(block_id));
    ++bl->n_blocks;
}

BlockList *
block_list_difference (BlockList *bl1, BlockList *bl2)
{
    BlockList *bl;
    int i;
    char *block_id;
    char *key;

    bl = block_list_new ();

    for (i = 0; i < bl1->block_ids->len; ++i) {
        block_id = g_ptr_array_index (bl1->block_ids, i);
        if (g_hash_table_lookup (bl2->block_hash, block_id) == NULL) {
            key = g_strdup(block_id);
            g_hash_table_insert (bl->block_hash, key, key);
            g_ptr_array_add (bl->block_ids, g_strdup(block_id));
            ++bl->n_blocks;
        }
    }

    return bl;
}

static int
traverse_file (SeafFSManager *mgr,
               const char *repo_id,
               int version,
               const char *id,
               TraverseFSTreeCallback callback,
               void *user_data,
               gboolean skip_errors)
{
    gboolean stop = FALSE;

    if (memcmp (id, EMPTY_SHA1, 40) == 0)
        return 0;

    if (!callback (mgr, repo_id, version, id, SEAF_METADATA_TYPE_FILE, user_data, &stop) &&
        !skip_errors)
        return -1;

    return 0;
}

static int
traverse_dir (SeafFSManager *mgr,
              const char *repo_id,
              int version,
              const char *id,
              TraverseFSTreeCallback callback,
              void *user_data,
              gboolean skip_errors)
{
    SeafDir *dir;
    GList *p;
    SeafDirent *seaf_dent;
    gboolean stop = FALSE;

    if (!callback (mgr, repo_id, version,
                   id, SEAF_METADATA_TYPE_DIR, user_data, &stop) &&
        !skip_errors)
        return -1;

    if (stop)
        return 0;

    dir = seaf_fs_manager_get_seafdir (mgr, repo_id, version, id);
    if (!dir) {
        g_warning ("[fs-mgr]get seafdir %s failed\n", id);
        if (skip_errors)
            return 0;
        return -1;
    }
    for (p = dir->entries; p; p = p->next) {
        seaf_dent = (SeafDirent *)p->data;

        if (S_ISREG(seaf_dent->mode)) {
            if (traverse_file (mgr, repo_id, version, seaf_dent->id,
                               callback, user_data, skip_errors) < 0) {
                if (!skip_errors) {
                    seaf_dir_free (dir);
                    return -1;
                }
            }
        } else if (S_ISDIR(seaf_dent->mode)) {
            if (traverse_dir (mgr, repo_id, version, seaf_dent->id,
                              callback, user_data, skip_errors) < 0) {
                if (!skip_errors) {
                    seaf_dir_free (dir);
                    return -1;
                }
            }
        }
    }

    seaf_dir_free (dir);
    return 0;
}

int
seaf_fs_manager_traverse_tree (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *root_id,
                               TraverseFSTreeCallback callback,
                               void *user_data,
                               gboolean skip_errors)
{
    if (strcmp (root_id, EMPTY_SHA1) == 0) {
        return 0;
    }
    return traverse_dir (mgr, repo_id, version, root_id, callback, user_data, skip_errors);
}

static int
traverse_dir_path (SeafFSManager *mgr,
                   const char *repo_id,
                   int version,
                   const char *dir_path,
                   SeafDirent *dent,
                   TraverseFSPathCallback callback,
                   void *user_data)
{
    SeafDir *dir;
    GList *p;
    SeafDirent *seaf_dent;
    gboolean stop = FALSE;
    char *sub_path;
    int ret = 0;

    if (!callback (mgr, dir_path, dent, user_data, &stop))
        return -1;

    if (stop)
        return 0;

    dir = seaf_fs_manager_get_seafdir (mgr, repo_id, version, dent->id);
    if (!dir) {
        seaf_warning ("get seafdir %s failed\n", dent->id);
        return -1;
    }

    for (p = dir->entries; p; p = p->next) {
        seaf_dent = (SeafDirent *)p->data;
        sub_path = g_strconcat (dir_path, "/", seaf_dent->name, NULL);

        if (S_ISREG(seaf_dent->mode)) {
            if (!callback (mgr, sub_path, seaf_dent, user_data, &stop)) {
                g_free (sub_path);
                ret = -1;
                break;
            }
        } else if (S_ISDIR(seaf_dent->mode)) {
            if (traverse_dir_path (mgr, repo_id, version, sub_path, seaf_dent,
                                   callback, user_data) < 0) {
                g_free (sub_path);
                ret = -1;
                break;
            }
        }
        g_free (sub_path);
    }

    seaf_dir_free (dir);
    return ret;
}

int
seaf_fs_manager_traverse_path (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *root_id,
                               const char *dir_path,
                               TraverseFSPathCallback callback,
                               void *user_data)
{
    SeafDirent *dent;
    int ret = 0;

    dent = seaf_fs_manager_get_dirent_by_path (mgr, repo_id, version,
                                               root_id, dir_path);
    if (!dent) {
        seaf_warning ("Failed to get dirent for %.8s:%s.\n", repo_id, dir_path);
        return -1;
    }

    ret = traverse_dir_path (mgr, repo_id, version, dir_path, dent,
                             callback, user_data);

    seaf_dirent_free (dent);
    return ret;
}

static gboolean
fill_blocklist (SeafFSManager *mgr,
                const char *repo_id, int version,
                const char *obj_id, int type,
                void *user_data, gboolean *stop)
{
    BlockList *bl = user_data;
    Seafile *seafile;
    int i;

    if (type == SEAF_METADATA_TYPE_FILE) {
        seafile = seaf_fs_manager_get_seafile (mgr, repo_id, version, obj_id);
        if (!seafile) {
            g_warning ("[fs mgr] Failed to find file %s.\n", obj_id);
            return FALSE;
        }

        for (i = 0; i < seafile->n_blocks; ++i)
            block_list_insert (bl, seafile->blk_sha1s[i]);

        seafile_unref (seafile);
    }

    return TRUE;
}

int
seaf_fs_manager_populate_blocklist (SeafFSManager *mgr,
                                    const char *repo_id,
                                    int version,
                                    const char *root_id,
                                    BlockList *bl)
{
    return seaf_fs_manager_traverse_tree (mgr, repo_id, version, root_id,
                                          fill_blocklist,
                                          bl, FALSE);
}

gboolean
seaf_fs_manager_object_exists (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *id)
{
    /* Empty file and dir always exists. */
    if (memcmp (id, EMPTY_SHA1, 40) == 0)
        return TRUE;

    return seaf_obj_store_obj_exists (mgr->obj_store, repo_id, version, id);
}

gint64
seaf_fs_manager_get_file_size (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *file_id)
{
    Seafile *file;
    gint64 file_size;

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr, repo_id, version, file_id);
    if (!file) {
        seaf_warning ("Couldn't get file %s\n", file_id);
        return -1;
    }

    file_size = file->file_size;

    seafile_unref (file);
    return file_size;
}

static gint64
get_dir_size (SeafFSManager *mgr, const char *repo_id, int version, const char *id)
{
    SeafDir *dir;
    SeafDirent *seaf_dent;
    guint64 size = 0;
    gint64 result;
    GList *p;

    dir = seaf_fs_manager_get_seafdir (mgr, repo_id, version, id);
    if (!dir)
        return -1;

    for (p = dir->entries; p; p = p->next) {
        seaf_dent = (SeafDirent *)p->data;

        if (S_ISREG(seaf_dent->mode)) {
            if (dir->version > 0)
                result = seaf_dent->size;
            else {
                result = seaf_fs_manager_get_file_size (mgr,
                                                        repo_id,
                                                        version,
                                                        seaf_dent->id);
                if (result < 0) {
                    seaf_dir_free (dir);
                    return result;
                }
            }
            size += result;
        } else if (S_ISDIR(seaf_dent->mode)) {
            result = get_dir_size (mgr, repo_id, version, seaf_dent->id);
            if (result < 0) {
                seaf_dir_free (dir);
                return result;
            }
            size += result;
        }
    }

    seaf_dir_free (dir);
    return size;
}

gint64
seaf_fs_manager_get_fs_size (SeafFSManager *mgr,
                             const char *repo_id,
                             int version,
                             const char *root_id)
{
     if (strcmp (root_id, EMPTY_SHA1) == 0)
        return 0;
     return get_dir_size (mgr, repo_id, version, root_id);
}

static int
count_dir_files (SeafFSManager *mgr, const char *repo_id, int version, const char *id)
{
    SeafDir *dir;
    SeafDirent *seaf_dent;
    int count = 0;
    int result;
    GList *p;

    dir = seaf_fs_manager_get_seafdir (mgr, repo_id, version, id);
    if (!dir)
        return -1;

    for (p = dir->entries; p; p = p->next) {
        seaf_dent = (SeafDirent *)p->data;

        if (S_ISREG(seaf_dent->mode)) {
            count ++;
        } else if (S_ISDIR(seaf_dent->mode)) {
            result = count_dir_files (mgr, repo_id, version, seaf_dent->id);
            if (result < 0) {
                seaf_dir_free (dir);
                return result;
            }
            count += result;
        }
    }

    seaf_dir_free (dir);
    return count;
}

int
seaf_fs_manager_count_fs_files (SeafFSManager *mgr,
                                const char *repo_id,
                                int version,
                                const char *root_id)
{
     if (strcmp (root_id, EMPTY_SHA1) == 0)
        return 0;
     return count_dir_files (mgr, repo_id, version, root_id);
}

SeafDir *
seaf_fs_manager_get_seafdir_by_path (SeafFSManager *mgr,
                                     const char *repo_id,
                                     int version,
                                     const char *root_id,
                                     const char *path,
                                     GError **error)
{
    SeafDir *dir;
    SeafDirent *dent;
    const char *dir_id = root_id;
    char *name, *saveptr;
    char *tmp_path = g_strdup(path);

    dir = seaf_fs_manager_get_seafdir (mgr, repo_id, version, dir_id);
    if (!dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_DIR_MISSING, "directory is missing");
        return NULL;
    }

    name = strtok_r (tmp_path, "/", &saveptr);
    while (name != NULL) {
        GList *l;
        for (l = dir->entries; l != NULL; l = l->next) {
            dent = l->data;

            if (strcmp(dent->name, name) == 0 && S_ISDIR(dent->mode)) {
                dir_id = dent->id;
                break;
            }
        }

        if (!l) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_PATH_NO_EXIST,
                         "Path does not exists %s", path);
            seaf_dir_free (dir);
            dir = NULL;
            break;
        }

        SeafDir *prev = dir;
        dir = seaf_fs_manager_get_seafdir (mgr, repo_id, version, dir_id);
        seaf_dir_free (prev);

        if (!dir) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_DIR_MISSING,
                         "directory is missing");
            break;
        }

        name = strtok_r (NULL, "/", &saveptr);
    }

    g_free (tmp_path);
    return dir;
}

char *
seaf_fs_manager_path_to_obj_id (SeafFSManager *mgr,
                                const char *repo_id,
                                int version,
                                const char *root_id,
                                const char *path,
                                guint32 *mode,
                                GError **error)
{
    char *copy = g_strdup (path);
    int off = strlen(copy) - 1;
    char *slash, *name;
    SeafDir *base_dir = NULL;
    SeafDirent *dent;
    GList *p;
    char *obj_id = NULL;

    while (off >= 0 && copy[off] == '/')
        copy[off--] = 0;

    if (strlen(copy) == 0) {
        /* the path is root "/" */
        if (mode) {
            *mode = S_IFDIR;
        }
        obj_id = g_strdup(root_id);
        goto out;
    }

    slash = strrchr (copy, '/');
    if (!slash) {
        base_dir = seaf_fs_manager_get_seafdir (mgr, repo_id, version, root_id);
        if (!base_dir) {
            g_warning ("Failed to find root dir %s.\n", root_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, " ");
            goto out;
        }
        name = copy;
    } else {
        *slash = 0;
        name = slash + 1;
        GError *tmp_error = NULL;
        base_dir = seaf_fs_manager_get_seafdir_by_path (mgr,
                                                        repo_id,
                                                        version,
                                                        root_id,
                                                        copy,
                                                        &tmp_error);
        if (tmp_error &&
            !g_error_matches(tmp_error,
                             SEAFILE_DOMAIN,
                             SEAF_ERR_PATH_NO_EXIST)) {
            g_warning ("Failed to get dir for %s.\n", copy);
            g_propagate_error (error, tmp_error);
            goto out;
        }

        /* The path doesn't exist in this commit. */
        if (!base_dir)
            goto out;
    }

    for (p = base_dir->entries; p != NULL; p = p->next) {
        dent = p->data;
        if (strcmp (dent->name, name) == 0) {
            obj_id = g_strdup (dent->id);
            if (mode) {
                *mode = dent->mode;
            }
            break;
        }
    }

out:
    if (base_dir)
        seaf_dir_free (base_dir);
    g_free (copy);
    return obj_id;
}

char *
seaf_fs_manager_get_seafile_id_by_path (SeafFSManager *mgr,
                                        const char *repo_id,
                                        int version,
                                        const char *root_id,
                                        const char *path,
                                        GError **error)
{
    guint32 mode;
    char *file_id;

    file_id = seaf_fs_manager_path_to_obj_id (mgr, repo_id, version,
                                              root_id, path, &mode, error);

    if (!file_id)
        return NULL;

    if (file_id && S_ISDIR(mode)) {
        g_free (file_id);
        return NULL;
    }

    return file_id;
}

char *
seaf_fs_manager_get_seafdir_id_by_path (SeafFSManager *mgr,
                                        const char *repo_id,
                                        int version,
                                        const char *root_id,
                                        const char *path,
                                        GError **error)
{
    guint32 mode = 0;
    char *dir_id;

    dir_id = seaf_fs_manager_path_to_obj_id (mgr, repo_id, version,
                                             root_id, path, &mode, error);

    if (!dir_id)
        return NULL;

    if (dir_id && !S_ISDIR(mode)) {
        g_free (dir_id);
        return NULL;
    }

    return dir_id;
}

SeafDirent *
seaf_fs_manager_get_dirent_by_path (SeafFSManager *mgr,
                                    const char *repo_id,
                                    int version,
                                    const char *root_id,
                                    const char *path)
{
    SeafDirent *dent = NULL;
    SeafDir *dir = NULL;
    char *parent_dir = NULL;
    char *file_name = NULL;

    parent_dir  = g_path_get_dirname(path);
    file_name = g_path_get_basename(path);

    if (strcmp (parent_dir, ".") == 0)
        dir = seaf_fs_manager_get_seafdir (mgr, repo_id, version, root_id);
    else
        dir = seaf_fs_manager_get_seafdir_by_path (mgr, repo_id, version,
                                                   root_id, parent_dir, NULL);

    if (!dir) {
        seaf_warning ("dir %s doesn't exist in repo %.8s.\n", parent_dir, repo_id);
        goto out;
    }

    GList *p;
    for (p = dir->entries; p; p = p->next) {
        SeafDirent *d = p->data;
        if (strcmp (d->name, file_name) == 0) {
            dent = seaf_dirent_dup(d);
            break;
        }
    }

out:
    if (dir)
        seaf_dir_free (dir);

    return dent;
}

static gboolean
verify_seafdir_v0 (const char *dir_id, const uint8_t *data, int len,
                   gboolean verify_id)
{
    guint32 meta_type;
    guint32 mode;
    char id[41];
    guint32 name_len;
    char name[SEAF_DIR_NAME_LEN];
    const uint8_t *ptr;
    int remain;
    int dirent_base_size;
    SHA_CTX ctx;
    uint8_t sha1[20];
    char check_id[41];

    if (len < sizeof(SeafdirOndisk)) {
        seaf_warning ("[fs mgr] Corrupt seafdir object %s.\n", dir_id);
        return FALSE;
    }

    ptr = data;
    remain = len;

    meta_type = get32bit (&ptr);
    remain -= 4;
    if (meta_type != SEAF_METADATA_TYPE_DIR) {
        seaf_warning ("Data does not contain a directory.\n");
        return FALSE;
    }

    if (verify_id)
        SHA1_Init (&ctx);

    dirent_base_size = 2 * sizeof(guint32) + 40;
    while (remain > dirent_base_size) {
        mode = get32bit (&ptr);
        memcpy (id, ptr, 40);
        id[40] = '\0';
        ptr += 40;
        name_len = get32bit (&ptr);
        remain -= dirent_base_size;
        if (remain >= name_len) {
            name_len = MIN (name_len, SEAF_DIR_NAME_LEN - 1);
            memcpy (name, ptr, name_len);
            ptr += name_len;
            remain -= name_len;
        } else {
            seaf_warning ("Bad data format for dir objcet %s.\n", dir_id);
            return FALSE;
        }

        if (verify_id) {
            /* Convert mode to little endian before compute. */
            if (G_BYTE_ORDER == G_BIG_ENDIAN)
                mode = GUINT32_SWAP_LE_BE (mode);

            SHA1_Update (&ctx, id, 40);
            SHA1_Update (&ctx, name, name_len);
            SHA1_Update (&ctx, &mode, sizeof(mode));
        }
    }

    if (!verify_id)
        return TRUE;

    SHA1_Final (sha1, &ctx);
    rawdata_to_hex (sha1, check_id, 20);

    if (strcmp (check_id, dir_id) == 0)
        return TRUE;
    else
        return FALSE;
}

static gboolean
verify_fs_object_json (const char *obj_id, uint8_t *data, int len)
{
    guint8 *decompressed;
    int outlen;
    unsigned char sha1[20];
    char hex[41];

    if (seaf_decompress (data, len, &decompressed, &outlen) < 0) {
        seaf_warning ("Failed to decompress fs object %s.\n", obj_id);
        return FALSE;
    }

    calculate_sha1 (sha1, (const char *)decompressed, outlen);
    rawdata_to_hex (sha1, hex, 20);

    g_free (decompressed);
    return (strcmp(hex, obj_id) == 0);
}

static gboolean
verify_seafdir (const char *dir_id, uint8_t *data, int len,
                gboolean verify_id, gboolean is_json)
{
    if (is_json)
        return verify_fs_object_json (dir_id, data, len);
    else
        return verify_seafdir_v0 (dir_id, data, len, verify_id);
}
                                        
gboolean
seaf_fs_manager_verify_seafdir (SeafFSManager *mgr,
                                const char *repo_id,
                                int version,
                                const char *dir_id,
                                gboolean verify_id,
                                gboolean *io_error)
{
    void *data;
    int len;

    if (memcmp (dir_id, EMPTY_SHA1, 40) == 0) {
        return TRUE;
    }

    if (seaf_obj_store_read_obj (mgr->obj_store, repo_id, version,
                                 dir_id, &data, &len) < 0) {
        seaf_warning ("[fs mgr] Failed to read dir %s.\n", dir_id);
        *io_error = TRUE;
        return FALSE;
    }

    gboolean ret = verify_seafdir (dir_id, data, len, verify_id, (version > 0));
    g_free (data);

    return ret;
}

static gboolean
verify_seafile_v0 (const char *id, const void *data, int len, gboolean verify_id)
{
    const SeafileOndisk *ondisk = data;
    SHA_CTX ctx;
    uint8_t sha1[20];
    char check_id[41];

    if (len < sizeof(SeafileOndisk)) {
        seaf_warning ("[fs mgr] Corrupt seafile object %s.\n", id);
        return FALSE;
    }

    if (ntohl(ondisk->type) != SEAF_METADATA_TYPE_FILE) {
        seaf_warning ("[fd mgr] %s is not a file.\n", id);
        return FALSE;
    }

    int id_list_length = len - sizeof(SeafileOndisk);
    if (id_list_length % 20 != 0) {
        seaf_warning ("[fs mgr] Bad seafile id list length %d.\n", id_list_length);
        return FALSE;
    }

    if (!verify_id)
        return TRUE;

    SHA1_Init (&ctx);
    SHA1_Update (&ctx, ondisk->block_ids, len - sizeof(SeafileOndisk));
    SHA1_Final (sha1, &ctx);

    rawdata_to_hex (sha1, check_id, 20);

    if (strcmp (check_id, id) == 0)
        return TRUE;
    else
        return FALSE;
}

static gboolean
verify_seafile (const char *id, void *data, int len,
                gboolean verify_id, gboolean is_json)
{
    if (is_json)
        return verify_fs_object_json (id, data, len);
    else
        return verify_seafile_v0 (id, data, len, verify_id);
}

gboolean
seaf_fs_manager_verify_seafile (SeafFSManager *mgr,
                                const char *repo_id,
                                int version,
                                const char *file_id,
                                gboolean verify_id,
                                gboolean *io_error)
{
    void *data;
    int len;

    if (memcmp (file_id, EMPTY_SHA1, 40) == 0) {
        return TRUE;
    }

    if (seaf_obj_store_read_obj (mgr->obj_store, repo_id, version,
                                 file_id, &data, &len) < 0) {
        seaf_warning ("[fs mgr] Failed to read file %s.\n", file_id);
        *io_error = TRUE;
        return FALSE;
    }

    gboolean ret = verify_seafile (file_id, data, len, verify_id, (version > 0));
    g_free (data);

    return ret;
}

static gboolean
verify_fs_object_v0 (const char *obj_id,
                     uint8_t *data,
                     int len,
                     gboolean verify_id)
{
    gboolean ret = TRUE;

    int type = seaf_metadata_type_from_data (obj_id, data, len, FALSE);
    switch (type) {
    case SEAF_METADATA_TYPE_FILE:
        ret = verify_seafile_v0 (obj_id, data, len, verify_id);
        break;
    case SEAF_METADATA_TYPE_DIR:
        ret = verify_seafdir_v0 (obj_id, data, len, verify_id);
        break;
    default:
        seaf_warning ("Invalid meta data type: %d.\n", type);
        return FALSE;
    }

    return ret;
}

gboolean
seaf_fs_manager_verify_object (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *obj_id,
                               gboolean verify_id,
                               gboolean *io_error)
{
    void *data;
    int len;
    gboolean ret = TRUE;

    if (memcmp (obj_id, EMPTY_SHA1, 40) == 0) {
        return TRUE;
    }

    if (seaf_obj_store_read_obj (mgr->obj_store, repo_id, version,
                                 obj_id, &data, &len) < 0) {
        seaf_warning ("[fs mgr] Failed to read object %s.\n", obj_id);
        *io_error = TRUE;
        return FALSE;
    }

    if (version == 0)
        ret = verify_fs_object_v0 (obj_id, data, len, verify_id);
    else
        ret = verify_fs_object_json (obj_id, data, len);

    g_free (data);
    return ret;
}

int
dir_version_from_repo_version (int repo_version)
{
    if (repo_version == 0)
        return 0;
    else
        return CURRENT_DIR_OBJ_VERSION;
}

int
seafile_version_from_repo_version (int repo_version)
{
    if (repo_version == 0)
        return 0;
    else
        return CURRENT_SEAFILE_OBJ_VERSION;
}
