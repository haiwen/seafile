/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#ifndef WIN32
    #include <arpa/inet.h>
#endif

#include <json-glib/json-glib.h>
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

#define SEAF_TMP_EXT ".seaftmp~"

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
               CDCFileDescriptor *cdc);
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
#if defined SEAFILE_SERVER && defined FULL_FEATURE
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

    return 0;
}

#ifndef SEAFILE_SERVER
static int
checkout_block (const char *block_id,
                int wfd,
                SeafileCrypt *crypt)
{
    SeafBlockManager *block_mgr = seaf->block_mgr;
    BlockHandle *handle;
    BlockMetadata *bmd;
    char *dec_out = NULL;
    int dec_out_len = -1;
    char *blk_content = NULL;

    handle = seaf_block_manager_open_block (block_mgr, block_id, BLOCK_READ);
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
                               const char *file_id, 
                               const char *file_path,
                               guint32 mode,
                               SeafileCrypt *crypt,
                               const char *conflict_suffix,
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

    seafile = seaf_fs_manager_get_seafile (mgr, file_id);
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
        if (checkout_block (blk_id, wfd, crypt) < 0)
            goto bad;
    }

    close (wfd);
    wfd = -1;

    /* The caller has detected conflict. */
    if (force_conflict) {
        *conflicted = TRUE;
        conflict_path = gen_conflict_path (file_path,
                                           conflict_suffix);
        if (ccnet_rename (tmp_path, conflict_path) < 0) {
            g_free (conflict_path);
            goto bad;
        }
        g_free (conflict_path);
    } else if (ccnet_rename (tmp_path, file_path) < 0) {
        if (conflict_suffix) {
            *conflicted = TRUE;
            conflict_path = gen_conflict_path (file_path,
                                               conflict_suffix);
            if (ccnet_rename (tmp_path, conflict_path) < 0) {
                g_free (conflict_path);
                goto bad;
            }
            g_free (conflict_path);
        } else
            goto bad;
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

static int
write_seafile (SeafFSManager *fs_mgr,
               CDCFileDescriptor *cdc)
{
    char seafile_id[41];
    SeafileOndisk *ondisk;
    int ondisk_size;
    int ret = 0;

    rawdata_to_hex (cdc->file_sum, seafile_id, 20);

    ondisk_size = sizeof(SeafileOndisk) + cdc->block_nr * 20;
    ondisk = (SeafileOndisk *)g_new0 (char, ondisk_size);

    ondisk->type = htonl(SEAF_METADATA_TYPE_FILE);
    ondisk->file_size = hton64 (cdc->file_size);
    memcpy (ondisk->block_ids, cdc->blk_sha1s, cdc->block_nr * 20);

    if (seaf_obj_store_write_obj (fs_mgr->obj_store, seafile_id,
                                  ondisk, ondisk_size) < 0)
        ret = -1;
    g_free (ondisk);

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
do_write_chunk (uint8_t *checksum, const char *buf, int len)
{
    SeafBlockManager *blk_mgr = seaf->block_mgr;
    char chksum_str[41];
    BlockHandle *handle;
    int n;

    rawdata_to_hex (checksum, chksum_str, 20);

    /* Don't write if the block already exists. */
    if (seaf_block_manager_block_exists (seaf->block_mgr, chksum_str))
        return 0;

    handle = seaf_block_manager_open_block (blk_mgr, chksum_str, BLOCK_WRITE);
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
seafile_write_chunk (CDCDescriptor *chunk,
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
            ret = do_write_chunk (checksum, encrypted_buf, enc_len);
        g_free (encrypted_buf);
    } else {
        /* not a encrypted repo, go ahead */
        SHA1_Init (&ctx);
        SHA1_Update (&ctx, chunk->block_buf, chunk->len);
        SHA1_Final (checksum, &ctx);

        if (write_data)
            ret = do_write_chunk (checksum, chunk->block_buf, chunk->len);
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
                              const char *file_path,
                              unsigned char sha1[],
                              SeafileCrypt *crypt)
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
        if (filename_chunk_cdc (file_path, &cdc, crypt, TRUE) < 0) {
            g_warning ("Failed to chunk file with CDC.\n");
            return -1;
        }
        memcpy (sha1, cdc.file_sum, 20);
    }

    if (write_seafile (mgr, &cdc) < 0) {
        g_warning ("Failed to write seafile for %s.\n", file_path);
        return -1;
    }

    if (cdc.blk_sha1s)
        free (cdc.blk_sha1s);

    return 0;
}

Seafile *
seafile_from_data (const char *id, const void *data, int len)
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

void *
seafile_to_data (Seafile *seafile, int *len)
{
    /* XXX: not implemented yet. */
    return NULL;
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

Seafile *
seaf_fs_manager_get_seafile (SeafFSManager *mgr, const char *file_id)
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

    if (seaf_obj_store_read_obj (mgr->obj_store, file_id, &data, &len) < 0) {
        g_warning ("[fs mgr] Failed to read file %s.\n", file_id);
        return NULL;
    }

    seafile = seafile_from_data (file_id, data, len);
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

static void compute_dir_id (SeafDir *dir, GList *entries)
{
    SHA_CTX ctx;
    GList *p;
    uint8_t sha1[20];
    SeafDirent *dent;

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
        SHA1_Update (&ctx, &dent->mode, sizeof(dent->mode));
    }
    SHA1_Final (sha1, &ctx);

    rawdata_to_hex (sha1, dir->dir_id, 20);
}

SeafDir *
seaf_dir_new (const char *id, GList *entries, gint64 ctime)
{
    SeafDir *dir;

    dir = g_new0(SeafDir, 1);

    if (id == NULL)
        compute_dir_id (dir, entries);
    else {
        memcpy(dir->dir_id, id, 40);
        dir->dir_id[40] = '\0';
    }

    dir->entries = entries;

    return dir;
} 

void 
seaf_dir_free (SeafDir *dir)
{
    if (dir == NULL)
        return;

    GList *ptr = dir->entries;
    while (ptr) {
        g_free (ptr->data);
        ptr = ptr->next;
    }

    g_list_free (dir->entries);
    g_free(dir);
}

SeafDir *
seaf_dir_from_data (const char *dir_id, const uint8_t *data, int len)
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
    memcpy(root->dir_id, dir_id, 40);
    root->dir_id[40] = '\0';

    dirent_base_size = 2 * sizeof(guint32) + 40;
    while (remain > dirent_base_size) {
        dent = g_new0(SeafDirent, 1);

        dent->mode = get32bit (&ptr);
        memcpy (dent->id, ptr, 40);
        dent->id[40] = '\0';
        ptr += 40;
        name_len = get32bit (&ptr);
        remain -= dirent_base_size;
        if (remain >= name_len) {
            dent->name_len = MIN (name_len, SEAF_DIR_NAME_LEN - 1);
            memcpy (dent->name, ptr, dent->name_len);
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

int
seaf_metadata_type_from_data (const uint8_t *data, int len)
{
    const uint8_t *ptr = data;

    if (len < sizeof(guint32))
        return SEAF_METADATA_TYPE_INVALID;

    return (int)(get32bit(&ptr));
}

inline static int
ondisk_dirent_size (SeafDirent *dirent)
{
    return sizeof(DirentOndisk) + dirent->name_len;
}

void *
seaf_dir_to_data (SeafDir *dir, int *len)
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

int 
seaf_dir_save (SeafFSManager *fs_mgr, SeafDir *dir)
{
    void *data;
    int len;
    int ret = 0;

    /* Don't need to save empty dir on disk. */
    if (memcmp (dir->dir_id, EMPTY_SHA1, 40) == 0)
        return 0;

    data = seaf_dir_to_data (dir, &len);

    if (seaf_obj_store_write_obj (fs_mgr->obj_store, dir->dir_id,
                                  data, len) < 0)
        ret = -1;

    g_free (data);

    return ret;
}

SeafDir *
seaf_fs_manager_get_seafdir (SeafFSManager *mgr, const char *dir_id)
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

    if (seaf_obj_store_read_obj (mgr->obj_store, dir_id, &data, &len) < 0) {
        g_warning ("[fs mgr] Failed to read dir %s.\n", dir_id);
        return NULL;
    }

    dir = seaf_dir_from_data (dir_id, data, len);
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
seaf_fs_manager_get_seafdir_sorted (SeafFSManager *mgr, const char *dir_id)
{
    SeafDir *dir = seaf_fs_manager_get_seafdir(mgr, dir_id);

    if (!dir)
        return NULL;

    if (!is_dirents_sorted (dir->entries))
        dir->entries = g_list_sort (dir->entries, compare_dirents);

    return dir;
}

SeafDirent *
seaf_dirent_new (const char *sha1, int mode, const char *name)
{
    SeafDirent *dent;

    dent = g_new0 (SeafDirent, 1);
    memcpy(dent->id, sha1, 40);
    dent->id[40] = '\0';
    dent->mode = mode;

    /* Name would be truncated if it's too long. */
    dent->name_len = MIN (strlen(name), SEAF_DIR_NAME_LEN - 1);
    memcpy (dent->name, name, dent->name_len);

    return dent;
}

SeafDirent *
seaf_dirent_dup (SeafDirent *dent)
{
    return g_memdup (dent, sizeof(SeafDirent));
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
    if (bl->block_map.bits != NULL)
        BitfieldDestruct (&bl->block_map);
    g_free (bl);
}

/** 
 * Determine which blocks exist in local.
 */
void
block_list_generate_bitmap (BlockList *bl)
{
    SeafBlockManager *blk_mgr = seaf->block_mgr;
    char *block_id;
    size_t i = 0;

    BitfieldConstruct (&bl->block_map, bl->n_blocks);
    for (i = 0; i < bl->n_blocks; ++i) {
        block_id = g_ptr_array_index (bl->block_ids, i);
        if (seaf_block_manager_block_exists (blk_mgr, block_id)) {
            BitfieldAdd (&bl->block_map, i);
            ++bl->n_valid_blocks;
        }
    }

    g_hash_table_destroy (bl->block_hash);
    bl->block_hash = NULL;
}

void
block_list_serialize (BlockList *bl, uint8_t **buffer, uint32_t *len)
{
    uint32_t i;
    uint32_t offset = 0;
    uint8_t *buf;

    buf = g_new (uint8_t, 41 * bl->n_blocks);
    for (i = 0; i < bl->n_blocks; ++i) {
        memcpy (&buf[offset], g_ptr_array_index(bl->block_ids, i), 41);
        offset += 41;
    }

    *buffer = buf;
    *len = 41 * bl->n_blocks;
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
               const char *id, 
               TraverseFSTreeCallback callback,
               void *user_data,
               gboolean skip_errors)
{
    gboolean stop = FALSE;

    if (memcmp (id, EMPTY_SHA1, 40) == 0)
        return 0;

    if (!callback (mgr, id, SEAF_METADATA_TYPE_FILE, user_data, &stop) &&
        !skip_errors)
        return -1;

    return 0;
}

static int
traverse_dir (SeafFSManager *mgr, 
              const char *id, 
              TraverseFSTreeCallback callback,
              void *user_data,
              gboolean skip_errors)
{
    SeafDir *dir;
    GList *p;
    SeafDirent *seaf_dent;
    gboolean stop = FALSE;

    if (!callback (mgr, id, SEAF_METADATA_TYPE_DIR, user_data, &stop) &&
        !skip_errors)
        return -1;

    if (stop)
        return 0;

    dir = seaf_fs_manager_get_seafdir (mgr, id);
    if (!dir) {
        g_warning ("[fs-mgr]get seafdir %s failed\n", id);
        if (skip_errors)
            return 0;
        return -1;
    }
    for (p = dir->entries; p; p = p->next) {
        seaf_dent = (SeafDirent *)p->data;

        if (S_ISREG(seaf_dent->mode)) {
            if (traverse_file (mgr, seaf_dent->id,
                               callback, user_data, skip_errors) < 0) {
                if (!skip_errors) {
                    seaf_dir_free (dir);
                    return -1;
                }
            }
        } else if (S_ISDIR(seaf_dent->mode)) {
            if (traverse_dir (mgr, seaf_dent->id,
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
                               const char *root_id,
                               TraverseFSTreeCallback callback,
                               void *user_data,
                               gboolean skip_errors)
{
    if (strcmp (root_id, EMPTY_SHA1) == 0) {
#if 0
        g_debug ("[fs-mgr] populate blocklist for empty root id\n");
#endif        
        return 0;
    }
    return traverse_dir (mgr, root_id, callback, user_data, skip_errors);
}

static gboolean
fill_blocklist (SeafFSManager *mgr, const char *obj_id, int type,
                void *user_data, gboolean *stop)
{
    BlockList *bl = user_data;
    Seafile *seafile;
    int i;

    if (type == SEAF_METADATA_TYPE_FILE) {
        seafile = seaf_fs_manager_get_seafile (mgr, obj_id);
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
                                    const char *root_id,
                                    BlockList *bl)
{
    return seaf_fs_manager_traverse_tree (mgr, root_id, 
                                          fill_blocklist,
                                          bl, FALSE);
}

gboolean
seaf_fs_manager_object_exists (SeafFSManager *mgr, const char *id)
{
    /* Empty file and dir always exists. */
    if (memcmp (id, EMPTY_SHA1, 40) == 0)
        return TRUE;

    return seaf_obj_store_obj_exists (mgr->obj_store, id);
}

gint64
seaf_fs_manager_get_file_size (SeafFSManager *mgr, const char *file_id)
{
    Seafile *file;
    gint64 file_size;

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr, file_id);
    if (!file) {
        seaf_warning ("Couldn't get file %s", file_id);
        return -1;
    }

    file_size = file->file_size;

    seafile_unref (file);
    return file_size;
}

static gint64
get_dir_size (SeafFSManager *mgr, const char *id)
{
    SeafDir *dir;
    SeafDirent *seaf_dent;
    guint64 size = 0;
    gint64 result;
    GList *p;

    dir = seaf_fs_manager_get_seafdir (mgr, id);
    if (!dir)
        return -1;

    for (p = dir->entries; p; p = p->next) {
        seaf_dent = (SeafDirent *)p->data;

        if (S_ISREG(seaf_dent->mode)) {
            result = seaf_fs_manager_get_file_size (mgr, seaf_dent->id);
            if (result < 0) {
                seaf_dir_free (dir);
                return result;
            }
            size += result;
        } else if (S_ISDIR(seaf_dent->mode)) {
            result = get_dir_size (mgr, seaf_dent->id);
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
                             const char *root_id)
{
     if (strcmp (root_id, EMPTY_SHA1) == 0)
        return 0;
     return get_dir_size (mgr, root_id);
}

static int
count_dir_files (SeafFSManager *mgr, const char *id)
{
    SeafDir *dir;
    SeafDirent *seaf_dent;
    int count = 0;
    int result;
    GList *p;

    dir = seaf_fs_manager_get_seafdir (mgr, id);
    if (!dir)
        return -1;

    for (p = dir->entries; p; p = p->next) {
        seaf_dent = (SeafDirent *)p->data;

        if (S_ISREG(seaf_dent->mode)) {
            count ++;
        } else if (S_ISDIR(seaf_dent->mode)) {
            result = count_dir_files (mgr, seaf_dent->id);
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
                                const char *root_id)
{
     if (strcmp (root_id, EMPTY_SHA1) == 0)
        return 0;
     return count_dir_files (mgr, root_id);
}

SeafDir *
seaf_fs_manager_get_seafdir_by_path (SeafFSManager *mgr,
                                     const char *root_id,
                                     const char *path,
                                     GError **error)
{
    SeafDir *dir;
    SeafDirent *dent;
    const char *dir_id = root_id;
    char *name, *saveptr;
    char *tmp_path = g_strdup(path);

    dir = seaf_fs_manager_get_seafdir (mgr, dir_id);
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
        dir = seaf_fs_manager_get_seafdir (mgr, dir_id);
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
        base_dir = seaf_fs_manager_get_seafdir (mgr, root_id);
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
                                        const char *root_id,
                                        const char *path,
                                        GError **error)
{
    guint32 mode;
    char *file_id;

    file_id = seaf_fs_manager_path_to_obj_id (mgr, root_id, path, &mode, error);

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
                                       const char *root_id,
                                       const char *path,
                                       GError **error)
{
    guint32 mode = 0;
    char *dir_id;

    dir_id = seaf_fs_manager_path_to_obj_id (mgr, root_id, path, &mode, error);

    if (!dir_id)
        return NULL;

    if (dir_id && !S_ISDIR(mode)) {
        g_free (dir_id);
        return NULL;
    }

    return dir_id;
}
                                        

