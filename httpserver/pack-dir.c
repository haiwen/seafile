#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_HTTP
#include "log.h"

#include <ccnet.h>

#include "seafile-object.h"
#include "seafile-crypt.h"
#include "seafile.h"

#include "utils.h"

#include "seafile-session.h"
#include "httpserver.h"

#include <archive.h>
#include <archive_entry.h>
#include <iconv.h>

#ifdef WIN32
#define S_IFLNK    0120000 /* Symbolic link */
#define S_ISLNK(x) (((x) & S_IFMT) == S_IFLNK)
#endif


typedef struct {
    struct archive *a;
    SeafileCrypt *crypt;
    const char *top_dir_name;
    gboolean is_windows;
    time_t mtime;

} PackDirData;

static char *
do_iconv (char *fromcode, char *tocode, char *in)
{
    iconv_t conv;
    size_t inlen, outlen, len;
    char out[1024];
    char *pin = in;
    char *pout = out;
    
    conv = iconv_open (tocode, fromcode);
    if (conv < 0) {
        return NULL;
    }

    inlen = strlen (in);
    outlen = sizeof(out);

    len = iconv (conv, &pin, &inlen, &pout, &outlen);
    iconv_close (conv);

    if (len == -1) {
        return NULL;
    }

    outlen = sizeof(out) - outlen;

    return g_strndup(out, outlen);
}

static int
add_file_to_archive (PackDirData *data,
                     const char *parent_dir,
                     SeafDirent *dent)
{
    struct archive *a = data->a;
    struct SeafileCrypt *crypt = data->crypt;
    gboolean is_windows = data->is_windows;
    const char *top_dir_name = data->top_dir_name;
    
    struct archive_entry *entry = NULL;
    Seafile *file = NULL;
    char *pathname = NULL;
    char buf[64 * 1024];
    int len = 0;
    int n = 0;
    int idx = 0;
    BlockHandle *handle = NULL;
    BlockMetadata *bmd = NULL;
    char *blk_id = NULL;
    uint32_t remain = 0;
    EVP_CIPHER_CTX ctx;
    gboolean enc_init = FALSE;
    char *dec_out = NULL;
    int dec_out_len = -1;
    int ret = 0;

    pathname = g_build_filename (top_dir_name, parent_dir, dent->name, NULL);

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr, dent->id);
    if (!file) {
        ret = -1;
        goto out;
    }

    entry = archive_entry_new ();

    /* File name fixup for WinRAR */
    if (is_windows && seaf->windows_encoding) {
        char *win_file_name = do_iconv ("UTF-8", seaf->windows_encoding, pathname);
        if (!win_file_name) {
            seaf_warning ("Failed to convert file name to %s\n", seaf->windows_encoding);
            ret = -1;
            goto out;
        }
        archive_entry_copy_pathname (entry, win_file_name);
        g_free (win_file_name);

    } else {
        archive_entry_set_pathname (entry, pathname);
    }

    /* FIXME: 0644 should be set when upload files in repo-mgr.c */
    archive_entry_set_mode (entry, dent->mode | 0644);
    archive_entry_set_size (entry, file->file_size);
    archive_entry_set_mtime (entry, data->mtime, 0);

    n = archive_write_header (a, entry);
    if (n != ARCHIVE_OK) {
        seaf_warning ("archive_write_header  error: %s\n", archive_error_string(a));
        ret = -1;
        goto out;
    }

    /* Read data of this entry block by block */
    while (idx < file->n_blocks) {
        blk_id = file->blk_sha1s[idx];
        handle = seaf_block_manager_open_block (seaf->block_mgr,
                                                blk_id, BLOCK_READ);
        if (!handle) {
            seaf_warning ("Failed to open block %s\n", blk_id);
            ret = -1;
            goto out;
        }

        bmd = seaf_block_manager_stat_block_by_handle (seaf->block_mgr,
                                                       handle);
        if (!bmd) {
            seaf_warning ("Failed to stat block %s\n", blk_id);
            ret = -1;
            goto out;
        }
        remain = bmd->size;
        g_free (bmd);

        if (crypt) {
            if (seafile_decrypt_init (&ctx, crypt->version,
                                      crypt->key, crypt->iv) < 0) {
                seaf_warning ("Failed to init decrypt.\n");
                ret = -1;
                goto out;
            }
            enc_init = TRUE;
        }

        while (remain != 0) {
            n = seaf_block_manager_read_block (seaf->block_mgr, handle,
                                               buf, sizeof(buf));
            if (n <= 0) {
                seaf_warning ("failed to read block %s\n", blk_id);
                ret = -1;
                goto out;
            }
            remain -= n;

            /* OK, We're read some data of this block  */
            if (crypt == NULL) {
                /* not encrypted */
                len = archive_write_data (a, buf, n);
                if (len <= 0) {
                    seaf_warning ("archive_write_data returned %d\n", len);
                    ret = -1;
                    goto out;
                }

            } else {
                /* an encrypted block */
                dec_out = g_new (char, n + 16);
                if (!dec_out) {
                    seaf_warning ("Failed to alloc memory.\n");
                    ret = -1;
                    goto out;
                }

                int r = EVP_DecryptUpdate (&ctx,
                                           (unsigned char *)dec_out,
                                           &dec_out_len,
                                           (unsigned char *)buf,
                                           n);

                /* EVP_DecryptUpdate returns 1 on success, 0 on failure */
                if (r != 1) {
                    seaf_warning ("Decrypt block %s failed.\n", blk_id);
                    ret = -1;
                    goto out;
                }

                if (dec_out_len > 0) {
                    len = archive_write_data (a, dec_out, dec_out_len);
                    if (len <= 0) {
                        seaf_warning ("archive_write_data returned %d\n", len);
                        ret = -1;
                        goto out;
                    }
                }

                /* If it's the last piece of a block, call decrypt_final()
                 * to decrypt the possible partial block. */
                if (remain == 0) {
                    r = EVP_DecryptFinal_ex (&ctx,
                                             (unsigned char *)dec_out,
                                             &dec_out_len);
                    if (r != 1) {
                        seaf_warning ("Decrypt block %s failed.\n", blk_id);
                        ret = -1;
                        goto out;
                    }

                    if (dec_out_len != 0) {
                        len = archive_write_data (a, dec_out, dec_out_len);
                        if (len <= 0) {
                            seaf_warning ("archive_write_data returned %d\n", len);
                            ret = -1;
                            goto out;
                        }
                    }
                }

                g_free (dec_out);
                dec_out = NULL;
            }
        }

        seaf_block_manager_close_block (seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
        handle = NULL;

        /* turn to next block */
        idx++;
    }

out:
    g_free (pathname);
    if (entry)
        archive_entry_free (entry);
    if (file)
        seafile_unref (file);
    if (handle) {
        seaf_block_manager_close_block (seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free(seaf->block_mgr, handle);
    }
    if (crypt != NULL && enc_init)
        EVP_CIPHER_CTX_cleanup (&ctx);
    g_free (dec_out);

    return ret;
}

static int
archive_dir (PackDirData *data,
             const char *root_id,
             const char *dirpath)
             
{
    SeafDir *dir = NULL;
    SeafDirent *dent;
    GList *ptr;
    char *subpath = NULL;
    int ret = 0;

    dir = seaf_fs_manager_get_seafdir (seaf->fs_mgr, root_id);
    if (!dir) {
        seaf_warning ("failed to get dir %s\n", root_id);
        goto out;
    }

    for (ptr = dir->entries; ptr; ptr = ptr->next) {
        dent = ptr->data;
        if (S_ISREG(dent->mode)) {
            ret = add_file_to_archive (data, dirpath, dent);

        } else if (S_ISLNK(dent->mode)) {
            if (archive_version_number() >= 3000001) {
                /* Symlink in zip arhive is not supported in earlier version
                 * of libarchive */
                ret = add_file_to_archive (data, dirpath, dent);
            }

        } else if (S_ISDIR(dent->mode)) {
            subpath = g_build_filename (dirpath, dent->name, NULL);
            ret = archive_dir (data, dent->id, subpath);
            g_free (subpath);
        }

        if (ret < 0) {
            goto out;
        }
    }

out:
    if (dir)
        seaf_dir_free (dir);

    return ret;
}

char *pack_dir (const char *dirname,
                const char *root_id,
                SeafileCrypt *crypt,
                gboolean is_windows)
{
    struct archive *a = NULL;
    char *tmpfile_name = NULL ;
    char *ret = NULL;
    int fd = -1;
    PackDirData *data = NULL;

    fd = g_file_open_tmp ("seafile-XXXXXX.zip", &tmpfile_name, NULL);
    if (fd < 0) {
        goto out;
    }

    a = archive_write_new ();
    archive_write_set_compression_none (a);
    archive_write_set_format_zip (a);
    archive_write_open_fd (a, fd);

    data = g_new0 (PackDirData, 1);
    data->crypt = crypt;
    data->is_windows = is_windows;
    data->a = a;
    data->top_dir_name = dirname;
    data->mtime = time(NULL);

    if (archive_dir (data, root_id, "") < 0) {
        g_debug ("failed to archive_dir\n");
        goto out;
    }

    if (archive_write_finish(a) < 0) {
        goto out;
    }

    ret = g_strdup (tmpfile_name);

out:
    if (data) g_free (data);
    if (fd > 0) close (fd);
    
    if (!ret && tmpfile_name) {
        /* zip failed: remove tmp file */
        unlink (tmpfile_name);
    }
    g_free (tmpfile_name);

    return ret;
}
