#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_HTTP
#include "log.h"

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#else
#include <event.h>
#endif

#include <evhtp.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <ccnet.h>

#include "seafile-object.h"
#include "seafile-crypt.h"

#include "utils.h"

#include "seafile-session.h"
#include "access-file.h"
#include "pack-dir.h"

#define FILE_TYPE_MAP_DEFAULT_LEN 1
#define BUFFER_SIZE 1024 * 64
#define MULTI_DOWNLOAD_FILE_PREFIX "documents-export-"

struct file_type_map {
    char *suffix;
    char *type;
};

typedef struct SendBlockData {
    evhtp_request_t *req;
    char *block_id;
    BlockHandle *handle;
    uint32_t bsize;
    uint32_t remain;

    char store_id[37];
    int repo_version;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendBlockData;

typedef struct SendfileData {
    evhtp_request_t *req;
    Seafile *file;
    SeafileCrypt *crypt;
    gboolean enc_init;
    EVP_CIPHER_CTX ctx;
    BlockHandle *handle;
    size_t remain;
    int idx;

    char store_id[37];
    int repo_version;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendfileData;

typedef struct SendFileRangeData {
    evhtp_request_t *req;
    Seafile *file;
    BlockHandle *handle;
    int blk_idx;
    guint64 start_off;
    guint64 range_remain;

    char store_id[37];
    int repo_version;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendFileRangeData;

typedef struct SendDirData {
    evhtp_request_t *req;
    size_t remain;

    int zipfd;
    char *zipfile;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendDirData;



extern SeafileSession *seaf;

static struct file_type_map ftmap[] = {
    { "txt", "text/plain" },
    { "doc", "application/vnd.ms-word" },
    { "docx", "application/vnd.ms-word" },
    { "ppt", "application/vnd.ms-powerpoint" },
    { "pptx", "application/vnd.ms-powerpoint" },
    { "xls", "application/vnd.ms-excel" },
    { "xlsx", "application/vnd.ms-excel" },
    { "pdf", "application/pdf" },
    { "zip", "application/zip"},
    { "mp3", "audio/mp3" },
    { "mpeg", "video/mpeg" },
    { "mp4", "video/mp4" },
    { "jpg", "image/jpg" },
    { "JPG", "image/jpg" },
    { "png", "image/png" },
    { "PNG", "image/png" },
    { "gif", "image/gif" },
    { "GIF", "image/gif" },
    { NULL, NULL },
};

static void
free_sendblock_data (SendBlockData *data)
{
    if (data->handle) {
        seaf_block_manager_close_block(seaf->block_mgr, data->handle);
        seaf_block_manager_block_handle_free(seaf->block_mgr, data->handle);
    }

    g_free (data->block_id);
    g_free (data);
}

static void
free_sendfile_data (SendfileData *data)
{
    if (data->handle) {
        seaf_block_manager_close_block(seaf->block_mgr, data->handle);
        seaf_block_manager_block_handle_free(seaf->block_mgr, data->handle);
    }

    if (data->enc_init)
        EVP_CIPHER_CTX_cleanup (&data->ctx);

    seafile_unref (data->file);
    g_free (data->crypt);
    g_free (data);
}

static void
free_send_file_range_data (SendFileRangeData *data)
{
    if (data->handle) {
        seaf_block_manager_close_block(seaf->block_mgr, data->handle);
        seaf_block_manager_block_handle_free(seaf->block_mgr, data->handle);
    }

    seafile_unref (data->file);
    g_free (data);
}

static void
free_senddir_data (SendDirData *data)
{
    close (data->zipfd);
    g_unlink (data->zipfile);

    g_free (data->zipfile);
    g_free (data);
}

static void
write_block_data_cb (struct bufferevent *bev, void *ctx)
{
    SendBlockData *data = ctx;
    char *blk_id;
    BlockHandle *handle;
    char buf[1024 * 64];
    int n;

    blk_id = data->block_id;

    if (!data->handle) {
        data->handle = seaf_block_manager_open_block(seaf->block_mgr,
                                                     data->store_id,
                                                     data->repo_version,
                                                     blk_id, BLOCK_READ);
        if (!data->handle) {
            seaf_warning ("Failed to open block %s:%s\n", data->store_id, blk_id);
            goto err;
        }

        data->remain = data->bsize;
    }
    handle = data->handle;

    n = seaf_block_manager_read_block(seaf->block_mgr, handle, buf, sizeof(buf));
    data->remain -= n;
    if (n < 0) {
        seaf_warning ("Error when reading from block %s:%s.\n",
                      data->store_id, blk_id);
        goto err;
    } else if (n == 0) {
        /* We've read up the data of this block, finish. */
        seaf_block_manager_close_block (seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
        data->handle = NULL;

        /* Recover evhtp's callbacks */
        bev->readcb = data->saved_read_cb;
        bev->writecb = data->saved_write_cb;
        bev->errorcb = data->saved_event_cb;
        bev->cbarg = data->saved_cb_arg;

        /* Resume reading incomming requests. */
        evhtp_request_resume (data->req);

        evhtp_send_reply_end (data->req);

        free_sendblock_data (data);
        return;
    }

    /* OK, we've got some data to send. */
    bufferevent_write (bev, buf, n);

    return;

err:
    evhtp_connection_free (evhtp_request_get_connection (data->req));
    free_sendblock_data (data);
    return;
}

static void
write_data_cb (struct bufferevent *bev, void *ctx)
{
    SendfileData *data = ctx;
    char *blk_id;
    BlockHandle *handle;
    char buf[1024 * 64];
    int n;

next:
    blk_id = data->file->blk_sha1s[data->idx];

    if (!data->handle) {
        data->handle = seaf_block_manager_open_block(seaf->block_mgr,
                                                     data->store_id,
                                                     data->repo_version,
                                                     blk_id, BLOCK_READ);
        if (!data->handle) {
            seaf_warning ("Failed to open block %s:%s\n", data->store_id, blk_id);
            goto err;
        }

        BlockMetadata *bmd;
        bmd = seaf_block_manager_stat_block_by_handle (seaf->block_mgr,
                                                       data->handle);
        if (!bmd)
            goto err;
        data->remain = bmd->size;
        g_free (bmd);

        if (data->crypt) {
            if (seafile_decrypt_init (&data->ctx,
                                      data->crypt->version,
                                      (unsigned char *)data->crypt->key,
                                      (unsigned char *)data->crypt->iv) < 0) {
                seaf_warning ("Failed to init decrypt.\n");
                goto err;
            }
            data->enc_init = TRUE;
        }
    }
    handle = data->handle;

    n = seaf_block_manager_read_block(seaf->block_mgr, handle, buf, sizeof(buf));
    data->remain -= n;
    if (n < 0) {
        seaf_warning ("Error when reading from block %s.\n", blk_id);
        goto err;
    } else if (n == 0) {
        /* We've read up the data of this block, finish or try next block. */
        seaf_block_manager_close_block (seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
        data->handle = NULL;
        if (data->crypt != NULL) {
            EVP_CIPHER_CTX_cleanup (&data->ctx);
            data->enc_init = FALSE;
        }

        if (data->idx == data->file->n_blocks - 1) {
            /* Recover evhtp's callbacks */
            bev->readcb = data->saved_read_cb;
            bev->writecb = data->saved_write_cb;
            bev->errorcb = data->saved_event_cb;
            bev->cbarg = data->saved_cb_arg;

            /* Resume reading incomming requests. */
            evhtp_request_resume (data->req);

            evhtp_send_reply_end (data->req);

            free_sendfile_data (data);
            return;
        }

        ++(data->idx);
        goto next;
    }

    /* OK, we've got some data to send. */
    if (data->crypt != NULL) {
        char *dec_out;
        int dec_out_len = -1;
        struct evbuffer *tmp_buf;

        dec_out = g_new (char, n + 16);
        if (!dec_out) {
            seaf_warning ("Failed to alloc memory.\n");
            goto err;
        }

        int ret = EVP_DecryptUpdate (&data->ctx,
                                     (unsigned char *)dec_out,
                                     &dec_out_len,
                                     (unsigned char *)buf,
                                     n);
        if (ret == 0) {
            seaf_warning ("Decrypt block %s:%s failed.\n", data->store_id, blk_id);
            g_free (dec_out);
            goto err;
        }

        tmp_buf = evbuffer_new ();

        evbuffer_add (tmp_buf, dec_out, dec_out_len);

        /* If it's the last piece of a block, call decrypt_final()
         * to decrypt the possible partial block. */
        if (data->remain == 0) {
            ret = EVP_DecryptFinal_ex (&data->ctx,
                                       (unsigned char *)dec_out,
                                       &dec_out_len);
            if (ret == 0) {
                seaf_warning ("Decrypt block %s:%s failed.\n", data->store_id, blk_id);
                evbuffer_free (tmp_buf);
                g_free (dec_out);
                goto err;
            }
            evbuffer_add (tmp_buf, dec_out, dec_out_len);
        }
        /* This may call write_data_cb() recursively (by libevent_openssl).
         * SendfileData struct may be free'd in the recursive calls.
         * So don't use "data" variable after here.
         */
        bufferevent_write_buffer (bev, tmp_buf);

        evbuffer_free (tmp_buf);
        g_free (dec_out);
    } else {
        bufferevent_write (bev, buf, n);
    }

    return;

err:
    evhtp_connection_free (evhtp_request_get_connection (data->req));
    free_sendfile_data (data);
    return;
}

static void
write_dir_data_cb (struct bufferevent *bev, void *ctx)
{
    SendDirData *data = ctx;
    char buf[64 * 1024];
    int n;

    n = readn (data->zipfd, buf, sizeof(buf));
    if (n < 0) {
        seaf_warning ("failed to read zipfile %s\n", data->zipfile);
        evhtp_connection_free (evhtp_request_get_connection (data->req));
        free_senddir_data (data);
    } else if (n > 0) {
        bufferevent_write (bev, buf, n);
        data->remain -= n;

        if (data->remain == 0) {
            /* Recover evhtp's callbacks */
            bev->readcb = data->saved_read_cb;
            bev->writecb = data->saved_write_cb;
            bev->errorcb = data->saved_event_cb;
            bev->cbarg = data->saved_cb_arg;

            /* Resume reading incomming requests. */
            evhtp_request_resume (data->req);

            evhtp_send_reply_end (data->req);

            free_senddir_data (data);
            return;
        }
    }
}

static void
my_block_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendBlockData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_sendblock_data (data);
}

static void
my_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendfileData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_sendfile_data (data);
}

static void
file_range_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendFileRangeData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_send_file_range_data (data);
}

static void
my_dir_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendDirData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_senddir_data (data);
}

static char *
parse_content_type(const char *filename)
{
    char *p;
    int i;

    if ((p = strrchr(filename, '.')) == NULL)
        return NULL;
    p++;

    for (i = 0; ftmap[i].suffix != NULL; i++) {
        if (strcmp(p, ftmap[i].suffix) == 0)
            return ftmap[i].type;
    }

    return NULL;
}

static gboolean
test_windows (evhtp_request_t *req)
{
    const char *user_agent = evhtp_header_find (req->headers_in, "User-Agent");
    if (!user_agent)
        return FALSE;

    GString *s = g_string_new (user_agent);
    if (g_strrstr (g_string_ascii_down (s)->str, "windows")) {
        g_string_free (s, TRUE);
        return TRUE;
    }
    else {
        g_string_free (s, TRUE);
        return FALSE;
    }
}

static gboolean
test_firefox (evhtp_request_t *req)
{
    const char *user_agent = evhtp_header_find (req->headers_in, "User-Agent");
    if (!user_agent)
        return FALSE;

    GString *s = g_string_new (user_agent);
    if (g_strrstr (g_string_ascii_down (s)->str, "firefox")) {
        g_string_free (s, TRUE);
        return TRUE;
    }
    else {
        g_string_free (s, TRUE);
        return FALSE;
    }
}

static int
do_file(evhtp_request_t *req, SeafRepo *repo, const char *file_id,
        const char *filename, const char *operation,
        SeafileCryptKey *crypt_key)
{
    Seafile *file;
    char *type = NULL;
    char file_size[255];
    gchar *content_type = NULL;
    char cont_filename[SEAF_PATH_MAX];
    char *key_hex, *iv_hex;
    unsigned char enc_key[32], enc_iv[16];
    SeafileCrypt *crypt = NULL;
    SendfileData *data;

    file = seaf_fs_manager_get_seafile(seaf->fs_mgr,
                                       repo->store_id, repo->version, file_id);
    if (file == NULL)
        return -1;

    if (crypt_key != NULL) {
        g_object_get (crypt_key,
                      "key", &key_hex,
                      "iv", &iv_hex,
                      NULL);
        if (repo->enc_version == 1)
            hex_to_rawdata (key_hex, enc_key, 16);
        else
            hex_to_rawdata (key_hex, enc_key, 32);
        hex_to_rawdata (iv_hex, enc_iv, 16);
        crypt = seafile_crypt_new (repo->enc_version, enc_key, enc_iv);
        g_free (key_hex);
        g_free (iv_hex);
    }

    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Access-Control-Allow-Origin",
                                              "*", 1, 1));


    type = parse_content_type(filename);
    if (type != NULL) {
        if (strstr(type, "text")) {
            content_type = g_strjoin("; ", type, "charset=gbk", NULL);
        } else {
            content_type = g_strdup (type);
        }

        evhtp_headers_add_header(req->headers_out,
                                 evhtp_header_new("Content-Type",
                                                  content_type, 1, 1));
        g_free (content_type);
    } else
        evhtp_headers_add_header (req->headers_out,
                                  evhtp_header_new("Content-Type",
                                                   "application/octet-stream", 1, 1));

    snprintf(file_size, sizeof(file_size), "%"G_GINT64_FORMAT"", file->file_size);
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Content-Length", file_size, 1, 1));

    if (strcmp(operation, "download") == 0) {
        if (test_firefox (req)) {
            snprintf(cont_filename, SEAF_PATH_MAX,
                     "attachment;filename*=\"utf8\' \'%s\"", filename);
        } else {
            snprintf(cont_filename, SEAF_PATH_MAX,
                     "attachment;filename=\"%s\"", filename);
        }
    } else {
        if (test_firefox (req)) {
            snprintf(cont_filename, SEAF_PATH_MAX,
                     "inline;filename*=\"utf8\' \'%s\"", filename);
        } else {
            snprintf(cont_filename, SEAF_PATH_MAX,
                     "inline;filename=\"%s\"", filename);
        }
    }
    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Disposition", cont_filename,
                                              1, 1));

    if (g_strcmp0 (type, "image/jpg") != 0) {
        evhtp_headers_add_header(req->headers_out,
                                 evhtp_header_new("X-Content-Type-Options", "nosniff",
                                                  1, 1));
    }

    /* If it's an empty file, send an empty reply. */
    if (file->n_blocks == 0) {
        evhtp_send_reply (req, EVHTP_RES_OK);
        seafile_unref (file);
        return 0;
    }

    data = g_new0 (SendfileData, 1);
    data->req = req;
    data->file = file;
    data->crypt = crypt;

    memcpy (data->store_id, repo->store_id, 36);
    data->repo_version = repo->version;

    /* We need to overwrite evhtp's callback functions to
     * write file data piece by piece.
     */
    struct bufferevent *bev = evhtp_request_get_bev (req);
    data->saved_read_cb = bev->readcb;
    data->saved_write_cb = bev->writecb;
    data->saved_event_cb = bev->errorcb;
    data->saved_cb_arg = bev->cbarg;
    bufferevent_setcb (bev,
                       NULL,
                       write_data_cb,
                       my_event_cb,
                       data);
    /* Block any new request from this connection before finish
     * handling this request.
     */
    evhtp_request_pause (req);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_OK);

    return 0;
}

// get block handle for range start
static BlockHandle *
get_start_block_handle (const char *store_id, int version, Seafile *file,
                        guint64 start, int *blk_idx)
{
    BlockHandle *handle = NULL;
    BlockMetadata *bmd;
    char *blkid;
    guint64 tolsize = 0;
    int i = 0;

    for (; i < file->n_blocks; i++) {
        blkid = file->blk_sha1s[i];

        bmd = seaf_block_manager_stat_block(seaf->block_mgr, store_id,
                                            version, blkid);
        if (!bmd)
            return NULL;

        if (start < tolsize + bmd->size) {
            g_free (bmd);
            break;
        }
        tolsize += bmd->size;
        g_free (bmd);
    }

    /* beyond the file size */
    if (i == file->n_blocks)
        return NULL;

    handle = seaf_block_manager_open_block(seaf->block_mgr,
                                           store_id, version,
                                           blkid, BLOCK_READ);
    if (!handle) {
        seaf_warning ("Failed to open block %s:%s.\n", store_id, blkid);
        return NULL;
    }

    /* trim the offset in a block */
    if (start > tolsize) {
        char *tmp = (char *)malloc(sizeof(*tmp) * (start - tolsize));
        if (!tmp)
            goto err;

        int n = seaf_block_manager_read_block(seaf->block_mgr, handle,
                                              tmp, start-tolsize);
        if (n != start-tolsize) {
            seaf_warning ("Failed to read block %s:%s.\n", store_id, blkid);
            free (tmp);
            goto err;
        }
        free (tmp);
    }

    *blk_idx = i;
    return handle;

err:
    seaf_block_manager_close_block(seaf->block_mgr, handle);
    seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
    return NULL;
}

static void
finish_file_range_request (struct bufferevent *bev, SendFileRangeData *data)
{
    /* Recover evhtp's callbacks */
    bev->readcb = data->saved_read_cb;
    bev->writecb = data->saved_write_cb;
    bev->errorcb = data->saved_event_cb;
    bev->cbarg = data->saved_cb_arg;

    /* Resume reading incomming requests. */
    evhtp_request_resume (data->req);

    evhtp_send_reply_end (data->req);

    free_send_file_range_data (data);
}

static void
write_file_range_cb (struct bufferevent *bev, void *ctx)
{
    SendFileRangeData *data = ctx;
    char *blk_id;
    char buf[BUFFER_SIZE];
    int bsize;
    int n;

    if (data->blk_idx == -1) {
        // start to send block
        data->handle = get_start_block_handle (data->store_id, data->repo_version,
                                               data->file, data->start_off,
                                               &data->blk_idx);
        if (!data->handle)
            goto err;
    }

next:
    blk_id = data->file->blk_sha1s[data->blk_idx];

    if (!data->handle) {
        data->handle = seaf_block_manager_open_block(seaf->block_mgr,
                                                     data->store_id,
                                                     data->repo_version,
                                                     blk_id, BLOCK_READ);
        if (!data->handle) {
            seaf_warning ("Failed to open block %s:%s\n", data->store_id, blk_id);
            goto err;
        }
    }

    bsize = data->range_remain < BUFFER_SIZE ? data->range_remain : BUFFER_SIZE;
    n = seaf_block_manager_read_block(seaf->block_mgr, data->handle, buf, bsize);
    data->range_remain -= n;
    if (n < 0) {
        seaf_warning ("Error when reading from block %s:%s.\n",
                      data->store_id, blk_id);
        goto err;
    } else if (n == 0) {
        seaf_block_manager_close_block (seaf->block_mgr, data->handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, data->handle);
        data->handle = NULL;
        ++data->blk_idx;
        goto next;
    }

    bufferevent_write (bev, buf, n);
    if (data->range_remain == 0) {
        finish_file_range_request (bev, data);
    }

    return;

err:
    evhtp_connection_free (evhtp_request_get_connection (data->req));
    free_send_file_range_data (data);
}

// parse range offset, only support single range (-num, num-num, num-)
static gboolean
parse_range_val (const char *byte_ranges, guint64 *pstart, guint64 *pend,
                 guint64 fsize)
{
    char *minus;
    char *end_ptr;
    gboolean error = FALSE;
    char *ranges_dup = g_strdup (strchr(byte_ranges, '=') + 1);
    char *tmp = ranges_dup;
    guint64 start;
    guint64 end;

    minus = strchr(tmp, '-');
    if (!minus)
        return FALSE;

    if (minus == tmp) {
        // -num mode
        start = strtoll(tmp, &end_ptr, 10);
        if (start == 0) {
            // range format is invalid
            error = TRUE;
        } else if (*end_ptr == '\0') {
            end = fsize - 1;
            start += fsize;
        } else {
            error = TRUE;
        }
    } else if (*(minus + 1) == '\0') {
        // num- mode
        start = strtoll(tmp, &end_ptr, 10);
        if (end_ptr == minus) {
            end = fsize - 1;
        } else {
            error = TRUE;
        }
    } else {
        // num-num mode
        start = strtoll(tmp, &end_ptr, 10);
        if (end_ptr == minus) {
            end = strtoll(minus + 1, &end_ptr, 10);
            if (*end_ptr != '\0') {
                error = TRUE;
            }
        } else {
            error = TRUE;
        }
    }

    g_free (ranges_dup);

    if (error)
        return FALSE;

    if (end > fsize - 1) {
        end = fsize - 1;
    }
    if (start > end) {
        // Range format is valid, but range number is invalid
        return FALSE;
    }

    *pstart = start;
    *pend = end;

    return TRUE;
}

static void
set_resp_disposition (evhtp_request_t *req, const char *operation,
                      const char *filename)
{
    char *cont_filename = NULL;

    if (strcmp(operation, "download") == 0) {
        if (test_firefox (req)) {
            cont_filename = g_strdup_printf("attachment;filename*=\"utf8\' \'%s\"",
                                            filename);

        } else {
            cont_filename = g_strdup_printf("attachment;filename=\"%s\"", filename);
        }
    } else {
        if (test_firefox (req)) {
            cont_filename = g_strdup_printf("inline;filename*=\"utf8\' \'%s\"",
                                            filename);
        } else {
            cont_filename = g_strdup_printf("inline;filename=\"%s\"", filename);
        }
    }

    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Disposition", cont_filename,
                                              0, 1));
    g_free (cont_filename);
}

static int
do_file_range (evhtp_request_t *req, SeafRepo *repo, const char *file_id,
               const char *filename, const char *operation, const char *byte_ranges)
{
    Seafile *file;
    SendFileRangeData *data = NULL;
    guint64 start;
    guint64 end;

    file = seaf_fs_manager_get_seafile(seaf->fs_mgr,
                                       repo->store_id, repo->version, file_id);
    if (file == NULL)
        return -1;

    /* If it's an empty file, send an empty reply. */
    if (file->n_blocks == 0) {
        evhtp_send_reply (req, EVHTP_RES_OK);
        seafile_unref (file);
        return 0;
    }

    if (!parse_range_val (byte_ranges, &start, &end, file->file_size)) {
        seafile_unref (file);
        char *con_range = g_strdup_printf ("bytes */%"G_GUINT64_FORMAT, file->file_size);
        evhtp_headers_add_header (req->headers_out,
                                  evhtp_header_new("Content-Range", con_range,
                                                   0, 1));
        g_free (con_range);
        evhtp_send_reply (req, EVHTP_RES_RANGENOTSC);
        return 0;
    }

    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new ("Accept-Ranges", "bytes", 0, 0));

    char *content_type = NULL;
    char *type = parse_content_type (filename);
    if (type != NULL) {
        if (strstr(type, "text")) {
            content_type = g_strjoin("; ", type, "charset=gbk", NULL);
        } else {
            content_type = g_strdup (type);
        }
    } else {
        content_type = g_strdup ("application/octet-stream");
    }

    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new ("Content-Type", content_type, 0, 1));
    g_free (content_type);

    char *con_len = g_strdup_printf ("%"G_GUINT64_FORMAT, end-start+1);
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Content-Length", con_len, 0, 1));
    g_free (con_len);

    char *con_range = g_strdup_printf ("%s %"G_GUINT64_FORMAT"-%"G_GUINT64_FORMAT
                                       "/%"G_GUINT64_FORMAT, "bytes",
                                       start, end, file->file_size);
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new ("Content-Range", con_range, 0, 1));
    g_free (con_range);

    set_resp_disposition (req, operation, filename);

    if (g_strcmp0 (type, "image/jpg") != 0) {
        evhtp_headers_add_header(req->headers_out,
                                 evhtp_header_new("X-Content-Type-Options", "nosniff",
                                                  1, 1));
    }

    data = g_new0 (SendFileRangeData, 1);
    if (!data) {
        seafile_unref (file);
        return -1;
    }
    data->req = req;
    data->file = file;
    data->blk_idx = -1;
    data->start_off = start;
    data->range_remain = end-start+1;

    memcpy (data->store_id, repo->store_id, 36);
    data->repo_version = repo->version;

    /* We need to overwrite evhtp's callback functions to
     * write file data piece by piece.
     */
    struct bufferevent *bev = evhtp_request_get_bev (req);
    data->saved_read_cb = bev->readcb;
    data->saved_write_cb = bev->writecb;
    data->saved_event_cb = bev->errorcb;
    data->saved_cb_arg = bev->cbarg;
    bufferevent_setcb (bev,
                       NULL,
                       write_file_range_cb,
                       file_range_event_cb,
                       data);


    /* Block any new request from this connection before finish
     * handling this request.
     */
    evhtp_request_pause (req);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_PARTIAL);

    return 0;
}

static int
start_download_zip_file (evhtp_request_t *req, const char *zipname,
                         char *zipfile)
{
    SeafStat st;
    char file_size[255];
    char cont_filename[SEAF_PATH_MAX];
    int zipfd = 0;

    if (seaf_stat(zipfile, &st) < 0) {
        seaf_warning ("Failed to stat %s: %s.\n", zipfile, strerror(errno));
        return -1;
    }

    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Type", "application/zip", 1, 1));

    snprintf (file_size, sizeof(file_size), "%"G_GUINT64_FORMAT"", st.st_size);
    evhtp_headers_add_header (req->headers_out,
            evhtp_header_new("Content-Length", file_size, 1, 1));

    if (test_firefox (req)) {
        snprintf(cont_filename, SEAF_PATH_MAX,
                 "attachment;filename*=\"utf8\' \'%s.zip\"", zipname);
    } else {
        snprintf(cont_filename, SEAF_PATH_MAX,
                 "attachment;filename=\"%s.zip\"", zipname);
    }

    evhtp_headers_add_header(req->headers_out,
            evhtp_header_new("Content-Disposition", cont_filename, 1, 1));

    zipfd = g_open (zipfile, O_RDONLY | O_BINARY, 0);
    if (zipfd < 0) {
        seaf_warning ("Failed to open zipfile %s: %s.\n", zipfile, strerror(errno));
        return -1;
    }

    SendDirData *data;
    data = g_new0 (SendDirData, 1);
    data->req = req;
    data->zipfd = zipfd;
    data->zipfile = zipfile;
    data->remain = st.st_size;

    /* We need to overwrite evhtp's callback functions to
     * write file data piece by piece.
     */
    struct bufferevent *bev = evhtp_request_get_bev (req);
    data->saved_read_cb = bev->readcb;
    data->saved_write_cb = bev->writecb;
    data->saved_event_cb = bev->errorcb;
    data->saved_cb_arg = bev->cbarg;
    bufferevent_setcb (bev,
                       NULL,
                       write_dir_data_cb,
                       my_dir_event_cb,
                       data);
    /* Block any new request from this connection before finish
     * handling this request.
     */
    evhtp_request_pause (req);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_OK);

    return 0;
}

static int
do_dir (evhtp_request_t *req, SeafRepo *repo, const char *dir_id,
        const char *filename, SeafileCryptKey *crypt_key)
{
    char *zipfile = NULL;
    char *filename_escaped = NULL;
    char *key_hex, *iv_hex;
    unsigned char enc_key[32], enc_iv[16];
    SeafileCrypt *crypt = NULL;
    int ret = 0;
    gint64 dir_size = 0;

    /* ensure file size does not exceed limit */
    dir_size = seaf_fs_manager_get_fs_size (seaf->fs_mgr,
                                            repo->store_id, repo->version,
                                            dir_id);
    if (dir_size < 0 || dir_size > seaf->http_server->max_download_dir_size) {
        seaf_warning ("invalid dir size: %"G_GINT64_FORMAT"\n", dir_size);
        return -1;
    }

    /* Let's zip the directory first */
    filename_escaped = g_uri_unescape_string (filename, NULL);
    if (!filename_escaped) {
        seaf_warning ("failed to unescape string %s\n", filename);
        return -1;
    }

    if (crypt_key != NULL) {
        g_object_get (crypt_key,
                      "key", &key_hex,
                      "iv", &iv_hex,
                      NULL);
        if (repo->enc_version == 1)
            hex_to_rawdata (key_hex, enc_key, 16);
        else
            hex_to_rawdata (key_hex, enc_key, 32);
        hex_to_rawdata (iv_hex, enc_iv, 16);
        crypt = seafile_crypt_new (repo->enc_version, enc_key, enc_iv);
        g_free (key_hex);
        g_free (iv_hex);
    }

    zipfile = pack_dir (repo->store_id, repo->version,
                        filename_escaped, dir_id, crypt, test_windows(req));

    if (crypt) {
        g_free (crypt);
    }

    if (!zipfile) {
        g_free (filename_escaped);
        return -1;
    }

    ret = start_download_zip_file (req, filename_escaped, zipfile);
    if (ret < 0) {
        g_unlink (zipfile);
        g_free (zipfile);
    }

    g_free (filename_escaped);

    return ret;
}

static GList *
get_download_dirent_list (SeafRepo *repo, const char *data)
{
    json_t *obj;
    const char *tmp_parent_dir;
    char *parent_dir;
    gboolean is_root_dir;
    json_t *name_array;
    json_error_t jerror;
    int i;
    int len;
    const char *file_name;
    char *file_path;
    SeafDirent *dirent;
    GList *dirent_list = NULL;
    GError *error = NULL;

    obj = json_loadb (data, strlen(data), 0, &jerror);
    if (!obj) {
        seaf_warning ("Failed to parse download file list: %s.\n", jerror.text);
        return NULL;
    }

    tmp_parent_dir = json_object_get_string_member (obj, "parent_dir");
    if (!tmp_parent_dir || strcmp (tmp_parent_dir, "") == 0) {
        seaf_warning ("Invalid download file list data, no parent_dir field.\n");
        json_decref (obj);
        return NULL;
    }
    name_array = json_object_get (obj, "file_list");
    if (!name_array) {
        seaf_warning ("Invalid download file list data, no file_list field.\n");
        json_decref (obj);
        return NULL;
    }
    len = json_array_size (name_array);
    if (len == 0) {
        seaf_warning ("Invalid download file list data, no download file name.\n");
        json_decref (obj);
        return NULL;
    }
    parent_dir = format_dir_path (tmp_parent_dir);
    is_root_dir = strcmp (parent_dir, "/") == 0;

    for (i = 0; i < len; i++) {
        file_name = json_string_value (json_array_get (name_array, i));
        if (strcmp (file_name, "") == 0 || strchr (file_name, '/') != NULL) {
            seaf_warning ("Invalid download file name: %s.\n", file_name);
            if (dirent_list) {
                g_list_free_full (dirent_list, (GDestroyNotify)seaf_dirent_free);
                dirent_list = NULL;
            }
            break;
        }

        if (is_root_dir) {
            file_path = g_strconcat (parent_dir, file_name, NULL);
        } else {
            file_path = g_strconcat (parent_dir, "/", file_name, NULL);
        }

        dirent = seaf_fs_manager_get_dirent_by_path (seaf->fs_mgr, repo->store_id,
                                                     repo->version, repo->root_id,
                                                     file_path, &error);
        if (!dirent) {
            if (error) {
                seaf_warning ("Failed to get dirent for %s: %s, stop download multi files.\n",
                              file_path, error->message);
                g_clear_error (&error);
            } else {
                seaf_warning ("Failed to get dirent for %s, stop download multi files.\n",
                              file_path);
            }
            g_free (file_path);
            if (dirent_list) {
                g_list_free_full (dirent_list, (GDestroyNotify)seaf_dirent_free);
                dirent_list = NULL;
            }
            break;
        }

        g_free (file_path);
        dirent_list = g_list_prepend (dirent_list, dirent);
    }

    g_free (parent_dir);
    json_decref (obj);

    return dirent_list;
}

static gint64
calcuate_download_size (SeafRepo *repo, GList *dirent_list)
{
    GList *iter = dirent_list;
    SeafDirent *dirent;
    gint64 size;
    gint64 total_size = 0;

    for (; iter; iter = iter->next) {
        dirent = iter->data;
        if (S_ISREG(dirent->mode)) {
            if (repo->version > 0) {
                size = dirent->size;
            } else {
                size = seaf_fs_manager_get_file_size (seaf->fs_mgr, repo->store_id,
                                                      repo->version, dirent->id);
            }
            if (size < 0) {
                seaf_warning ("Failed to get file %s size.\n", dirent->name);
                return -1;
            }
            total_size += size;
        } else if (S_ISDIR(dirent->mode)) {
            size = seaf_fs_manager_get_fs_size (seaf->fs_mgr, repo->store_id,
                                                repo->version, dirent->id);
            if (size < 0) {
                seaf_warning ("Failed to get dir %s size.\n", dirent->name);
                return -1;
            }
            total_size += size;
        }
    }

    return total_size;
}

static int
download_multi (evhtp_request_t *req, SeafRepo *repo,
                GList *dirent_list, SeafileCryptKey *crypt_key)
{
    gint64 total_size;
    char *zipfile = NULL;
    char *key_hex, *iv_hex;
    unsigned char enc_key[32], enc_iv[16];
    SeafileCrypt *crypt = NULL;
    char date_str[11];
    time_t now;
    char *filename;
    int ret = 0;

    total_size = calcuate_download_size (repo, dirent_list);
    if (total_size < 0) {
        seaf_warning ("Failed to calcuate download size, stop download multi files.\n");
        return -1;
    } else if (total_size > seaf->http_server->max_download_dir_size) {
        seaf_warning ("Total download size %"G_GINT64_FORMAT
                      ", exceed max download dir size %"G_GINT64_FORMAT
                      ", stop download multi files.\n",
                      total_size, seaf->http_server->max_download_dir_size);
        return -1;
    }

    if (crypt_key != NULL) {
        g_object_get (crypt_key,
                      "key", &key_hex,
                      "iv", &iv_hex,
                      NULL);
        if (repo->enc_version == 1)
            hex_to_rawdata (key_hex, enc_key, 16);
        else
            hex_to_rawdata (key_hex, enc_key, 32);
        hex_to_rawdata (iv_hex, enc_iv, 16);
        crypt = seafile_crypt_new (repo->enc_version, enc_key, enc_iv);
        g_free (key_hex);
        g_free (iv_hex);
    }

    zipfile = pack_mutli_files (repo->store_id, repo->version,
                                dirent_list, crypt, test_windows(req));

    if (crypt) {
        g_free (crypt);
    }

    if (!zipfile) {
        return -1;
    }

    now = time(NULL);
    strftime(date_str, sizeof(date_str), "%Y-%m-%d", localtime(&now));
    filename = g_strconcat (MULTI_DOWNLOAD_FILE_PREFIX, date_str, NULL);

    ret = start_download_zip_file (req, filename, zipfile);
    if (ret < 0) {
        g_unlink (zipfile);
        g_free (zipfile);
    }

    g_free (filename);

    return ret;
}

static void
access_cb(evhtp_request_t *req, void *arg)
{
    SeafRepo *repo = NULL;
    char *error = NULL;
    char *token = NULL;
    char *filename = NULL;
    const char *repo_id = NULL;
    const char *data = NULL;
    const char *operation = NULL;
    const char *user = NULL;
    const char *byte_ranges = NULL;
    GList *dirent_list = NULL;

    GError *err = NULL;
    SeafileCryptKey *key = NULL;
    SeafileWebAccess *webaccess = NULL;

    /* Skip the first '/'. */
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    if (!parts || g_strv_length (parts) < 2 ||
        strcmp (parts[0], "files") != 0) {
        error = "Invalid URL";
        goto bad_req;
    }

    token = parts[1];
    // For upload-multi, no filename parameter
    if (g_strv_length (parts) > 2) {
        filename = parts[2];
    }

    webaccess = seaf_web_at_manager_query_access_token (seaf->web_at_mgr, token);
    if (!webaccess) {
        error = "Bad access token";
        goto bad_req;
    }

    repo_id = seafile_web_access_get_repo_id (webaccess);
    data = seafile_web_access_get_obj_id (webaccess);
    operation = seafile_web_access_get_op (webaccess);
    user = seafile_web_access_get_username (webaccess);

    if (strcmp(operation, "view") != 0 &&
        strcmp(operation, "download") != 0 &&
        strcmp(operation, "download-dir") != 0 &&
        strcmp(operation, "download-multi") != 0) {
        error = "Bad access token";
        goto bad_req;
    }

    if (evhtp_kv_find (req->headers_in, "If-Modified-Since") != NULL) {
        evhtp_send_reply (req, EVHTP_RES_NOTMOD);
        goto success;
    } else {
        char http_date[256];
        evhtp_kv_t *kv;
        time_t now = time(NULL);

        /* Set Last-Modified header if the client gets this file
         * for the first time. So that the client will set
         * If-Modified-Since header the next time it gets the same
         * file.
         */
#ifndef WIN32
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %T GMT",
                  gmtime(&now));
#else
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %H:%M:%S GMT",
                  gmtime(&now));
#endif
        kv = evhtp_kv_new ("Last-Modified", http_date, 1, 1);
        evhtp_kvs_add_kv (req->headers_out, kv);

        kv = evhtp_kv_new ("Cache-Control", "max-age=3600", 1, 1);
        evhtp_kvs_add_kv (req->headers_out, kv);
    }

    byte_ranges = evhtp_kv_find (req->headers_in, "Range");

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, repo_id);
    if (!repo) {
        error = "Bad repo id\n";
        goto bad_req;
    }

    if (repo->encrypted) {
        err = NULL;
        key = seaf_passwd_manager_get_decrypt_key (seaf->passwd_mgr,
                                                   repo_id, user);
        if (!key) {
            error = "Repo is encrypted. Please provide password to view it.";
            goto bad_req;
        }
    }

    if (strcmp (operation, "download-multi") == 0) {
        dirent_list = get_download_dirent_list (repo, data);
        if (!dirent_list) {
            error = "Invalid file list info\n";
            goto bad_req;
        }

        if (download_multi (req, repo, dirent_list, key) < 0) {
            error = "Internal server error\n";
            goto bad_req;
        }
    } else {
        if (!seaf_fs_manager_object_exists (seaf->fs_mgr,
                                            repo->store_id, repo->version, data)) {
            error = "Invalid file id\n";
            goto bad_req;
        }

        if (strcmp(operation, "download-dir") == 0) {
            if (do_dir(req, repo, data, filename, key) < 0) {
                error = "Internal server error\n";
                goto bad_req;
            }
        } else if (!repo->encrypted && byte_ranges) {
            if (do_file_range (req, repo, data, filename, operation, byte_ranges) < 0) {
                error = "Internal server error\n";
                goto bad_req;
            }
        } else if (do_file(req, repo, data, filename, operation, key) < 0) {
            error = "Internal server error\n";
            goto bad_req;
        }
    }

success:
    g_strfreev (parts);
    if (repo != NULL)
        seaf_repo_unref (repo);
    if (key != NULL)
        g_object_unref (key);
    if (webaccess)
        g_object_unref (webaccess);
    if (dirent_list)
        g_list_free_full (dirent_list, (GDestroyNotify)seaf_dirent_free);

    return;

bad_req:
    g_strfreev (parts);
    if (repo != NULL)
        seaf_repo_unref (repo);
    if (key != NULL)
        g_object_unref (key);
    if (webaccess != NULL)
        g_object_unref (webaccess);
    if (dirent_list)
        g_list_free_full (dirent_list, (GDestroyNotify)seaf_dirent_free);

    evbuffer_add_printf(req->buffer_out, "%s\n", error);
    evhtp_send_reply(req, EVHTP_RES_BADREQ);
}

static int
do_block(evhtp_request_t *req, SeafRepo *repo, const char *file_id,
         const char *blk_id)
{
    Seafile *file;
    uint32_t bsize;
    gboolean found = FALSE;
    int i;
    char blk_size[255];
    char cont_filename[SEAF_PATH_MAX];
    SendBlockData *data;

    file = seaf_fs_manager_get_seafile(seaf->fs_mgr,
                                       repo->store_id, repo->version, file_id);
    if (file == NULL)
        return -1;

    for (i = 0; i < file->n_blocks; i++) {
        if (memcmp(file->blk_sha1s[i], blk_id, 40) == 0) {
            BlockMetadata *bm = seaf_block_manager_stat_block (seaf->block_mgr,
                                                               repo->store_id,
                                                               repo->version,
                                                               blk_id);
            if (bm && bm->size >= 0) {
                bsize = bm->size;
                found = TRUE;
            }
            g_free (bm);
            break;
        }
    }

    seafile_unref (file);

    /* block not found. */
    if (!found) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return 0;
    }
    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Access-Control-Allow-Origin",
                                              "*", 1, 1));

    if (test_firefox (req)) {
        snprintf(cont_filename, SEAF_PATH_MAX,
                 "attachment;filename*=\"utf8\' \'%s\"", blk_id);
    } else {
        snprintf(cont_filename, SEAF_PATH_MAX,
                 "attachment;filename=\"%s\"", blk_id);
    }
    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Disposition", cont_filename,
                                              1, 1));

    snprintf(blk_size, sizeof(blk_size), "%"G_GUINT32_FORMAT"", bsize);
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Content-Length", blk_size, 1, 1));

    data = g_new0 (SendBlockData, 1);
    data->req = req;
    data->block_id = g_strdup(blk_id);

    memcpy (data->store_id, repo->store_id, 36);
    data->repo_version = repo->version;

    /* We need to overwrite evhtp's callback functions to
     * write file data piece by piece.
     */
    struct bufferevent *bev = evhtp_request_get_bev (req);
    data->saved_read_cb = bev->readcb;
    data->saved_write_cb = bev->writecb;
    data->saved_event_cb = bev->errorcb;
    data->saved_cb_arg = bev->cbarg;
    data->bsize = bsize;
    bufferevent_setcb (bev,
                       NULL,
                       write_block_data_cb,
                       my_block_event_cb,
                       data);
    /* Block any new request from this connection before finish
     * handling this request.
     */
    evhtp_request_pause (req);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_OK);

    return 0;
}

static void
access_blks_cb(evhtp_request_t *req, void *arg)
{
    SeafRepo *repo = NULL;
    char *error = NULL;
    char *token = NULL;
    char *blkid = NULL;
    const char *repo_id = NULL;
    const char *id = NULL;
    const char *operation = NULL;

    char *repo_role = NULL;
    SeafileWebAccess *webaccess = NULL;

    /* Skip the first '/'. */
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    if (!parts || g_strv_length (parts) < 3 ||
        strcmp (parts[0], "blks") != 0) {
        error = "Invalid URL";
        goto bad_req;
    }

    token = parts[1];
    blkid = parts[2];

    webaccess = seaf_web_at_manager_query_access_token (seaf->web_at_mgr, token);
    if (!webaccess) {
        error = "Bad access token";
        goto bad_req;
    }

    if (evhtp_kv_find (req->headers_in, "If-Modified-Since") != NULL) {
        evhtp_send_reply (req, EVHTP_RES_NOTMOD);
        goto success;
    } else {
        char http_date[256];
        evhtp_kv_t *kv;
        time_t now = time(NULL);

        /* Set Last-Modified header if the client gets this file
         * for the first time. So that the client will set
         * If-Modified-Since header the next time it gets the same
         * file.
         */
#ifndef WIN32
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %T GMT",
                  gmtime(&now));
#else
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %H:%M:%S GMT",
                  gmtime(&now));
#endif
        kv = evhtp_kv_new ("Last-Modified", http_date, 1, 1);
        evhtp_kvs_add_kv (req->headers_out, kv);

        kv = evhtp_kv_new ("Cache-Control", "max-age=3600", 1, 1);
        evhtp_kvs_add_kv (req->headers_out, kv);
    }

    repo_id = seafile_web_access_get_repo_id (webaccess);
    id = seafile_web_access_get_obj_id (webaccess);
    operation = seafile_web_access_get_op (webaccess);

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, repo_id);
    if (!repo) {
        error = "Bad repo id\n";
        goto bad_req;
    }

    if (!seaf_fs_manager_object_exists (seaf->fs_mgr,
                                        repo->store_id, repo->version, id)) {
        error = "Invalid file id\n";
        goto bad_req;
    }

    if (strcmp(operation, "downloadblks") == 0) {
        if (do_block(req, repo, id, blkid) < 0) {
            error = "Internal server error\n";
            goto bad_req;
        }
    }

success:
    g_strfreev (parts);
    if (repo != NULL)
        seaf_repo_unref (repo);
    g_free (repo_role);
    g_object_unref (webaccess);

    return;

bad_req:
    g_strfreev (parts);
    if (repo != NULL)
        seaf_repo_unref (repo);
    g_free (repo_role);
    if (webaccess != NULL)
        g_object_unref (webaccess);

    evbuffer_add_printf(req->buffer_out, "%s\n", error);
    evhtp_send_reply(req, EVHTP_RES_BADREQ);
}

int
access_file_init (evhtp_t *htp)
{
    evhtp_set_regex_cb (htp, "^/files/.*", access_cb, NULL);
    evhtp_set_regex_cb (htp, "^/blks/.*", access_blks_cb, NULL);

    return 0;
}
