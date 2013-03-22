#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_HTTP
#include "log.h"

#include <event.h>
#include <evhtp.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <ccnet.h>

#include "seafile-object.h"
#include "seafile-crypt.h"
#include "seafile.h"

#include "utils.h"

#include "seafile-session.h"
#include "httpserver.h"
#include "access-file.h"
#include "pack-dir.h"

#define CONTENT_TYPE_FILENAME "content-type.txt"
#define FILE_TYPE_MAP_DEFAULT_LEN 1

struct file_type_map {
    char *suffix;
    char *type;
};

typedef struct SendfileData {
    evhtp_request_t *req;
    Seafile *file;
    SeafileCrypt *crypt;
    gboolean enc_init;
    EVP_CIPHER_CTX ctx;
    BlockHandle *handle;
    size_t remain;
    int idx;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendfileData;

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
    { "html", "text/html" },
    { "doc", "application/word" },
    { "docx", "application/word" },
    { "mp3", "audio/mp3" },
    { "pdf", "application/pdf" },
    { NULL, NULL },
};

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
free_senddir_data (SendDirData *data)
{
    close (data->zipfd);
    unlink (data->zipfile);
    
    g_free (data->zipfile);
    g_free (data);
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
                                                     blk_id, BLOCK_READ);
        if (!data->handle) {
            seaf_warning ("Failed to open block %s\n", blk_id);
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
            seaf_warning ("Decrypt block %s failed.\n", blk_id);
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
                seaf_warning ("Decrypt block %s failed.\n", blk_id);
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
my_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendfileData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_sendfile_data (data);
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
    unsigned char enc_key[16], enc_iv[16];
    SeafileCrypt *crypt = NULL;
    SendfileData *data;

    file = seaf_fs_manager_get_seafile(seaf->fs_mgr, file_id);
    if (file == NULL)
        return -1;

    if (crypt_key != NULL) {
        g_object_get (crypt_key,
                      "key", &key_hex,
                      "iv", &iv_hex,
                      NULL);
        hex_to_rawdata (key_hex, enc_key, 16);
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
    }

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

    /* Avoid recursive call of write_data_cb(). */
    if (req->htp->ssl_cfg != NULL)
        evbuffer_defer_callbacks (bev->output, bev->ev_base);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_OK);

    return 0;
}

static int
do_dir (evhtp_request_t *req, SeafRepo *repo, const char *dir_id,
        const char *filename, const char *operation,
        SeafileCryptKey *crypt_key)
{
    char *zipfile = NULL;
    char *filename_escaped = NULL;
    char cont_filename[SEAF_PATH_MAX];
    char file_size[255];
    struct stat st;
    char *key_hex, *iv_hex;
    unsigned char enc_key[16], enc_iv[16];
    SeafileCrypt *crypt = NULL;
    int zipfd = 0;
    int ret = 0;
    gint64 dir_size = 0;

    /* ensure file size does not exceed limit */
    dir_size = seaf_fs_manager_get_fs_size (seaf->fs_mgr, dir_id);
    if (dir_size < 0 || dir_size > seaf->max_download_dir_size) {
        seaf_warning ("invalid dir size: %"G_GINT64_FORMAT"\n", dir_size);
        ret = -1;
        goto out;
    }

    /* Let's zip the directory first */
    filename_escaped = g_uri_unescape_string (filename, NULL);
    if (!filename_escaped) {
        seaf_warning ("failed to unescape string %s\n", filename);
        ret = -1;
        goto out;
    }

    if (crypt_key != NULL) {
        g_object_get (crypt_key,
                      "key", &key_hex,
                      "iv", &iv_hex,
                      NULL);
        hex_to_rawdata (key_hex, enc_key, 16);
        hex_to_rawdata (iv_hex, enc_iv, 16);
        crypt = seafile_crypt_new (repo->enc_version, enc_key, enc_iv);
        g_free (key_hex);
        g_free (iv_hex);
    }

    zipfile = pack_dir (filename_escaped, dir_id, crypt, test_windows(req));
    if (!zipfile) {
        ret = -1;
        goto out;
    }
    
    /* OK, the dir is zipped */
    evhtp_headers_add_header(req->headers_out,
                evhtp_header_new("Content-Type", "application/zip", 1, 1));
    
    if (stat(zipfile, &st) < 0) {
        ret = -1;
        goto out;
    }

#ifndef WIN32
    snprintf (file_size, sizeof(file_size), "%"G_GUINT64_FORMAT"", st.st_size);
#else
    snprintf (file_size, sizeof(file_size), "%ld", st.st_size);
#endif
    evhtp_headers_add_header (req->headers_out,
            evhtp_header_new("Content-Length", file_size, 1, 1));

    if (test_firefox (req)) {
        snprintf(cont_filename, SEAF_PATH_MAX,
                 "attachment;filename*=\"utf8\' \'%s.zip\"", filename);
    } else {
        snprintf(cont_filename, SEAF_PATH_MAX,
                 "attachment;filename=\"%s.zip\"", filename);
    }

    evhtp_headers_add_header(req->headers_out,
            evhtp_header_new("Content-Disposition", cont_filename, 1, 1));

    zipfd = open (zipfile, O_RDONLY);
    if (zipfd < 0) {
        seaf_warning ("failed to open zipfile %s\n", zipfile);
        ret = -1;
        goto out;
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

    /* Avoid recursive call of write_dir_data_cb(). */
    if (req->htp->ssl_cfg != NULL)
        evbuffer_defer_callbacks (bev->output, bev->ev_base);

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_OK);

out:
    g_free (filename_escaped);
    if (ret < 0) {
        if (zipfile != NULL) {
            unlink (zipfile);
            g_free (zipfile);
        }

        if (zipfd > 0) {
            close (zipfd);
        }
    }

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
    const char *id = NULL;
    const char *operation = NULL;
    const char *user = NULL;

    SearpcClient *rpc_client = NULL;
    GError *err = NULL;
    char *repo_role = NULL;
    SeafileCryptKey *key = NULL;
    SeafileWebAccess *webaccess = NULL;

    /* Skip the first '/'. */
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    if (!parts || g_strv_length (parts) < 3 ||
        strcmp (parts[0], "files") != 0) {
        error = "Invalid URL";
        goto bad_req;
    }

    token = parts[1];
    filename = parts[2];

    rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                 NULL,
                                                 "seafserv-rpcserver");

    webaccess = (SeafileWebAccess *) searpc_client_call__object (
        rpc_client, "seafile_web_query_access_token", SEAFILE_TYPE_WEB_ACCESS,
        NULL, 1, "string", token);
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
    user = seafile_web_access_get_username (webaccess);

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, repo_id);
    if (!repo) {
        error = "Bad repo id\n";
        goto bad_req;
    }

    if (repo->encrypted) {
        err = NULL;
        key = (SeafileCryptKey *) seafile_get_decrypt_key (rpc_client,
                                                           repo_id, user, &err);
        if (!key) {
            error = "Repo is encrypted. Please provide password to view it.";
            goto bad_req;
        }
    }

    if (!seaf_fs_manager_object_exists (seaf->fs_mgr, id)) {
        error = "Invalid file id\n";
        goto bad_req;
    }

    if (strcmp(operation, "download-dir") == 0) {
        if (do_dir(req, repo, id, filename, operation, key) < 0) {
            error = "Internal server error\n";
            goto bad_req;
        }
        
    } else if (do_file(req, repo, id, filename, operation, key) < 0) {
        error = "Internal server error\n";
        goto bad_req;
    }

success:
    ccnet_rpc_client_free (rpc_client);

    g_strfreev (parts);
    if (repo != NULL)
        seaf_repo_unref (repo);
    g_free (repo_role);
    if (key != NULL)
        g_object_unref (key);
    g_object_unref (webaccess);

    return;

bad_req:
    g_strfreev (parts);
    if (repo != NULL)
        seaf_repo_unref (repo);
    g_free (repo_role);
    if (key != NULL)
        g_object_unref (key);
    if (webaccess != NULL)
        g_object_unref (webaccess);

    if (rpc_client)
        ccnet_rpc_client_free (rpc_client);

    seaf_warning ("fetch failed: %s\n", error);
    evbuffer_add_printf(req->buffer_out, "%s\n", error);
    evhtp_send_reply(req, EVHTP_RES_BADREQ);
}

int
access_file_init (evhtp_t *htp)
{
    evhtp_set_regex_cb (htp, "^/files/.*", access_cb, NULL);

    return 0;
}
