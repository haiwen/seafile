#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_HTTP
#include "log.h"

#include <event.h>
#include <evhtp.h>

#include <ccnet.h>

#include "seafile-object.h"
#include "seafile-crypt.h"
#include "seafile.h"

#include "utils.h"

#include "seafile-session.h"
#include "httpserver.h"
#include "access-file.h"

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
    EVP_CIPHER_CTX ctx;
    BlockHandle *handle;
    size_t remain;
    int idx;

    bufferevent_data_cb saved_read_cb;
    bufferevent_data_cb saved_write_cb;
    bufferevent_event_cb saved_event_cb;
    void *saved_cb_arg;
} SendfileData;

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
    seafile_unref (data->file);
    g_free (data->crypt);
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
        data->remain = bmd->size;
        g_free (bmd);

        if (data->crypt) {
            if (seafile_decrypt_init (&data->ctx, data->crypt) < 0) {
                seaf_warning ("Failed to init decrypt.\n");
                goto err;
            }
        }
    }
    handle = data->handle;

    n = seaf_block_manager_read_block(seaf->block_mgr, handle, buf, sizeof(buf));
    data->remain -= n;
    if (n < 0) {
        seaf_warning ("Error when reading from block %s.\n", blk_id);
        seaf_block_manager_close_block(seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free(seaf->block_mgr, handle);
        goto err;
    } else if (n == 0) {
        seaf_block_manager_close_block (seaf->block_mgr, handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, handle);

        /* We've read up the data of this block, finish or try next block. */
        if (data->idx == data->file->n_blocks - 1) {
            /* Recover evhtp's callbacks */
            struct bufferevent *bev = evhtp_request_get_bev (data->req);
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
        data->handle = NULL;
        goto next;
    }

    /* OK, we've got some data to send. */
    if (data->crypt != NULL) {
        char *dec_out;
        int dec_out_len = -1;

        dec_out = g_new (char, n + 16);
        if (!dec_out) {
            seaf_warning ("Failed to alloc memory.\n");
            goto err;
        }

        int ret = seafile_decrypt_update (&data->ctx,
                                          dec_out,
                                          &dec_out_len,
                                          buf,
                                          n);
        if (ret != 0) {
            seaf_warning ("Decrypt block %s failed.\n", blk_id);
            g_free (dec_out);
            goto err;
        }

        bufferevent_write (bev, dec_out, dec_out_len);

        /* If it's the last piece of a block, call decrypt_final()
         * to decrypt the possible partial block. */
        if (data->remain == 0) {
            ret = seafile_decrypt_final (&data->ctx, dec_out, &dec_out_len);
            if (ret != 0) {
                seaf_warning ("Decrypt block %s failed.\n", blk_id);
                g_free (dec_out);
                goto err;
            }
            bufferevent_write (bev, dec_out, dec_out_len);
        }

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
my_event_cb (struct bufferevent *bev, short events, void *ctx)
{
    SendfileData *data = ctx;

    data->saved_event_cb (bev, events, data->saved_cb_arg);

    /* Free aux data. */
    free_sendfile_data (data);
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
    char cont_filename[PATH_MAX];
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
            snprintf(cont_filename, PATH_MAX,
                     "attachment;filename*=\"utf8\' \'%s\"", filename);
        } else {
            snprintf(cont_filename, PATH_MAX,
                     "attachment;filename=\"%s\"", filename);
        }
    } else {
        if (test_firefox (req)) {
            snprintf(cont_filename, PATH_MAX,
                     "inline;filename*=\"utf8\' \'%s\"", filename);
        } else {
            snprintf(cont_filename, PATH_MAX,
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

    /* Kick start data transfer by sending out http headers. */
    evhtp_send_reply_start(req, EVHTP_RES_OK);

    return 0;
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
        strftime (http_date, sizeof(http_date), "%a, %d %b %Y %T GMT",
                  gmtime(&now));
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

    if (do_file(req, repo, id, filename, operation, key) < 0) {
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
