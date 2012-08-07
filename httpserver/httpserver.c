/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <getopt.h>

#include <glib.h>

#include <event.h>
#include <evhtp.h>

#include <searpc.h>
#include <ccnet.h>
#include <searpc-client.h>
#include <ccnetrpc-transport.h>
#include <seafile-session.h>
#include <seafile-object.h>
#include <seafile-crypt.h>
#include "seafile.h"

#include "utils.h"

#include "httpserver.h"

/* for debugging */
/*#define DEBUG*/

typedef struct HttpData {
    SearpcClient *rpc_client;
    SearpcClient *threaded_rpc_client;
} HttpData;

static char *config_dir = NULL;
static char *seafile_dir = NULL;
static char *bind_addr = "0.0.0.0";
static uint16_t bind_port = 8082;
static int num_threads = 10;
static char *root_dir = NULL;

CcnetClient *ccnet_client;
SeafileSession *seaf;

static const char *short_opts = "hvfc:d:p:b:t:r:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "foreground", no_argument, NULL, 'f', },
    { "config-file", required_argument, NULL, 'c', },
    { "seafdir", required_argument, NULL, 'd', },
    { "port", required_argument, NULL, 'p', },
    { "bindaddr", required_argument, NULL, 'b', },
    { "threads", required_argument, NULL, 't', },
    { "root", required_argument, NULL, 'r', },
};

static void usage ()
{
    fprintf (stderr, "usage: httpserver [-c config_dir] [-d seafile_dir] -r http_root_dir\n");
}

#define CONTENT_TYPE_FILENAME "content-type.txt"
#define FILE_TYPE_MAP_DEFAULT_LEN 1

struct file_type_map *ftmap;

static int
load_content_type_map(struct file_type_map **ftmap)
{
    FILE *fin;
    int cnt = 0;
    int max = FILE_TYPE_MAP_DEFAULT_LEN;
    char suffix[16], type[16];
    char path[PATH_MAX];

    *ftmap = (struct file_type_map *)malloc(sizeof(struct file_type_map) *
                                            FILE_TYPE_MAP_DEFAULT_LEN);
    if (*ftmap == NULL)
        return -1;

    snprintf(path, PATH_MAX, "%s/%s", root_dir, CONTENT_TYPE_FILENAME);
    fin = fopen(path, "r");
    if (fin == NULL) {
        g_warning ("cann't open content type file\n");
        return -1;
    }
    while (!feof(fin)) {
        fscanf(fin, "%s %s\n", suffix, type);
        (*ftmap)[cnt].suffix = strdup(suffix);
        (*ftmap)[cnt].type = strdup(type);
        cnt++;

        /* realloc ftmap */
        if (cnt >= max) {
            max *= 2;
            *ftmap = realloc(*ftmap, sizeof(struct file_type_map) * max);
            if (*ftmap == NULL)
                return -1;
        }
    }
    (*ftmap)[cnt].suffix = NULL;
    (*ftmap)[cnt].type = NULL;

    fclose(fin);

#ifdef DEBUG
    {
        struct file_type_map *p;
        g_warning ("%d %d\n", cnt, max);
        for (p = *ftmap; p->suffix != NULL; p++) {
            g_warning ("%s %s\n", p->suffix, p->type);
        }
    }
#endif

    return 0;
}

static void
default_cb(evhtp_request_t *req, void *arg)
{
    /* Return empty page. */
    evhtp_send_reply (req, EVHTP_RES_OK);
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
            g_warning ("Failed to open block %s\n", blk_id);
            goto err;
        }

        BlockMetadata *bmd;
        bmd = seaf_block_manager_stat_block_by_handle (seaf->block_mgr,
                                                       data->handle);
        data->remain = bmd->size;
        g_free (bmd);

        if (data->crypt) {
            if (seafile_decrypt_init (&data->ctx, data->crypt) < 0) {
                g_warning ("Failed to init decrypt.\n");
                goto err;
            }
        }
    }
    handle = data->handle;

    n = seaf_block_manager_read_block(seaf->block_mgr, handle, buf, sizeof(buf));
    data->remain -= n;
    if (n < 0) {
        g_warning ("Error when reading from block %s.\n", blk_id);
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
            g_warning ("Failed to alloc memory.\n");
            goto err;
        }

        int ret = seafile_decrypt_update (&data->ctx,
                                          dec_out,
                                          &dec_out_len,
                                          buf,
                                          n);
        if (ret != 0) {
            g_warning ("Decrypt block %s failed.\n", blk_id);
            g_free (dec_out);
            goto err;
        }

        bufferevent_write (bev, dec_out, dec_out_len);

        /* If it's the last piece of a block, call decrypt_final()
         * to decrypt the possible partial block. */
        if (data->remain == 0) {
            ret = seafile_decrypt_final (&data->ctx, dec_out, &dec_out_len);
            if (ret != 0) {
                g_warning ("Decrypt block %s failed.\n", blk_id);
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
                                              "*", 0, 0));


    type = parse_content_type(filename);
    if (type != NULL) {
        if (strstr(type, "text")) {
            content_type = g_strjoin("; ", type, "charset=gbk", NULL);
        } else {
            content_type = g_strdup (type);
        }

        evhtp_headers_add_header(req->headers_out,
                                 evhtp_header_new("Content-Type",
                                                  content_type, 0, 0));
        g_free (content_type);
    }

    snprintf(file_size, sizeof(file_size), "%"G_GINT64_FORMAT"", file->file_size);
    evhtp_headers_add_header (req->headers_out,
                              evhtp_header_new("Content-Length", file_size, 0, 0));

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
                                              0, 0));

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

    CcnetClient *client;
    SearpcClient *threaded_rpc_client, *rpc_client;
    GError *err = NULL;
    char *repo_role = NULL;
    SeafileCryptKey *key = NULL;
    SeafileWebAccess *webaccess = NULL;

    token = req->uri->path->match_start;
    *(token+strlen(token)-1) = '\0';	    /* cut out last '/' in token */
    token += 7;                             /* cut out '/files/' at head */
    
    filename = req->uri->path->file;
    
    client = ccnet_client_new ();
    if ((ccnet_client_load_confdir(client, config_dir)) < 0 ) {
        error = "Read config dir error\n";
        goto bad_req_no_free;
    }

    if (ccnet_client_connect_daemon(client, CCNET_CLIENT_SYNC) < 0) {
        error = "Connect to server failed\n";
        goto bad_req;
    }

    rpc_client = ccnet_create_rpc_client (client, NULL,
                                          "seafserv-rpcserver");
    threaded_rpc_client = ccnet_create_rpc_client (
         client, NULL, "seafserv-threaded-rpcserver");

    webaccess = (SeafileWebAccess *) searpc_client_call__object (
        rpc_client, "seafile_web_query_access_token", SEAFILE_TYPE_WEB_ACCESS,
        NULL, 1, "string", token);
    if (!webaccess) {
        error = "Bad access token";
        goto bad_req;
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

    ccnet_rpc_client_free (rpc_client);
    ccnet_rpc_client_free (threaded_rpc_client);
    g_object_unref (client);
    seaf_repo_unref (repo);
    g_free (repo_role);
    if (key != NULL)
        g_object_unref (key);
    g_object_unref (webaccess);

    return;

bad_req:
    g_free (rpc_client->arg);
    searpc_client_free (rpc_client);
    g_free (threaded_rpc_client->arg);
    searpc_client_free (threaded_rpc_client);
    g_object_unref (client);
    if (repo != NULL)
        seaf_repo_unref (repo);
    g_free (repo_role);
    if (key != NULL)
        g_object_unref (key);
    if (webaccess != NULL)
        g_object_unref (webaccess);

bad_req_no_free:
    g_warning ("fetch failed: %s\n", error);
    evbuffer_add_printf(req->buffer_out, "%s\n", error);
    evhtp_send_reply(req, EVHTP_RES_BADREQ);
}

int
main(int argc, char *argv[])
{
    evbase_t *evbase = NULL;
    evhtp_t *htp = NULL;
    int daemon_mode = 1;
    int c;

    config_dir = DEFAULT_CONFIG_DIR;

    while ((c = getopt_long(argc, argv,
                short_opts, long_opts, NULL)) != EOF) {
        switch (c) {
        case 'h':
            usage();
            exit(0);
        case 'v':
            exit(-1);
            break;
        case 'c':
            config_dir = strdup(optarg);
            break;
        case 'd':
            seafile_dir = strdup(optarg);
            break;
        case 'p':
            bind_port = atoi(optarg);
            break;
        case 'b':
            bind_addr = strdup(optarg);
            break;
        case 't':
            num_threads = atoi(optarg);
            break;
        case 'r':
            root_dir = strdup(optarg);
            break;
        case 'f':
            daemon_mode = 0;
            break;
        default:
            usage();
            exit(-1);
        }
    }

    if (!root_dir) {
        usage();
        exit (-1);
    }

#ifndef WIN32    
    if (daemon_mode)
        daemon(1, 0);
#endif    

    g_type_init();

    ccnet_client = ccnet_client_new();
    if ((ccnet_client_load_confdir(ccnet_client, config_dir)) < 0) {
        g_warning ("Read config dir error\n");
        return -1;
    }

    if (seafile_dir == NULL)
        seafile_dir = g_build_filename (config_dir, "seafile-data", NULL);
    
    seaf = seafile_session_new(seafile_dir, ccnet_client);
    if (!seaf) {
        g_warning ("Failed to create seafile session.\n");
        exit (1);
    }
    seafile_session_init(seaf);

    if (load_content_type_map(&ftmap) < 0) {
        g_warning ("load content type error\n");
        return -1;
    }

    evbase = event_base_new();
    htp = evhtp_new(evbase, NULL);

    evhtp_set_regex_cb (htp, "^/files/.*", access_cb, NULL);
    
    evhtp_set_gencb(htp, default_cb, NULL);

    evhtp_use_threads(htp, NULL, num_threads, NULL);

    if (evhtp_bind_socket(htp, bind_addr, bind_port, 128) < 0) {
        g_warning ("Could not bind socket: %s\n", strerror(errno));
        exit(-1);
    }

    event_base_loop(evbase, 0);

    return 0;
}
