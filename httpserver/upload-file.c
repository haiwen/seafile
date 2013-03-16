#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_HTTP
#include "log.h"

#include <getopt.h>
#include <fcntl.h>

#include <event.h>
#include <evhtp.h>

#include <json-glib/json-glib.h>

#include <pthread.h>

#include <ccnet.h>

#include "seafile-object.h"
#include "seafile.h"

#include "utils.h"

#include "seafile-session.h"
#include "httpserver.h"
#include "upload-file.h"


#define SEAF_HTTP_RES_BADFILENAME 440
#define SEAF_HTTP_RES_EXISTS 441
#define SEAF_HTTP_RES_NOT_EXISTS 441
#define SEAF_HTTP_RES_TOOLARGE 442
#define SEAF_HTTP_RES_NOQUOTA 443

enum RecvState {
    RECV_INIT,
    RECV_HEADERS,
    RECV_CONTENT,
    RECV_ERROR,
};

enum UploadError {
    ERROR_FILENAME,
    ERROR_EXISTS,
    ERROR_NOT_EXIST,
    ERROR_SIZE,
    ERROR_QUOTA,
    ERROR_RECV,
    ERROR_INTERNAL,
};

typedef struct Progress {
    gint64 uploaded;
    gint64 size;
} Progress;

typedef struct RecvFSM {
    int state;

    char *repo_id;
    char *user;
    char *boundary;        /* boundary of multipart form-data. */
    char *input_name;      /* input name of the current form field. */
    evbuf_t *line;          /* buffer for a line */

    GHashTable *form_kvs;       /* key/value of form fields */
    GList *filenames;           /* uploaded file names */
    GList *files;               /* paths for completely uploaded tmp files. */

    gboolean recved_crlf; /* Did we recv a CRLF when write out the last line? */
    char *file_name;
    char *tmp_file;
    int fd;
    GList *tmp_files;           /* tmp files for each uploading file */

    /* For upload progress. */
    char *progress_id;
    Progress *progress;
} RecvFSM;

#define MAX_CONTENT_LINE 10240

static GHashTable *upload_progress;
static pthread_mutex_t pg_lock;

#ifdef WIN32
int mkstemp(char *template)
{
    DWORD pathSize;
    char pathBuffer[1000];
    char tempFilename[MAX_PATH];
    UINT uniqueNum;

    pathSize = GetTempPath( 1000, pathBuffer);

    if (pathSize < 1000)

        pathBuffer[pathSize] = 0;
    else
        pathBuffer[0] = 0;
    uniqueNum = GetTempFileName(pathBuffer, "tmp", FILE_FLAG_DELETE_ON_CLOSE , tempFilename);

    strcpy(template, tempFilename);
    return open(tempFilename, O_RDWR|O_BINARY);
}
#endif

/* IE8 will set filename to the full path of the uploaded file.
 * So we need to strip out the basename from it.
 */
static char *
get_basename (const char *path)
{
    int i = strlen(path) - 1;

    while (i >= 0) {
        if (path[i] == '/' || path[i] == '\\')
            break;
        --i;
    }

    if (i < 0)
        return g_strdup(path);

    return g_strdup(&path[i+1]);
}

static void
redirect_to_upload_error (evhtp_request_t *req,
                          const char *repo_id,
                          const char *parent_dir,
                          const char *filename,
                          int error_code)
{
    char *seahub_url, *escaped_path, *escaped_fn = NULL;
    char url[1024];

    seahub_url = seaf->session->base.service_url;
    escaped_path = g_uri_escape_string (parent_dir, NULL, FALSE);
    if (filename) {
        escaped_fn = g_uri_escape_string (filename, NULL, FALSE);
        snprintf(url, 1024, "%s/repo/upload_error/%s?p=%s&fn=%s&err=%d",
                 seahub_url, repo_id, escaped_path, escaped_fn, error_code);
    } else {
        snprintf(url, 1024, "%s/repo/upload_error/%s?p=%s&err=%d",
                 seahub_url, repo_id, escaped_path, error_code);
    }
    g_free (escaped_path);
    g_free (escaped_fn);

    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Location",
                                              url, 1, 1));
    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Length",
                                              "0", 1, 1));
    evhtp_send_reply(req, EVHTP_RES_SEEOTHER);
}

static void
redirect_to_update_error (evhtp_request_t *req,
                          const char *repo_id,
                          const char *target_file,
                          int error_code)
{
    char *seahub_url, *escaped_path;
    char url[1024];

    seahub_url = seaf->session->base.service_url;
    escaped_path = g_uri_escape_string (target_file, NULL, FALSE);
    snprintf(url, 1024, "%s/repo/update_error/%s?p=%s&err=%d",
             seahub_url, repo_id, escaped_path, error_code);
    g_free (escaped_path);

    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Location",
                                              url, 1, 1));
    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Length",
                                              "0", 1, 1));
    evhtp_send_reply(req, EVHTP_RES_SEEOTHER);
}

static void
redirect_to_success_page (evhtp_request_t *req,
                          const char *repo_id,
                          const char *parent_dir)
{
    char *seahub_url, *escaped_path;
    char url[1024];

    seahub_url = seaf->session->base.service_url;
    escaped_path = g_uri_escape_string (parent_dir, NULL, FALSE);
    snprintf(url, 1024, "%s/repo/%s?p=%s", seahub_url, repo_id, escaped_path);
    g_free (escaped_path);

    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Location",
                                              url, 1, 1));
    /* Firefox expects Content-Length header. */
    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Length",
                                              "0", 1, 1));
    evhtp_send_reply(req, EVHTP_RES_SEEOTHER);
}

static gboolean
check_tmp_file_list (GList *tmp_files, int *error_code)
{
    GList *ptr;
    char *tmp_file;
    struct stat st;
    gint64 total_size = 0;

    for (ptr = tmp_files; ptr; ptr = ptr->next) {
        tmp_file = ptr->data;

        if (stat (tmp_file, &st) < 0) {
            seaf_warning ("[upload] Failed to stat temp file %s.\n", tmp_file);
            *error_code = ERROR_RECV;
            return FALSE;
        }

        total_size += (gint64)st.st_size;
    }

    if (total_size > seaf->max_upload_size) {
        seaf_warning ("[upload] File size is too large.\n");
        *error_code = ERROR_SIZE;
        return FALSE;
    }

    return TRUE;
}

static char *
file_list_to_json (GList *files)
{
    JsonNode *root;
    JsonArray *array;
    GList *ptr;
    char *file;
    JsonGenerator *gen;
    char *json_data;
    gsize len;

    root = json_node_new (JSON_NODE_ARRAY);
    array = json_array_new ();

    for (ptr = files; ptr; ptr = ptr->next) {
        file = ptr->data;
        json_array_add_string_element (array, file);
    }
    json_node_set_array (root, array);

    gen = json_generator_new ();
    json_generator_set_root (gen, root);
    json_data = json_generator_to_data (gen, &len);
    json_node_free (root);
    g_object_unref (gen);

    return json_data;
}

static void
upload_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    SearpcClient *rpc_client = NULL;
    char *parent_dir;
    GError *error = NULL;
    int error_code = ERROR_INTERNAL;
    char *err_file = NULL;
    char *filenames_json, *tmp_files_json;

    /* After upload_headers_cb() returns an error, libevhtp may still
     * receive data from the web browser and call into this cb.
     * In this case fsm will be NULL.
     */
    if (!fsm || fsm->state == RECV_ERROR)
        return;

    if (!fsm->files) {
        seaf_warning ("[upload] No file uploaded.\n");
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    parent_dir = g_hash_table_lookup (fsm->form_kvs, "parent_dir");
    if (!parent_dir) {
        seaf_warning ("[upload] No parent dir given.\n");
        evbuffer_add_printf(req->buffer_out, "Invalid URL.\n");
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    if (!check_tmp_file_list (fsm->files, &error_code))
        goto error;

    rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                 NULL,
                                                 "seafserv-threaded-rpcserver");

    if (seafile_check_quota (rpc_client, fsm->repo_id, NULL) < 0) {
        seaf_warning ("[upload] Out of quota.\n");
        error_code = ERROR_QUOTA;
        goto error;
    }

    filenames_json = file_list_to_json (fsm->filenames);
    tmp_files_json = file_list_to_json (fsm->files);

    seafile_post_multi_files (rpc_client,
                              fsm->repo_id,
                              parent_dir,
                              filenames_json,
                              tmp_files_json,
                              fsm->user,
                              &error);
    g_free (filenames_json);
    g_free (tmp_files_json);
    if (error) {
        if (error->code == POST_FILE_ERR_FILENAME) {
            error_code = ERROR_FILENAME;
            err_file = g_strdup(error->message);
        }
        g_clear_error (&error);
        goto error;
    }

    ccnet_rpc_client_free (rpc_client);

    /* Redirect to repo dir page after upload finishes. */
    redirect_to_success_page (req, fsm->repo_id, parent_dir);
    return;

error:
    if (rpc_client)
        ccnet_rpc_client_free (rpc_client);

    redirect_to_upload_error (req, fsm->repo_id, parent_dir,
                              err_file, error_code);
    g_free (err_file);
}

static void
upload_api_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    SearpcClient *rpc_client = NULL;
    char *parent_dir;
    GError *error = NULL;
    int error_code = ERROR_INTERNAL;
    char *filenames_json, *tmp_files_json;

    /* After upload_headers_cb() returns an error, libevhtp may still
     * receive data from the web browser and call into this cb.
     * In this case fsm will be NULL.
     */
    if (!fsm || fsm->state == RECV_ERROR)
        return;

    if (!fsm->files) {
        seaf_warning ("[upload] No file uploaded.\n");
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    parent_dir = g_hash_table_lookup (fsm->form_kvs, "parent_dir");
    if (!parent_dir) {
        seaf_warning ("[upload] No parent dir given.\n");
        evbuffer_add_printf(req->buffer_out, "Invalid URL.\n");
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    if (!check_tmp_file_list (fsm->files, &error_code))
        goto error;

    rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                 NULL,
                                                 "seafserv-threaded-rpcserver");

    if (seafile_check_quota (rpc_client, fsm->repo_id, NULL) < 0) {
        seaf_warning ("[upload] Out of quota.\n");
        error_code = ERROR_QUOTA;
        goto error;
    }

    filenames_json = file_list_to_json (fsm->filenames);
    tmp_files_json = file_list_to_json (fsm->files);

    seafile_post_multi_files (rpc_client,
                              fsm->repo_id,
                              parent_dir,
                              filenames_json,
                              tmp_files_json,
                              fsm->user,
                              &error);
    g_free (filenames_json);
    g_free (tmp_files_json);
    if (error) {
        if (error->code == POST_FILE_ERR_FILENAME) {
            error_code = ERROR_FILENAME;
            seaf_warning ("[upload] Bad filename.\n");
        }
        g_clear_error (&error);
        goto error;
    }

    ccnet_rpc_client_free (rpc_client);

    evhtp_send_reply (req, EVHTP_RES_OK);
    return;

error:
    if (rpc_client)
        ccnet_rpc_client_free (rpc_client);

    switch (error_code) {
    case ERROR_FILENAME:
        evbuffer_add_printf(req->buffer_out, "Invalid filename.\n");
        evhtp_send_reply (req, SEAF_HTTP_RES_BADFILENAME);
        break;
    case ERROR_EXISTS:
        evbuffer_add_printf(req->buffer_out, "File already exists.\n");
        evhtp_send_reply (req, SEAF_HTTP_RES_EXISTS);
        break;
    case ERROR_SIZE:
        evbuffer_add_printf(req->buffer_out, "File size is too large.\n");
        evhtp_send_reply (req, SEAF_HTTP_RES_TOOLARGE);
        break;
    case ERROR_QUOTA:
        evbuffer_add_printf(req->buffer_out, "Out of quota.\n");
        evhtp_send_reply (req, SEAF_HTTP_RES_NOQUOTA);
        break;
    case ERROR_RECV:
    case ERROR_INTERNAL:
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        break;
    }
}

static void
update_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    SearpcClient *rpc_client = NULL;
    char *target_file, *parent_dir = NULL, *filename = NULL;
    const char *head_id = NULL;
    GError *error = NULL;
    int error_code = ERROR_INTERNAL;

    if (!fsm || fsm->state == RECV_ERROR)
        return;

    if (!fsm->files) {
        seaf_warning ("[update] No file uploaded.\n");
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    target_file = g_hash_table_lookup (fsm->form_kvs, "target_file");
    if (!target_file) {
        seaf_warning ("[Update] No target file given.\n");
        evbuffer_add_printf(req->buffer_out, "Invalid URL.\n");
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    parent_dir = g_path_get_dirname (target_file);
    filename = g_path_get_basename (target_file);

    if (!check_tmp_file_list (fsm->files, &error_code))
        goto error;

    head_id = evhtp_kv_find (req->uri->query, "head");

    rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                 NULL,
                                                 "seafserv-threaded-rpcserver");

    if (seafile_check_quota (rpc_client, fsm->repo_id, NULL) < 0) {
        seaf_warning ("[update] Out of quota.\n");
        error_code = ERROR_QUOTA;
        goto error;
    }

    seafile_put_file (rpc_client,
                      fsm->repo_id,
                      (char *)(fsm->files->data),
                      parent_dir,
                      filename,
                      fsm->user,
                      head_id,
                      &error);
    if (error) {
        if (g_strcmp0 (error->message, "file does not exist") == 0) {
            error_code = ERROR_NOT_EXIST;
        }
        if (error->message)
            printf ("%s\n", error->message);
        g_clear_error (&error);
        goto error;
    }

    ccnet_rpc_client_free (rpc_client);

    /* Redirect to repo dir page after upload finishes. */
    redirect_to_success_page (req, fsm->repo_id, parent_dir);
    g_free (parent_dir);
    g_free (filename);
    return;

error:
    if (rpc_client)
        ccnet_rpc_client_free (rpc_client);

    redirect_to_update_error (req, fsm->repo_id, target_file, error_code);
    g_free (parent_dir);
    g_free (filename);
}

static void
update_api_cb(evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    SearpcClient *rpc_client = NULL;
    char *target_file, *parent_dir = NULL, *filename = NULL;
    const char *head_id = NULL;
    GError *error = NULL;
    int error_code = ERROR_INTERNAL;
    char *new_file_id = NULL;

    if (!fsm || fsm->state == RECV_ERROR)
        return;

    if (!fsm->files) {
        seaf_warning ("[update] No file uploaded.\n");
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    target_file = g_hash_table_lookup (fsm->form_kvs, "target_file");
    if (!target_file) {
        seaf_warning ("[Update] No target file given.\n");
        evbuffer_add_printf(req->buffer_out, "Invalid URL.\n");
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    parent_dir = g_path_get_dirname (target_file);
    filename = g_path_get_basename (target_file);

    if (!check_tmp_file_list (fsm->files, &error_code))
        goto error;

    head_id = evhtp_kv_find (req->uri->query, "head");

    rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                 NULL,
                                                 "seafserv-threaded-rpcserver");

    if (seafile_check_quota (rpc_client, fsm->repo_id, NULL) < 0) {
        seaf_warning ("[update] Out of quota.\n");
        error_code = ERROR_QUOTA;
        goto error;
    }

    new_file_id = seafile_put_file (rpc_client,
                                    fsm->repo_id,
                                    (char *)(fsm->files->data),
                                    parent_dir,
                                    filename,
                                    fsm->user,
                                    head_id,
                                    &error);
    g_free (parent_dir);
    g_free (filename);
    
    if (error) {
        if (g_strcmp0 (error->message, "file does not exist") == 0) {
            error_code = ERROR_NOT_EXIST;
        }
        if (error->message)
            printf ("%s\n", error->message);
        g_clear_error (&error);
        goto error;
    }

    ccnet_rpc_client_free (rpc_client);
    /* Send back the new file id, so that the mobile client can update local cache */
    evbuffer_add(req->buffer_out, new_file_id, strlen(new_file_id));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (new_file_id);
    return;

error:
    if (rpc_client)
        ccnet_rpc_client_free (rpc_client);

    switch (error_code) {
    case ERROR_FILENAME:
        evbuffer_add_printf(req->buffer_out, "Invalid filename.\n");
        evhtp_send_reply (req, SEAF_HTTP_RES_BADFILENAME);
        break;
    case ERROR_EXISTS:
        evbuffer_add_printf(req->buffer_out, "File already exists.\n");
        evhtp_send_reply (req, SEAF_HTTP_RES_EXISTS);
        break;
    case ERROR_SIZE:
        evbuffer_add_printf(req->buffer_out, "File size is too large.\n");
        evhtp_send_reply (req, SEAF_HTTP_RES_TOOLARGE);
        break;
    case ERROR_QUOTA:
        evbuffer_add_printf(req->buffer_out, "Out of quota.\n");
        evhtp_send_reply (req, SEAF_HTTP_RES_NOQUOTA);
        break;
    case ERROR_NOT_EXIST:
        evbuffer_add_printf(req->buffer_out, "File does not exist.\n");
        evhtp_send_reply (req, SEAF_HTTP_RES_NOT_EXISTS);
        break;
    case ERROR_RECV:
    case ERROR_INTERNAL:
    default:
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        break;
    }
}

static evhtp_res
upload_finish_cb (evhtp_request_t *req, void *arg)
{
    RecvFSM *fsm = arg;
    GList *ptr;

    if (!fsm)
        return EVHTP_RES_OK;

    /* Clean up FSM struct no matter upload succeed or not. */

    g_free (fsm->repo_id);
    g_free (fsm->user);
    g_free (fsm->boundary);
    g_free (fsm->input_name);

    g_hash_table_destroy (fsm->form_kvs);

    g_free (fsm->file_name);
    if (fsm->tmp_file) {
        close (fsm->fd);
    }
    g_free (fsm->tmp_file);

    for (ptr = fsm->tmp_files; ptr; ptr = ptr->next)
        g_unlink ((char *)(ptr->data));
    string_list_free (fsm->tmp_files);
    string_list_free (fsm->filenames);
    string_list_free (fsm->files);

    evbuffer_free (fsm->line);

    if (fsm->progress_id) {
        pthread_mutex_lock (&pg_lock);
        g_hash_table_remove (upload_progress, fsm->progress_id);
        pthread_mutex_unlock (&pg_lock);

        /* fsm->progress has been free'd by g_hash_table_remove(). */
        g_free (fsm->progress_id);
    }

    g_free (fsm);

    return EVHTP_RES_OK;
}

static char *
get_mime_header_param_value (const char *param)
{
    char *first_quote, *last_quote;
    char *value;

    first_quote = strchr (param, '\"');
    last_quote = strrchr (param, '\"');
    if (!first_quote || !last_quote || first_quote == last_quote) {
        seaf_warning ("[upload] Invalid mime param %s.\n", param);
        return NULL;
    }

    value = g_strndup (first_quote + 1, last_quote - first_quote - 1);
    return value;
}

static int
parse_mime_header (char *header, RecvFSM *fsm)
{
    char *colon;
    char **params, **p;

    colon = strchr (header, ':');
    if (!colon) {
        seaf_warning ("[upload] bad mime header format.\n");
        return -1;
    }

    *colon = 0;
    if (strcmp (header, "Content-Disposition") == 0) {
        params = g_strsplit (colon + 1, ";", 0);
        for (p = params; *p != NULL; ++p)
            *p = g_strstrip (*p);

        if (!params || g_strv_length (params) < 2) {
            seaf_warning ("[upload] Too little params for mime header.\n");
            g_strfreev (params);
            return -1;
        }
        if (strcasecmp (params[0], "form-data") != 0) {
            seaf_warning ("[upload] Invalid Content-Disposition\n");
            g_strfreev (params);
            return -1;
        }

        for (p = params; *p != NULL; ++p) {
            if (strncasecmp (*p, "name", strlen("name")) == 0) {
                fsm->input_name = get_mime_header_param_value (*p);
                break;
            }
        }
        if (!fsm->input_name) {
            seaf_warning ("[upload] No input-name given.\n");
            g_strfreev (params);
            return -1;
        }

        if (strcmp (fsm->input_name, "file") == 0) {
            for (p = params; *p != NULL; ++p) {
                if (strncasecmp (*p, "filename", strlen("filename")) == 0) {
                    fsm->file_name = get_mime_header_param_value (*p);
                    break;
                }
            }
            if (!fsm->file_name) {
                seaf_warning ("[upload] No filename given.\n");
                g_strfreev (params);
                return -1;
            }
        }
        g_strfreev (params);
    }

    return 0;
}

static int
open_temp_file (RecvFSM *fsm)
{
    GString *temp_file = g_string_new (NULL);

    g_string_printf (temp_file, "%s/%sXXXXXX",
                     seaf->http_temp_dir, get_basename(fsm->file_name));

    fsm->fd = mkstemp (temp_file->str);
    if (fsm->fd < 0) {
        g_string_free (temp_file, TRUE);
        return -1;
    }

    fsm->tmp_file = g_string_free (temp_file, FALSE);
    /* For clean up later. */
    fsm->tmp_files = g_list_prepend (fsm->tmp_files, g_strdup(fsm->tmp_file));

    return 0;
}

static evhtp_res
recv_form_field (RecvFSM *fsm, gboolean *no_line)
{
    char *line;
    size_t len;

    *no_line = FALSE;

    line = evbuffer_readln (fsm->line, &len, EVBUFFER_EOL_CRLF_STRICT);
    if (line != NULL) {
        if (strstr (line, fsm->boundary) != NULL) {
            seaf_debug ("[upload] form field ends.\n");

            g_free (fsm->input_name);
            fsm->input_name = NULL;
            fsm->state = RECV_HEADERS;
        } else {
            seaf_debug ("[upload] form field is %s.\n", line);

            g_hash_table_insert (fsm->form_kvs,
                                 g_strdup(fsm->input_name),
                                 g_strdup(line));
        }
        free (line);
    } else {
        *no_line = TRUE;
    }

    return EVHTP_RES_OK;
}

static void
add_uploaded_file (RecvFSM *fsm)
{
    fsm->filenames = g_list_prepend (fsm->filenames,
                                     get_basename(fsm->file_name));
    fsm->files = g_list_prepend (fsm->files, g_strdup(fsm->tmp_file));

    g_free (fsm->file_name);
    g_free (fsm->tmp_file);
    close (fsm->fd);
    fsm->file_name = NULL;
    fsm->tmp_file = NULL;
    fsm->recved_crlf = FALSE;
}

static evhtp_res
recv_file_data (RecvFSM *fsm, gboolean *no_line)
{
    char *line;
    size_t len;

    *no_line = FALSE;

    line = evbuffer_readln (fsm->line, &len, EVBUFFER_EOL_CRLF_STRICT);
    if (!line) {
        /* If we haven't read an entire line, but the line
         * buffer gets too long, flush the content to file.
         * It should be safe to assume the boundary line is
         * no longer than 10240 bytes.
         */
        if (evbuffer_get_length (fsm->line) >= MAX_CONTENT_LINE) {
            seaf_debug ("[upload] recv file data %d bytes.\n",
                     evbuffer_get_length(fsm->line));
            if (fsm->recved_crlf) {
                if (writen (fsm->fd, "\r\n", 2) < 0) {
                    seaf_warning ("[upload] Failed to write temp file: %s.\n",
                               strerror(errno));
                    return EVHTP_RES_SERVERR;
                }
            }
            if (evbuffer_write (fsm->line, fsm->fd) < 0) {
                seaf_warning ("[upload] Failed to write temp file: %s.\n",
                           strerror(errno));
                return EVHTP_RES_SERVERR;
            }
            fsm->recved_crlf = FALSE;
        }
        *no_line = TRUE;
    } else if (strstr (line, fsm->boundary) != NULL) {
        seaf_debug ("[upload] file data ends.\n");

        add_uploaded_file (fsm);

        g_free (fsm->input_name);
        fsm->input_name = NULL;
        fsm->state = RECV_HEADERS;
        free (line);
    } else {
        seaf_debug ("[upload] recv file data %d bytes.\n", len + 2);
        if (fsm->recved_crlf) {
            if (writen (fsm->fd, "\r\n", 2) < 0) {
                seaf_warning ("[upload] Failed to write temp file: %s.\n",
                           strerror(errno));
                return EVHTP_RES_SERVERR;
            }
        }
        if (writen (fsm->fd, line, len) < 0) {
            seaf_warning ("[upload] Failed to write temp file: %s.\n",
                       strerror(errno));
            free (line);
            return EVHTP_RES_SERVERR;
        }
        free (line);
        fsm->recved_crlf = TRUE;
    }

    return EVHTP_RES_OK;
}

/*
   Example multipart form-data request content format:

   --AaB03x
   Content-Disposition: form-data; name="submit-name"

   Larry
   --AaB03x
   Content-Disposition: form-data; name="file"; filename="file1.txt"
   Content-Type: text/plain

   ... contents of file1.txt ...
   --AaB03x--
*/
static evhtp_res
upload_read_cb (evhtp_request_t *req, evbuf_t *buf, void *arg)
{
    RecvFSM *fsm = arg;
    char *line;
    size_t len;
    gboolean no_line = FALSE;
    int res = EVHTP_RES_OK;

    if (fsm->state == RECV_ERROR)
        return EVHTP_RES_OK;

    /* Update upload progress. */
    if (fsm->progress) {
        fsm->progress->uploaded += (gint64)evbuffer_get_length(buf);

        seaf_debug ("progress: %lld/%lld\n",
                    fsm->progress->uploaded, fsm->progress->size);
    }

    evbuffer_add_buffer (fsm->line, buf);
    /* Drain the buffer so that evhtp don't copy it to another buffer
     * after this callback returns. 
     */
    evbuffer_drain (buf, evbuffer_get_length (buf));

    while (!no_line) {
        switch (fsm->state) {
        case RECV_INIT:
            line = evbuffer_readln (fsm->line, &len, EVBUFFER_EOL_CRLF_STRICT);
            if (line != NULL) {
                seaf_debug ("[upload] boundary line: %s.\n", line);
                if (!strstr (line, fsm->boundary)) {
                    seaf_warning ("[upload] no boundary found in the first line.\n");
                    free (line);
                    res = EVHTP_RES_BADREQ;
                    goto out;
                } else {
                    fsm->state = RECV_HEADERS;
                    free (line);
                }
            } else {
                no_line = TRUE;
            }
            break;
        case RECV_HEADERS:
            line = evbuffer_readln (fsm->line, &len, EVBUFFER_EOL_CRLF_STRICT);
            if (line != NULL) {
                seaf_debug ("[upload] mime header line: %s.\n", line);
                if (len == 0) {
                    /* Read an blank line, headers end. */
                    free (line);
                    if (g_strcmp0 (fsm->input_name, "file") == 0) {
                        if (open_temp_file (fsm) < 0) {
                            seaf_warning ("[upload] Failed open temp file.\n");
                            res = EVHTP_RES_SERVERR;
                            goto out;
                        }
                    }
                    seaf_debug ("[upload] Start to recv %s.\n", fsm->input_name);
                    fsm->state = RECV_CONTENT;
                } else if (parse_mime_header (line, fsm) < 0) {
                    free (line);
                    res = EVHTP_RES_BADREQ;
                    goto out;
                } else {
                    free (line);
                }
            } else {
                no_line = TRUE;
            }
            break;
        case RECV_CONTENT:
            if (g_strcmp0 (fsm->input_name, "file") == 0)
                res = recv_file_data (fsm, &no_line);
            else
                res = recv_form_field (fsm, &no_line);

            if (res != EVHTP_RES_OK)
                goto out;

            break;
        }
    }

out:
    if (res != EVHTP_RES_OK) {
        /* Don't receive any data before the connection is closed. */
        evhtp_request_pause (req);

        /* Set keepalive to 0. This will cause evhtp to close the
         * connection after sending the reply.
         */
        req->keepalive = 0;

        fsm->state = RECV_ERROR;
    }

    if (res == EVHTP_RES_BADREQ) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
    } else if (res == EVHTP_RES_SERVERR) {
        evbuffer_add_printf (req->buffer_out, "Internal server error\n");
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    }
    return EVHTP_RES_OK;
}

static char *
get_http_header_param_value (const char *param)
{
    char *equal;
    char *value;

    equal = strchr (param, '=');
    if (!equal) {
        seaf_warning ("[upload] Invalid http header param %s.\n", param);
        return NULL;
    }

    value = g_strdup (equal + 1);
    return value;
}

static char *
get_boundary (evhtp_headers_t *hdr)
{
    const char *content_type;
    char **params, **p;
    char *boundary = NULL;

    content_type = evhtp_kv_find (hdr, "Content-Type");
    if (!content_type) {
        seaf_warning ("[upload] Missing Content-Type header\n");
        return boundary;
    }

    params = g_strsplit (content_type, ";", 0);
    for (p = params; *p != NULL; ++p)
        *p = g_strstrip (*p);

    if (!params || g_strv_length (params) < 2) {
        seaf_warning ("[upload] Too little params Content-Type header\n");
        g_strfreev (params);
        return boundary;
    }
    if (strcasecmp (params[0], "multipart/form-data") != 0) {
        seaf_warning ("[upload] Invalid Content-Type\n");
        g_strfreev (params);
        return boundary;
    }

    for (p = params; *p != NULL; ++p) {
        if (strncasecmp (*p, "boundary", strlen("boundary")) == 0) {
            boundary = get_http_header_param_value (*p);
            break;
        }
    }
    g_strfreev (params);
    if (!boundary) {
        seaf_warning ("[upload] boundary not given\n");
    }

    return boundary;
}

static int
check_access_token (SearpcClient *rpc,
                    const char *token,
                    char **repo_id,
                    char **user)
{
    SeafileWebAccess *webaccess;

    webaccess = (SeafileWebAccess *)
        seafile_web_query_access_token (rpc, token, NULL);
    if (!webaccess)
        return -1;

    *repo_id = g_strdup (seafile_web_access_get_repo_id (webaccess));
    *user = g_strdup (seafile_web_access_get_username (webaccess));

    g_object_unref (webaccess);

    return 0;
}

static int
get_progress_info (evhtp_request_t *req,
                   evhtp_headers_t *hdr,
                   gint64 *content_len,
                   char **progress_id)
{
    const char *content_len_str;
    const char *uuid;

    uuid = evhtp_kv_find (req->uri->query, "X-Progress-ID");
    /* If progress id is not given, we don't need content-length either. */
    if (!uuid)
        return 0;
    *progress_id = g_strdup(uuid);

    content_len_str = evhtp_kv_find (hdr, "Content-Length");
    if (!content_len_str) {
        seaf_warning ("[upload] Content-Length not found.\n");
        return -1;
    }
    *content_len = strtoll (content_len_str, NULL, 10);

    return 0;
}

static evhtp_res
upload_headers_cb (evhtp_request_t *req, evhtp_headers_t *hdr, void *arg)
{
    SearpcClient *rpc_client = NULL;
    char *token, *repo_id = NULL, *user = NULL;
    char *boundary = NULL;
    gint64 content_len;
    char *progress_id = NULL;
    char *err_msg = NULL;
    RecvFSM *fsm = NULL;
    Progress *progress = NULL;

    /* URL format: http://host:port/[upload|update]/<token>?X-Progress-ID=<uuid> */
    token = req->uri->path->file;
    if (!token) {
        seaf_warning ("[upload] No token in url.\n");
        err_msg = "Invalid URL";
        goto err;
    }

    rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                 NULL,
                                                 "seafserv-rpcserver");

    if (check_access_token (rpc_client, token, &repo_id, &user) < 0) {
        seaf_warning ("[upload] Invalid token.\n");
        err_msg = "Access denied";
        goto err;
    }

    boundary = get_boundary (hdr);
    if (!boundary) {
        goto err;
    }

    if (get_progress_info (req, hdr, &content_len, &progress_id) < 0)
        goto err;

    if (progress_id != NULL) {
        pthread_mutex_lock (&pg_lock);
        if (g_hash_table_lookup (upload_progress, progress_id)) {
            pthread_mutex_unlock (&pg_lock);
            err_msg = "Duplicate progress id.\n";
            goto err;
        }
        pthread_mutex_unlock (&pg_lock);
    }

    fsm = g_new0 (RecvFSM, 1);
    fsm->boundary = boundary;
    fsm->repo_id = repo_id;
    fsm->user = user;
    fsm->line = evbuffer_new ();
    fsm->form_kvs = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           g_free, g_free);

    if (progress_id != NULL) {
        progress = g_new0 (Progress, 1);
        progress->size = content_len;
        fsm->progress_id = progress_id;
        fsm->progress = progress;

        pthread_mutex_lock (&pg_lock);
        g_hash_table_insert (upload_progress, g_strdup(progress_id), progress);
        pthread_mutex_unlock (&pg_lock);
    }

    /* Set up per-request hooks, so that we can read file data piece by piece. */
    evhtp_set_hook (&req->hooks, evhtp_hook_on_read, upload_read_cb, fsm);
    evhtp_set_hook (&req->hooks, evhtp_hook_on_request_fini, upload_finish_cb, fsm);
    /* Set arg for upload_cb or update_cb. */
    req->cbarg = fsm;

    ccnet_rpc_client_free (rpc_client);

    return EVHTP_RES_OK;

err:
    /* Don't receive any data before the connection is closed. */
    evhtp_request_pause (req);

    /* Set keepalive to 0. This will cause evhtp to close the
     * connection after sending the reply.
     */
    req->keepalive = 0;
    if (err_msg)
        evbuffer_add_printf (req->buffer_out, "%s\n", err_msg);
    evhtp_send_reply (req, EVHTP_RES_BADREQ);

    if (rpc_client)
        ccnet_rpc_client_free (rpc_client);

    g_free (repo_id);
    g_free (user);
    g_free (boundary);
    g_free (progress_id);
    return EVHTP_RES_OK;
}

static void
upload_progress_cb(evhtp_request_t *req, void *arg)
{
    const char *progress_id;
    const char *callback;
    Progress *progress;
    GString *buf;

    progress_id = evhtp_kv_find (req->uri->query, "X-Progress-ID");
    if (!progress_id) {
        seaf_warning ("[get pg] Progress id not found in url.\n");
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    callback = evhtp_kv_find (req->uri->query, "callback");
    if (!callback) {
        seaf_warning ("[get pg] callback not found in url.\n");
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    pthread_mutex_lock (&pg_lock);
    progress = g_hash_table_lookup (upload_progress, progress_id);
    pthread_mutex_unlock (&pg_lock);

    if (!progress) {
        /* seaf_warning ("[get pg] No progress found for %s.\n", progress_id); */
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    /* Return JSONP formated data. */
    buf = g_string_new (NULL);
    g_string_append_printf (buf,
                            "%s({\"uploaded\": %lld, \"length\": %lld});",
                            callback, progress->uploaded, progress->size);
    evbuffer_add (req->buffer_out, buf->str, buf->len);

    seaf_debug ("JSONP: %s\n", buf->str);

    evhtp_send_reply (req, EVHTP_RES_OK);
    g_string_free (buf, TRUE);
}

int
upload_file_init (evhtp_t *htp)
{
    evhtp_callback_t *cb;

    if (g_mkdir_with_parents (seaf->http_temp_dir, 0777) < 0) {
        seaf_warning ("Failed to create temp file dir %s.\n",
                      seaf->http_temp_dir);
        return -1;
    }

    cb = evhtp_set_regex_cb (htp, "^/upload/.*", upload_cb, NULL);
    /* upload_headers_cb() will be called after evhtp parsed all http headers. */
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    cb = evhtp_set_regex_cb (htp, "^/upload-api/.*", upload_api_cb, NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    cb = evhtp_set_regex_cb (htp, "^/update/.*", update_cb, NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    cb = evhtp_set_regex_cb (htp, "^/update-api/.*", update_api_cb, NULL);
    evhtp_set_hook(&cb->hooks, evhtp_hook_on_headers, upload_headers_cb, NULL);

    evhtp_set_regex_cb (htp, "^/upload_progress.*", upload_progress_cb, NULL);

    upload_progress = g_hash_table_new_full (g_str_hash, g_str_equal,
                                             g_free, g_free);
    pthread_mutex_init (&pg_lock, NULL);

    return 0;
}
