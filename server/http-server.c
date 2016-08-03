#include "common.h"

#include <pthread.h>
#include <string.h>
#include <jansson.h>
#include <locale.h>
#include <sys/types.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#else
#include <event.h>
#endif

#include <evhtp.h>

#include "utils.h"
#include "log.h"
#include "http-server.h"
#include "seafile-session.h"
#include "diff-simple.h"
#include "merge-new.h"
#include "seaf-db.h"

#include "access-file.h"
#include "upload-file.h"
#include "fileserver-config.h"

#include "http-status-codes.h"

#define DEFAULT_BIND_HOST "0.0.0.0"
#define DEFAULT_BIND_PORT 8082
#define DEFAULT_THREADS 50
#define DEFAULT_MAX_DOWNLOAD_DIR_SIZE 100 * ((gint64)1 << 20) /* 100MB */
#define DEFAULT_MAX_INDEXING_THREADS 1

#define HOST "host"
#define PORT "port"

#define INIT_INFO "If you see this page, Seafile HTTP syncing component works."
#define PROTO_VERSION "{\"version\": 1}"

#define CLEANING_INTERVAL_SEC 300	/* 5 minutes */
#define TOKEN_EXPIRE_TIME 7200	    /* 2 hours */
#define PERM_EXPIRE_TIME 7200       /* 2 hours */
#define VIRINFO_EXPIRE_TIME 7200       /* 2 hours */

struct _HttpServer {
    evbase_t *evbase;
    evhtp_t *evhtp;
    pthread_t thread_id;

    GHashTable *token_cache;
    pthread_mutex_t token_cache_lock; /* token -> username */

    GHashTable *perm_cache;
    pthread_mutex_t perm_cache_lock; /* repo_id:username -> permission */

    GHashTable *vir_repo_info_cache;
    pthread_mutex_t vir_repo_info_cache_lock;

    uint32_t cevent_id;         /* Used for sending activity events. */

    event_t *reap_timer;
};
typedef struct _HttpServer HttpServer;

typedef struct TokenInfo {
    char *repo_id;
    char *email;
    gint64 expire_time;
} TokenInfo;

typedef struct PermInfo {
    char *perm;
    gint64 expire_time;
} PermInfo;

typedef struct VirRepoInfo {
    char *store_id;
    gint64 expire_time;
} VirRepoInfo;

typedef struct FsHdr {
    char obj_id[40];
    guint32 obj_size;
} __attribute__((__packed__)) FsHdr;

typedef enum CheckExistType {
    CHECK_FS_EXIST,
    CHECK_BLOCK_EXIST
} CheckExistType;

const char *GET_PROTO_PATH = "/protocol-version";
const char *OP_PERM_CHECK_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/permission-check/.*";
const char *GET_CHECK_QUOTA_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/quota-check/.*";
const char *HEAD_COMMIT_OPER_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/HEAD";
const char *COMMIT_OPER_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/[\\da-z]{40}";
const char *PUT_COMMIT_INFO_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/commit/[\\da-z]{40}";
const char *GET_FS_OBJ_ID_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/fs-id-list/.*";
const char *BLOCK_OPER_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/block/[\\da-z]{40}";
const char *POST_CHECK_FS_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/check-fs";
const char *POST_CHECK_BLOCK_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/check-blocks";
const char *POST_RECV_FS_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/recv-fs";
const char *POST_PACK_FS_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/pack-fs";
const char *GET_BLOCK_MAP_REGEX = "^/repo/[\\da-z]{8}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{4}-[\\da-z]{12}/block-map/[\\da-z]{40}";

static void
load_http_config (HttpServerStruct *htp_server, SeafileSession *session)
{
    GError *error = NULL;
    char *host = NULL;
    int port = 0;
    int max_upload_size_mb;
    int max_download_dir_size_mb;
    char *encoding;
    int max_indexing_threads;

    host = fileserver_config_get_string (session->config, HOST, &error);
    if (!error) {
        htp_server->bind_addr = host;
    } else {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND &&
            error->code != G_KEY_FILE_ERROR_GROUP_NOT_FOUND) {
            seaf_warning ("[conf] Error: failed to read the value of 'host'\n");
            exit (1);
        }

        htp_server->bind_addr = g_strdup (DEFAULT_BIND_HOST);
        g_clear_error (&error);
    }

    port = fileserver_config_get_integer (session->config, PORT, &error);
    if (!error) {
        htp_server->bind_port = port;
    } else {
        if (error->code != G_KEY_FILE_ERROR_KEY_NOT_FOUND &&
            error->code != G_KEY_FILE_ERROR_GROUP_NOT_FOUND) {
            seaf_warning ("[conf] Error: failed to read the value of 'port'\n");
            exit (1);
        }

        htp_server->bind_port = DEFAULT_BIND_PORT;
        g_clear_error (&error);
    }

    max_upload_size_mb = fileserver_config_get_integer (session->config,
                                                 "max_upload_size",
                                                 &error);
    if (error) {
        htp_server->max_upload_size = -1; /* no limit */
        g_clear_error (&error);
    } else {
        if (max_upload_size_mb <= 0)
            htp_server->max_upload_size = -1; /* no limit */
        else
            htp_server->max_upload_size = max_upload_size_mb * ((gint64)1 << 20);
    }

    max_download_dir_size_mb = fileserver_config_get_integer (session->config,
                                                       "max_download_dir_size",
                                                       &error);
    if (error) {
        htp_server->max_download_dir_size = DEFAULT_MAX_DOWNLOAD_DIR_SIZE;
        g_clear_error (&error);
    } else {
        if (max_download_dir_size_mb <= 0)
            htp_server->max_download_dir_size = DEFAULT_MAX_DOWNLOAD_DIR_SIZE;
        else
            htp_server->max_download_dir_size = max_download_dir_size_mb * ((gint64)1 << 20);
    }

    max_indexing_threads = fileserver_config_get_integer (session->config,
                                                          "max_indexing_threads",
                                                          &error);
    if (error) {
        htp_server->max_indexing_threads = DEFAULT_MAX_INDEXING_THREADS;
        g_clear_error (&error);
    } else {
        if (max_indexing_threads <= 0)
            htp_server->max_indexing_threads = DEFAULT_MAX_INDEXING_THREADS;
        else
            htp_server->max_indexing_threads = max_indexing_threads;
    }

    encoding = g_key_file_get_string (session->config,
                                      "zip", "windows_encoding",
                                      &error);
    if (encoding) {
        htp_server->windows_encoding = encoding;
    } else {
        g_clear_error (&error);
        /* No windows specific encoding is specified. Set the ZIP_UTF8 flag. */
        setlocale (LC_ALL, "en_US.UTF-8");
    }
}

static int
validate_token (HttpServer *htp_server, evhtp_request_t *req,
                const char *repo_id, char **username,
                gboolean skip_cache)
{
    char *email = NULL;
    TokenInfo *token_info;

    const char *token = evhtp_kv_find (req->headers_in, "Seafile-Repo-Token");
    if (token == NULL) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return EVHTP_RES_BADREQ;
    }

    if (!skip_cache) {
        pthread_mutex_lock (&htp_server->token_cache_lock);

        token_info = g_hash_table_lookup (htp_server->token_cache, token);
        if (token_info) {
            if (username)
                *username = g_strdup(token_info->email);
            pthread_mutex_unlock (&htp_server->token_cache_lock);
            return EVHTP_RES_OK;
        }

        pthread_mutex_unlock (&htp_server->token_cache_lock);
    }

    email = seaf_repo_manager_get_email_by_token (seaf->repo_mgr,
                                                  repo_id, token);
    if (email == NULL) {
        pthread_mutex_lock (&htp_server->token_cache_lock);
        g_hash_table_remove (htp_server->token_cache, token);
        pthread_mutex_unlock (&htp_server->token_cache_lock);
        return EVHTP_RES_FORBIDDEN;
    }

    token_info = g_new0 (TokenInfo, 1);
    token_info->repo_id = g_strdup (repo_id);
    token_info->expire_time = (gint64)time(NULL) + TOKEN_EXPIRE_TIME;
    token_info->email = email;

    pthread_mutex_lock (&htp_server->token_cache_lock);
    g_hash_table_insert (htp_server->token_cache, g_strdup (token), token_info);
    pthread_mutex_unlock (&htp_server->token_cache_lock);

    if (username)
        *username = g_strdup(email);
    return EVHTP_RES_OK;
}

static PermInfo *
lookup_perm_cache (HttpServer *htp_server, const char *repo_id, const char *username)
{
    PermInfo *ret = NULL;
    char *key = g_strdup_printf ("%s:%s", repo_id, username);

    pthread_mutex_lock (&htp_server->perm_cache_lock);
    ret = g_hash_table_lookup (htp_server->perm_cache, key);
    pthread_mutex_unlock (&htp_server->perm_cache_lock);
    g_free (key);

    return ret;
}

static void
insert_perm_cache (HttpServer *htp_server,
                   const char *repo_id, const char *username,
                   PermInfo *perm)
{
    char *key = g_strdup_printf ("%s:%s", repo_id, username);

    pthread_mutex_lock (&htp_server->perm_cache_lock);
    g_hash_table_insert (htp_server->perm_cache, key, perm);
    pthread_mutex_unlock (&htp_server->perm_cache_lock);
}

static void
remove_perm_cache (HttpServer *htp_server,
                   const char *repo_id, const char *username)
{
    char *key = g_strdup_printf ("%s:%s", repo_id, username);

    pthread_mutex_lock (&htp_server->perm_cache_lock);
    g_hash_table_remove (htp_server->perm_cache, key);
    pthread_mutex_unlock (&htp_server->perm_cache_lock);

    g_free (key);
}

static int
check_permission (HttpServer *htp_server, const char *repo_id, const char *username,
                  const char *op, gboolean skip_cache)
{
    PermInfo *perm_info = NULL;

    if (!skip_cache)
        perm_info = lookup_perm_cache (htp_server, repo_id, username);

    if (perm_info) {
        if (strcmp(perm_info->perm, "r") == 0 && strcmp(op, "upload") == 0)
            return EVHTP_RES_FORBIDDEN;
        return EVHTP_RES_OK;
    }

    char *perm = seaf_repo_manager_check_permission (seaf->repo_mgr,
                                                     repo_id, username, NULL);
    if (perm) {
        perm_info = g_new0 (PermInfo, 1);
        /* Take the reference of perm. */
        perm_info->perm = perm;
        perm_info->expire_time = (gint64)time(NULL) + PERM_EXPIRE_TIME;
        insert_perm_cache (htp_server, repo_id, username, perm_info);

        if ((strcmp (perm, "r") == 0 && strcmp (op, "upload") == 0))
            return EVHTP_RES_FORBIDDEN;
        return EVHTP_RES_OK;
    }

    /* Invalidate cache if perm not found in db. */
    remove_perm_cache (htp_server, repo_id, username);
    return EVHTP_RES_FORBIDDEN;
}

static gboolean
get_vir_repo_info (SeafDBRow *row, void *data)
{
    HttpServer *htp_server = data;

    const char *repo_id = seaf_db_row_get_column_text (row, 0);
    if (!repo_id)
        return FALSE;
    const char *origin_id = seaf_db_row_get_column_text (row, 1);
    if (!origin_id)
        return FALSE;

    VirRepoInfo **vinfo = data;
    *vinfo = g_new0 (VirRepoInfo, 1);
    if (!*vinfo)
        return FALSE;
    (*vinfo)->store_id = g_strdup (origin_id);
    if (!(*vinfo)->store_id)
        return FALSE;
    (*vinfo)->expire_time = time (NULL) + VIRINFO_EXPIRE_TIME;

    return TRUE;
}

static char *
get_store_id_from_vir_repo_info_cache (HttpServer *htp_server, const char *repo_id)
{
    char *store_id = NULL;
    VirRepoInfo *vinfo = NULL;

    pthread_mutex_lock (&htp_server->vir_repo_info_cache_lock);
    vinfo = g_hash_table_lookup (htp_server->vir_repo_info_cache, repo_id);

    if (vinfo) {
        if (vinfo->store_id)
            store_id = g_strdup (vinfo->store_id);
        else
            store_id = g_strdup (repo_id);

        vinfo->expire_time = time (NULL) + VIRINFO_EXPIRE_TIME;
    }

    pthread_mutex_unlock (&htp_server->vir_repo_info_cache_lock);

    return store_id;
}

static void
add_vir_info_to_cache (HttpServer *htp_server, const char *repo_id,
                       VirRepoInfo *vinfo)
{
    pthread_mutex_lock (&htp_server->vir_repo_info_cache_lock);
    g_hash_table_insert (htp_server->vir_repo_info_cache, g_strdup (repo_id), vinfo);
    pthread_mutex_unlock (&htp_server->vir_repo_info_cache_lock);
}

static char *
get_repo_store_id (HttpServer *htp_server, const char *repo_id)
{
    char *store_id = get_store_id_from_vir_repo_info_cache (htp_server,
                                                            repo_id);
    if (store_id) {
        return store_id;
    }

    VirRepoInfo *vinfo = NULL;
    char *sql = "SELECT repo_id, origin_repo FROM VirtualRepo where repo_id = ?";
    int n_row = seaf_db_statement_foreach_row (seaf->db, sql, get_vir_repo_info,
                                               &vinfo, 1, "string", repo_id);
    if (n_row < 0) {
        // db error, return NULL
        return NULL;
    } else if (n_row == 0) {
        // repo is not virtual repo
        vinfo = g_new0 (VirRepoInfo, 1);
        if (!vinfo)
            return NULL;
        vinfo->expire_time = time (NULL) + VIRINFO_EXPIRE_TIME;

        add_vir_info_to_cache (htp_server, repo_id, vinfo);

        return g_strdup (repo_id);
    } else if (!vinfo || !vinfo->store_id) {
        // out of memory, return NULL
        return NULL;
    }

    add_vir_info_to_cache (htp_server, repo_id, vinfo);

    return g_strdup (vinfo->store_id);
}

static void
default_cb (evhtp_request_t *req, void *arg)
{
    evbuffer_add (req->buffer_out, INIT_INFO, strlen (INIT_INFO));
    evhtp_send_reply (req, EVHTP_RES_OK);
}

typedef struct {
    char *etype;
    char *user;
    char *ip;
    char repo_id[37];
    char *path;
    char *client_name;
} RepoEventData;

static void
free_repo_event_data (RepoEventData *data)
{
    if (!data)
        return;

    g_free (data->etype);
    g_free (data->user);
    g_free (data->ip);
    g_free (data->path);
    g_free (data->client_name);
    g_free (data);
}

static void
publish_repo_event (CEvent *event, void *data)
{
    RepoEventData *rdata = event->data;

    GString *buf = g_string_new (NULL);
    g_string_printf (buf, "%s\t%s\t%s\t%s\t%s\t%s",
                     rdata->etype, rdata->user, rdata->ip,
                     rdata->client_name ? rdata->client_name : "",
                     rdata->repo_id, rdata->path ? rdata->path : "/");

    seaf_mq_manager_publish_event (seaf->mq_mgr, buf->str);

    g_string_free (buf, TRUE);
    free_repo_event_data (rdata);
}

static void
on_repo_oper (HttpServer *htp_server, const char *etype,
              const char *repo_id, char *user, char *ip, char *client_name)
{
    RepoEventData *rdata = g_new0 (RepoEventData, 1);
    SeafVirtRepo *vinfo = seaf_repo_manager_get_virtual_repo_info (seaf->repo_mgr,
                                                                   repo_id);

    if (vinfo) {
        memcpy (rdata->repo_id, vinfo->origin_repo_id, 36);
        rdata->path = g_strdup(vinfo->path);
    } else
        memcpy (rdata->repo_id, repo_id, 36);
    rdata->etype = g_strdup (etype);
    rdata->user = g_strdup (user);
    rdata->ip = g_strdup (ip);
    rdata->client_name = g_strdup(client_name);

    cevent_manager_add_event (seaf->ev_mgr, htp_server->cevent_id, rdata);

    if (vinfo) {
        g_free (vinfo->path);
        g_free (vinfo);
    }
}

char *
get_client_ip_addr (evhtp_request_t *req)
{
    const char *xff = evhtp_kv_find (req->headers_in, "X-Forwarded-For");
    if (xff) {
        struct in_addr addr;
        const char *comma = strchr (xff, ',');
        char *copy;
        if (comma)
            copy = g_strndup(xff, comma-xff);
        else
            copy = g_strdup(xff);
        if (evutil_inet_pton (AF_INET, copy, &addr) == 1)
            return copy;
        g_free (copy);
    }

    evhtp_connection_t *conn = req->conn;
    char ip_addr[17];
    const char *ip = NULL;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)conn->saddr;

    memset (ip_addr, '\0', 17);
    ip = evutil_inet_ntop (AF_INET, &addr_in->sin_addr, ip_addr, 16);

    return g_strdup (ip);
}

static int
validate_client_ver (const char *client_ver)
{
    int n_major;
    int n_minor;
    int n_build;
    char **versions = NULL;
    char *next_str = NULL;

    versions = g_strsplit (client_ver, ".", 3);
    if (g_strv_length (versions) != 3) {
        g_strfreev (versions);
        return EVHTP_RES_BADREQ;
    }

    n_major = strtoll (versions[0], &next_str, 10);
    if (versions[0] == next_str) {
        g_strfreev (versions);
        return EVHTP_RES_BADREQ;
    }

    n_minor = strtoll (versions[1], &next_str, 10);
    if (versions[1] == next_str) {
        g_strfreev (versions);
        return EVHTP_RES_BADREQ;
    }

    n_build = strtoll (versions[2], &next_str, 10);
    if (versions[2] == next_str) {
        g_strfreev (versions);
        return EVHTP_RES_BADREQ;
    }

    // todo: judge whether version is too old, then return 426

    g_strfreev (versions);
    return EVHTP_RES_OK;
}

static void
get_check_permission_cb (evhtp_request_t *req, void *arg)
{
    const char *op = evhtp_kv_find (req->uri->query, "op");
    if (op == NULL || (strcmp (op, "upload") != 0 && strcmp (op, "download") != 0)) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *client_id = evhtp_kv_find (req->uri->query, "client_id");
    if (client_id && strlen(client_id) != 40) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *client_ver = evhtp_kv_find (req->uri->query, "client_ver");
    if (client_ver) {
        int status = validate_client_ver (client_ver);
        if (status != EVHTP_RES_OK) {
            evhtp_send_reply (req, status);
            return;
        }
    }

    char *client_name = NULL;
    const char *client_name_in = evhtp_kv_find (req->uri->query, "client_name");
    if (client_name_in)
        client_name = g_uri_unescape_string (client_name_in, NULL);

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    HttpServer *htp_server = (HttpServer *)arg;
    char *username = NULL;
    char *ip = NULL;
    const char *token;
    SeafRepo *repo = NULL;

    repo = seaf_repo_manager_get_repo_ex (seaf->repo_mgr, repo_id);
    if (!repo) {
        evhtp_send_reply (req, SEAF_HTTP_RES_REPO_DELETED);
        goto out;
    }
    if (repo->is_corrupted || repo->repaired) {
        evhtp_send_reply (req, SEAF_HTTP_RES_REPO_CORRUPTED);
        goto out;
    }

    int token_status = validate_token (htp_server, req, repo_id, &username, TRUE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    /* We shall actually check the permission from database, don't rely on
     * the cache here.
     */
    int perm_status = check_permission (htp_server, repo_id, username, op, TRUE);
    if (perm_status == EVHTP_RES_FORBIDDEN) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    ip = get_client_ip_addr (req);
    if (!ip) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        token = evhtp_kv_find (req->headers_in, "Seafile-Repo-Token");
        seaf_warning ("[%s] Failed to get client ip.\n", token);
        goto out;
    }

    if (strcmp (op, "download") == 0) {
        on_repo_oper (htp_server, "repo-download-sync", repo_id, username, ip, client_name);
    }
    /* else if (strcmp (op, "upload") == 0) { */
    /*     on_repo_oper (htp_server, "repo-upload-sync", repo_id, username, ip, client_name); */
    /* } */

    if (client_id && client_name) {
        token = evhtp_kv_find (req->headers_in, "Seafile-Repo-Token");

        /* Record the (token, email, <peer info>) information, <peer info> may
         * include peer_id, peer_ip, peer_name, etc.
         */
        if (!seaf_repo_manager_token_peer_info_exists (seaf->repo_mgr, token))
            seaf_repo_manager_add_token_peer_info (seaf->repo_mgr,
                                                   token,
                                                   client_id,
                                                   ip,
                                                   client_name,
                                                   (gint64)time(NULL),
                                                   client_ver);
        else
            seaf_repo_manager_update_token_peer_info (seaf->repo_mgr,
                                                      token,
                                                      ip,
                                                      (gint64)time(NULL),
                                                      client_ver);
    }

    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    g_free (username);
    g_strfreev (parts);
    g_free (ip);
    g_free (client_name);
    if (repo) {
        seaf_repo_unref (repo);
    }
}

static void
get_protocol_cb (evhtp_request_t *req, void *arg)
{
    evbuffer_add (req->buffer_out, PROTO_VERSION, strlen (PROTO_VERSION));
    evhtp_send_reply (req, EVHTP_RES_OK);
}

static void
get_check_quota_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    const char *delta = evhtp_kv_find (req->uri->query, "delta");
    if (delta == NULL) {
        char *error = "Invalid delta parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    char *next_ptr = NULL;
    gint64 delta_num = strtoll(delta, &next_ptr, 10);
    if (!(*delta != '\0' && *next_ptr == '\0')) {
        char *error = "Invalid delta parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    int ret = seaf_quota_manager_check_quota_with_delta (seaf->quota_mgr,
                                                         repo_id, delta_num);
    if (ret < 0) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    } else if (ret == 0) {
        evhtp_send_reply (req, EVHTP_RES_OK);
    } else {
        evhtp_send_reply (req, SEAF_HTTP_RES_NOQUOTA);
    }

out:
    g_strfreev (parts);
}

static gboolean
get_branch (SeafDBRow *row, void *vid)
{
    char *ret = vid;
    const char *commit_id;

    commit_id = seaf_db_row_get_column_text (row, 0);
    memcpy (ret, commit_id, 41);

    return FALSE;
}

static void
get_head_commit_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    gboolean db_err = FALSE, exists = TRUE;
    int token_status;
    char commit_id[41];
    char *sql;

    sql = "SELECT 1 FROM Repo WHERE repo_id=?";
    exists = seaf_db_statement_exists (seaf->db, sql, &db_err, 1, "string", repo_id);
    if (!exists) {
        if (db_err) {
            seaf_warning ("DB error when check repo existence.\n");
            evbuffer_add_printf (req->buffer_out,
                                 "{\"is_corrupted\": 1}");
            evhtp_send_reply (req, EVHTP_RES_OK);
            goto out;
        }
        evhtp_send_reply (req, SEAF_HTTP_RES_REPO_DELETED);
        goto out;
    }

    token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    commit_id[0] = 0;

    sql = "SELECT commit_id FROM Branch WHERE name='master' AND repo_id=?";
    if (seaf_db_statement_foreach_row (seaf->db, sql,
                                       get_branch, commit_id,
                                       1, "string", repo_id) < 0) {
        seaf_warning ("DB error when get branch master.\n");
        evbuffer_add_printf (req->buffer_out,
                             "{\"is_corrupted\": 1}");
        evhtp_send_reply (req, EVHTP_RES_OK);
        goto out;
    }

    if (commit_id[0] == 0) {
        evhtp_send_reply (req, SEAF_HTTP_RES_REPO_DELETED);
        goto out;
    }

    evbuffer_add_printf (req->buffer_out,
                         "{\"is_corrupted\": 0, \"head_commit_id\": \"%s\"}",
                         commit_id);
    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    g_strfreev (parts);
}

static char *
gen_merge_description (SeafRepo *repo,
                       const char *merged_root,
                       const char *p1_root,
                       const char *p2_root)
{
    GList *p;
    GList *results = NULL;
    char *desc;

    diff_merge_roots (repo->store_id, repo->version,
                      merged_root, p1_root, p2_root, &results, TRUE);

    desc = diff_results_to_description (results);

    for (p = results; p; p = p->next) {
        DiffEntry *de = p->data;
        diff_entry_free (de);
    }
    g_list_free (results);

    return desc;
}

static int
fast_forward_or_merge (const char *repo_id,
                       SeafCommit *base,
                       SeafCommit *new_commit)
{
#define MAX_RETRY_COUNT 3

    SeafRepo *repo = NULL;
    SeafCommit *current_head = NULL, *merged_commit = NULL;
    int retry_cnt = 0;
    int ret = 0;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Repo %s doesn't exist.\n", repo_id);
        ret = -1;
        goto out;
    }

retry:
    current_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                   repo->id, repo->version,
                                                   repo->head->commit_id);
    if (!current_head) {
        seaf_warning ("Failed to find head commit of %s.\n", repo_id);
        ret = -1;
        goto out;
    }

    /* Merge if base and head are not the same. */
    if (strcmp (base->commit_id, current_head->commit_id) != 0) {
        MergeOptions opt;
        const char *roots[3];
        char *desc = NULL;

        memset (&opt, 0, sizeof(opt));
        opt.n_ways = 3;
        memcpy (opt.remote_repo_id, repo_id, 36);
        memcpy (opt.remote_head, new_commit->commit_id, 40);
        opt.do_merge = TRUE;

        roots[0] = base->root_id; /* base */
        roots[1] = current_head->root_id; /* head */
        roots[2] = new_commit->root_id;      /* remote */

        if (seaf_merge_trees (repo->store_id, repo->version, 3, roots, &opt) < 0) {
            seaf_warning ("Failed to merge.\n");
            ret = -1;
            goto out;
        }

        if (!opt.conflict)
            desc = g_strdup("Auto merge by system");
        else {
            desc = gen_merge_description (repo,
                                          opt.merged_tree_root,
                                          current_head->root_id,
                                          new_commit->root_id);
            if (!desc)
                desc = g_strdup("Auto merge by system");
        }

        merged_commit = seaf_commit_new(NULL, repo->id, opt.merged_tree_root,
                                        new_commit->creator_name, EMPTY_SHA1,
                                        desc,
                                        0);
        g_free (desc);

        merged_commit->parent_id = g_strdup (current_head->commit_id);
        merged_commit->second_parent_id = g_strdup (new_commit->commit_id);
        merged_commit->new_merge = TRUE;
        if (opt.conflict)
            merged_commit->conflict = TRUE;
        seaf_repo_to_commit (repo, merged_commit);

        if (seaf_commit_manager_add_commit (seaf->commit_mgr, merged_commit) < 0) {
            seaf_warning ("Failed to add commit.\n");
            ret = -1;
            goto out;
        }
    } else {
        seaf_commit_ref (new_commit);
        merged_commit = new_commit;
    }

    seaf_branch_set_commit(repo->head, merged_commit->commit_id);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   current_head->commit_id) < 0)
    {
        seaf_repo_unref (repo);
        repo = NULL;
        seaf_commit_unref (current_head);
        current_head = NULL;
        seaf_commit_unref (merged_commit);
        merged_commit = NULL;

        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!repo) {
            seaf_warning ("Repo %s doesn't exist.\n", repo_id);
            ret = -1;
            goto out;
        }

        if (++retry_cnt <= MAX_RETRY_COUNT) {
            /* Sleep random time between 100 and 1000 millisecs. */
            usleep (g_random_int_range(1, 11) * 100 * 1000);
            goto retry;
        } else {
            ret = -1;
            goto out;
        }
    }

out:
    seaf_commit_unref (current_head);
    seaf_commit_unref (merged_commit);
    seaf_repo_unref (repo);
    return ret;
}

static void
put_update_branch_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = arg;
    char **parts;
    char *repo_id;
    char *username = NULL;
    SeafRepo *repo = NULL;
    SeafCommit *new_commit = NULL, *base = NULL;

    const char *new_commit_id = evhtp_kv_find (req->uri->query, "head");
    if (new_commit_id == NULL || !is_object_id_valid (new_commit_id)) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "upload", FALSE);
    if (perm_status == EVHTP_RES_FORBIDDEN) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Repo %s is missing or corrupted.\n", repo_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    /* Since this is the last step of upload procedure, commit should exist. */
    new_commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 repo->id, repo->version,
                                                 new_commit_id);
    if (!new_commit) {
        seaf_warning ("Failed to get commit %s for repo %s.\n",
                      new_commit_id, repo->id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    base = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id, repo->version,
                                           new_commit->parent_id);
    if (!base) {
        seaf_warning ("Failed to get commit %s for repo %s.\n",
                      new_commit->parent_id, repo->id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    if (seaf_quota_manager_check_quota (seaf->quota_mgr, repo_id) < 0) {
        evhtp_send_reply (req, SEAF_HTTP_RES_NOQUOTA);
        goto out;
    }

    if (fast_forward_or_merge (repo_id, base, new_commit) < 0) {
        seaf_warning ("Fast forward merge for repo %s is failed.\n", repo_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    seaf_repo_manager_cleanup_virtual_repos (seaf->repo_mgr, repo_id);
    seaf_repo_manager_merge_virtual_repo (seaf->repo_mgr, repo_id, NULL);

    schedule_repo_size_computation (seaf->size_sched, repo_id);

    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    seaf_repo_unref (repo);
    seaf_commit_unref (new_commit);
    seaf_commit_unref (base);
    g_free (username);
    g_strfreev (parts);
}

static void
head_commit_oper_cb (evhtp_request_t *req, void *arg)
{
   htp_method req_method = evhtp_request_get_method (req);

   if (req_method == htp_method_GET) {
       get_head_commit_cb (req, arg);
   } else if (req_method == htp_method_PUT) {
       put_update_branch_cb (req, arg);
   }
}

static void
get_commit_info_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    char *commit_id = parts[3];

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    char *data = NULL;
    int len;

    int ret = seaf_obj_store_read_obj (seaf->commit_mgr->obj_store, repo_id, 1,
                                       commit_id, (void **)&data, &len);
    if (ret < 0) {
        seaf_warning ("Get commit info failed: commit %s is missing.\n", commit_id);
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    evbuffer_add (req->buffer_out, data, len);
    evhtp_send_reply (req, EVHTP_RES_OK);
    g_free (data);

out:
    g_strfreev (parts);
}

static void
put_commit_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    char *commit_id = parts[3];
    char *username = NULL;
    void *data = NULL;

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "upload", FALSE);
    if (perm_status == EVHTP_RES_FORBIDDEN) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    int con_len = evbuffer_get_length (req->buffer_in);
    if(con_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    data = g_new0 (char, con_len);
    if (!data) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %d bytes memory.\n", con_len);
        goto out;
    }

    evbuffer_remove (req->buffer_in, data, con_len);
    SeafCommit *commit = seaf_commit_from_data (commit_id, (char *)data, con_len);
    if (!commit) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    if (strcmp (commit->repo_id, repo_id) != 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    } else {
        evhtp_send_reply (req, EVHTP_RES_OK);
    }
    seaf_commit_unref (commit);

out:
    g_free (username);
    g_free (data);
    g_strfreev (parts);
}

static void
commit_oper_cb (evhtp_request_t *req, void *arg)
{
    htp_method req_method = evhtp_request_get_method (req);

    if (req_method == htp_method_PUT) {
        put_commit_cb (req, arg);
    } else if (req_method == htp_method_GET) {
        get_commit_info_cb (req, arg);
    }
}

static int
collect_file_ids (int n, const char *basedir, SeafDirent *files[], void *data)
{
    SeafDirent *file1 = files[0];
    SeafDirent *file2 = files[1];
    GList **pret = data;

    if (file1 && (!file2 || strcmp(file1->id, file2->id) != 0) &&
        strcmp (file1->id, EMPTY_SHA1) != 0)
        *pret = g_list_prepend (*pret, g_strdup(file1->id));

    return 0;
}

static int
collect_file_ids_nop (int n, const char *basedir, SeafDirent *files[], void *data)
{
    return 0;
}

static int
collect_dir_ids (int n, const char *basedir, SeafDirent *dirs[], void *data,
                 gboolean *recurse)
{
    SeafDirent *dir1 = dirs[0];
    SeafDirent *dir2 = dirs[1];
    GList **pret = data;

    if (dir1 && (!dir2 || strcmp(dir1->id, dir2->id) != 0) &&
        strcmp (dir1->id, EMPTY_SHA1) != 0)
        *pret = g_list_prepend (*pret, g_strdup(dir1->id));

    return 0;
}

static int
calculate_send_object_list (SeafRepo *repo,
                            const char *server_head,
                            const char *client_head,
                            gboolean dir_only,
                            GList **results)
{
    SeafCommit *remote_head = NULL, *master_head = NULL;
    char *remote_head_root;
    int ret = 0;

    *results = NULL;

    master_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                  repo->id, repo->version,
                                                  server_head);
    if (!master_head) {
        seaf_warning ("Server head commit %s:%s not found.\n", repo->id, server_head);
        return -1;
    }

    if (client_head) {
        remote_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                      repo->id, repo->version,
                                                      client_head);
        if (!remote_head) {
            seaf_warning ("Remote head commit %s:%s not found.\n",
                          repo->id, client_head);
            ret = -1;
            goto out;
        }
        remote_head_root = remote_head->root_id;
    } else
        remote_head_root = EMPTY_SHA1;

    /* Diff won't traverse the root object itself. */
    if (strcmp (remote_head_root, master_head->root_id) != 0 &&
        strcmp (master_head->root_id, EMPTY_SHA1) != 0)
        *results = g_list_prepend (*results, g_strdup(master_head->root_id));

    DiffOptions opts;
    memset (&opts, 0, sizeof(opts));
    memcpy (opts.store_id, repo->store_id, 36);
    opts.version = repo->version;
    if (!dir_only)
        opts.file_cb = collect_file_ids;
    else
        opts.file_cb = collect_file_ids_nop;
    opts.dir_cb = collect_dir_ids;
    opts.data = results;

    const char *trees[2];
    trees[0] = master_head->root_id;
    trees[1] = remote_head_root;
    if (diff_trees (2, trees, &opts) < 0) {
        seaf_warning ("Failed to diff remote and master head for repo %.8s.\n",
                      repo->id);
        string_list_free (*results);
        ret = -1;
    }

out:
    seaf_commit_unref (remote_head);
    seaf_commit_unref (master_head);
    return ret;
}

static void
get_fs_obj_id_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = arg;
    char **parts;
    char *repo_id;
    SeafRepo *repo = NULL;
    gboolean dir_only = FALSE;

    const char *server_head = evhtp_kv_find (req->uri->query, "server-head");
    if (server_head == NULL || !is_object_id_valid (server_head)) {
        char *error = "Invalid server-head parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *client_head = evhtp_kv_find (req->uri->query, "client-head");
    if (client_head && !is_object_id_valid (client_head)) {
        char *error = "Invalid client-head parameter.\n";
        seaf_warning ("%s", error);
        evbuffer_add (req->buffer_out, error, strlen (error));
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    const char *dir_only_arg = evhtp_kv_find (req->uri->query, "dir-only");
    if (dir_only_arg)
        dir_only = TRUE;

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    GList *list = NULL, *ptr;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to find repo %.8s.\n", repo_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    if (calculate_send_object_list (repo, server_head, client_head, dir_only, &list) < 0) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    json_t *obj_array = json_array ();

    for (ptr = list; ptr; ptr = ptr->next) {
        json_array_append_new (obj_array, json_string (ptr->data));
        g_free (ptr->data);
    }
    g_list_free (list);

    char *obj_list = json_dumps (obj_array, JSON_COMPACT);
    evbuffer_add (req->buffer_out, obj_list, strlen (obj_list));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (obj_list);
    json_decref (obj_array);

out:
    g_strfreev (parts);
    seaf_repo_unref (repo);
}

static void
get_block_cb (evhtp_request_t *req, void *arg)
{
    const char *repo_id = NULL;
    char *block_id = NULL;
    char *store_id = NULL;
    HttpServer *htp_server = arg;
    BlockMetadata *blk_meta = NULL;

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    block_id = parts[3];

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    blk_meta = seaf_block_manager_stat_block (seaf->block_mgr,
                                              store_id, 1, block_id);
    if (blk_meta == NULL) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    BlockHandle *blk_handle = NULL;
    blk_handle = seaf_block_manager_open_block(seaf->block_mgr,
                                               store_id, 1, block_id, BLOCK_READ);
    if (!blk_handle) {
        seaf_warning ("Failed to open block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    void *block_con = g_new0 (char, blk_meta->size);
    if (!block_con) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %d bytes memeory.\n", blk_meta->size);
        goto free_handle;
    }

    int rsize = seaf_block_manager_read_block (seaf->block_mgr,
                                               blk_handle, block_con,
                                               blk_meta->size);
    if (rsize != blk_meta->size) {
        seaf_warning ("Failed to read block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
    } else {
        evbuffer_add (req->buffer_out, block_con, blk_meta->size);
        evhtp_send_reply (req, EVHTP_RES_OK);
    }
    g_free (block_con);

free_handle:
    seaf_block_manager_close_block (seaf->block_mgr, blk_handle);
    seaf_block_manager_block_handle_free (seaf->block_mgr, blk_handle);

out:
    g_free (blk_meta);
    g_free (store_id);
    g_strfreev (parts);
}

static void
put_send_block_cb (evhtp_request_t *req, void *arg)
{
    const char *repo_id = NULL;
    char *block_id = NULL;
    char *store_id = NULL;
    char *username = NULL;
    HttpServer *htp_server = arg;
    char **parts = NULL;
    void *blk_con = NULL;

    parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    block_id = parts[3];

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "upload", FALSE);
    if (perm_status == EVHTP_RES_FORBIDDEN) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    int blk_len = evbuffer_get_length (req->buffer_in);
    if (blk_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    blk_con = g_new0 (char, blk_len);
    if (!blk_con) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %d bytes memory.\n", blk_len);
        goto out;
    }

    evbuffer_remove (req->buffer_in, blk_con, blk_len);

    BlockHandle *blk_handle = NULL;
    blk_handle = seaf_block_manager_open_block (seaf->block_mgr,
                                                store_id, 1, block_id, BLOCK_WRITE);
    if (blk_handle == NULL) {
        seaf_warning ("Failed to open block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    if (seaf_block_manager_write_block (seaf->block_mgr, blk_handle,
                                        blk_con, blk_len) != blk_len) {
        seaf_warning ("Failed to write block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_block_manager_close_block (seaf->block_mgr, blk_handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, blk_handle);
        goto out;
    }

    if (seaf_block_manager_close_block (seaf->block_mgr, blk_handle) < 0) {
        seaf_warning ("Failed to close block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_block_manager_block_handle_free (seaf->block_mgr, blk_handle);
        goto out;
    }

    if (seaf_block_manager_commit_block (seaf->block_mgr,
                                         blk_handle) < 0) {
        seaf_warning ("Failed to commit block %.8s:%s.\n", store_id, block_id);
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_block_manager_block_handle_free (seaf->block_mgr, blk_handle);
        goto out;
    }

    seaf_block_manager_block_handle_free (seaf->block_mgr, blk_handle);

    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    g_free (username);
    g_free (store_id);
    g_strfreev (parts);
    g_free (blk_con);
}

static void
block_oper_cb (evhtp_request_t *req, void *arg)
{
    htp_method req_method = evhtp_request_get_method (req);

    if (req_method == htp_method_GET) {
        get_block_cb (req, arg);
    } else if (req_method == htp_method_PUT) {
        put_send_block_cb (req, arg);
    }
}

static void
post_check_exist_cb (evhtp_request_t *req, void *arg, CheckExistType type)
{
    HttpServer *htp_server = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    char *repo_id = parts[1];
    char *store_id = NULL;

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    size_t list_len = evbuffer_get_length (req->buffer_in);
    if (list_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    char *obj_list_con = g_new0 (char, list_len);
    if (!obj_list_con) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %zu bytes memory.\n", list_len);
        goto out;
    }

    json_error_t jerror;
    evbuffer_remove (req->buffer_in, obj_list_con, list_len);
    json_t *obj_array = json_loadb (obj_list_con, list_len, 0, &jerror);
    g_free (obj_list_con);

    if (!obj_array) {
        seaf_warning ("dump obj_id to json failed, error: %s\n", jerror.text);
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        return;
    }

    json_t *obj = NULL;
    gboolean ret = TRUE;
    const char *obj_id = NULL;
    int index = 0;

    int array_size = json_array_size (obj_array);
    json_t *needed_objs = json_array();

    for (; index < array_size; ++index) {
        obj = json_array_get (obj_array, index);
        obj_id = json_string_value (obj);
        if (!is_object_id_valid (obj_id))
            continue;

        if (type == CHECK_FS_EXIST) {
            ret = seaf_fs_manager_object_exists (seaf->fs_mgr, store_id, 1,
                                                 obj_id);
        } else if (type == CHECK_BLOCK_EXIST) {
            ret = seaf_block_manager_block_exists (seaf->block_mgr, store_id, 1,
                                                   obj_id);
        }

        if (!ret) {
            json_array_append (needed_objs, obj);
        }
    }

    char *ret_array = json_dumps (needed_objs, JSON_COMPACT);
    evbuffer_add (req->buffer_out, ret_array, strlen (ret_array));
    evhtp_send_reply (req, EVHTP_RES_OK);

    g_free (ret_array);
    json_decref (needed_objs);
    json_decref (obj_array);

out:
    g_free (store_id);
    g_strfreev (parts);
}

static void
post_check_fs_cb (evhtp_request_t *req, void *arg)
{
   post_check_exist_cb (req, arg, CHECK_FS_EXIST);
}

static void
post_check_block_cb (evhtp_request_t *req, void *arg)
{
   post_check_exist_cb (req, arg, CHECK_BLOCK_EXIST);
}

static void
post_recv_fs_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    const char *repo_id = parts[1];
    char *store_id = NULL;
    char *username = NULL;
    FsHdr *hdr = NULL;

    int token_status = validate_token (htp_server, req, repo_id, &username, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    int perm_status = check_permission (htp_server, repo_id, username,
                                        "upload", FALSE);
    if (perm_status == EVHTP_RES_FORBIDDEN) {
        evhtp_send_reply (req, EVHTP_RES_FORBIDDEN);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    int fs_con_len = evbuffer_get_length (req->buffer_in);
    if (fs_con_len < sizeof(FsHdr)) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    hdr = g_new0 (FsHdr, 1);
    if (!hdr) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    char obj_id[41];
    void *obj_con = NULL;
    int con_len;

    while (fs_con_len > 0) {
        if (fs_con_len < sizeof(FsHdr)) {
            seaf_warning ("Bad fs object content format from %.8s:%s.\n",
                          repo_id, username);
            evhtp_send_reply (req, EVHTP_RES_BADREQ);
            break;
        }

        evbuffer_remove (req->buffer_in, hdr, sizeof(FsHdr));
        con_len = ntohl (hdr->obj_size);
        memcpy (obj_id, hdr->obj_id, 40);
        obj_id[40] = 0;

        if (!is_object_id_valid (obj_id)) {
            evhtp_send_reply (req, EVHTP_RES_BADREQ);
            break;
        }

        obj_con = g_new0 (char, con_len);
        if (!obj_con) {
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
            break;
        }
        evbuffer_remove (req->buffer_in, obj_con, con_len);

        if (seaf_obj_store_write_obj (seaf->fs_mgr->obj_store,
                                      store_id, 1, obj_id, obj_con,
                                      con_len, FALSE) < 0) {
            seaf_warning ("Failed to write fs object %.8s to disk.\n",
                          obj_id);
            g_free (obj_con);
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
            break;
        }

        fs_con_len -= (con_len + sizeof(FsHdr));
        g_free (obj_con);
    }

    if (fs_con_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_OK);
    }

out:
    g_free (store_id);
    g_free (hdr);
    g_free (username);
    g_strfreev (parts);
}

#define MAX_OBJECT_PACK_SIZE (1 << 20) /* 1MB */

static void
post_pack_fs_cb (evhtp_request_t *req, void *arg)
{
    HttpServer *htp_server = arg;
    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    const char *repo_id = parts[1];
    char *store_id = NULL;

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    int fs_id_list_len = evbuffer_get_length (req->buffer_in);
    if (fs_id_list_len == 0) {
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    char *fs_id_list = g_new0 (char, fs_id_list_len);
    if (!fs_id_list) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        seaf_warning ("Failed to allocate %d bytes memory.\n", fs_id_list_len);
        goto out;
    }

    json_error_t jerror;
    evbuffer_remove (req->buffer_in, fs_id_list, fs_id_list_len);
    json_t *fs_id_array = json_loadb (fs_id_list, fs_id_list_len, 0, &jerror);

    g_free (fs_id_list);

    if (!fs_id_array) {
        seaf_warning ("dump fs obj_id from json failed, error: %s\n", jerror.text);
        evhtp_send_reply (req, EVHTP_RES_BADREQ);
        goto out;
    }

    json_t *obj = NULL;
    const char *obj_id = NULL;
    int index = 0;
    void *fs_data = NULL;
    int data_len;
    int data_len_net;
    int total_size = 0;

    int array_size = json_array_size (fs_id_array);

    for (; index < array_size; ++index) {
        obj = json_array_get (fs_id_array, index);
        obj_id = json_string_value (obj);

        if (!is_object_id_valid (obj_id)) {
            seaf_warning ("Invalid fs id %s.\n", obj_id);
            evhtp_send_reply (req, EVHTP_RES_BADREQ);
            json_decref (fs_id_array);
            goto out;
        }
        if (seaf_obj_store_read_obj (seaf->fs_mgr->obj_store, store_id, 1,
                                     obj_id, &fs_data, &data_len) < 0) {
            seaf_warning ("Failed to read seafile object %s:%s.\n", store_id, obj_id);
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
            json_decref (fs_id_array);
            goto out;
        }

        evbuffer_add (req->buffer_out, obj_id, 40);
        data_len_net = htonl (data_len);
        evbuffer_add (req->buffer_out, &data_len_net, 4);
        evbuffer_add (req->buffer_out, fs_data, data_len);

        total_size += data_len;
        g_free (fs_data);

        if (total_size >= MAX_OBJECT_PACK_SIZE)
            break;
    }

    evhtp_send_reply (req, EVHTP_RES_OK);

    json_decref (fs_id_array);
out:
    g_free (store_id);
    g_strfreev (parts);
}

static void
get_block_map_cb (evhtp_request_t *req, void *arg)
{
    const char *repo_id = NULL;
    char *file_id = NULL;
    char *store_id = NULL;
    HttpServer *htp_server = arg;
    Seafile *file = NULL;
    char *block_id;
    BlockMetadata *blk_meta = NULL;
    json_t *array = NULL;
    char *data = NULL;

    char **parts = g_strsplit (req->uri->path->full + 1, "/", 0);
    repo_id = parts[1];
    file_id = parts[3];

    int token_status = validate_token (htp_server, req, repo_id, NULL, FALSE);
    if (token_status != EVHTP_RES_OK) {
        evhtp_send_reply (req, token_status);
        goto out;
    }

    store_id = get_repo_store_id (htp_server, repo_id);
    if (!store_id) {
        evhtp_send_reply (req, EVHTP_RES_SERVERR);
        goto out;
    }

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr, store_id, 1, file_id);
    if (!file) {
        evhtp_send_reply (req, EVHTP_RES_NOTFOUND);
        goto out;
    }

    array = json_array ();

    int i;
    for (i = 0; i < file->n_blocks; ++i) {
        block_id = file->blk_sha1s[i];
        blk_meta = seaf_block_manager_stat_block (seaf->block_mgr,
                                                  store_id, 1, block_id);
        if (blk_meta == NULL) {
            seaf_warning ("Failed to find block %s/%s\n", store_id, block_id);
            evhtp_send_reply (req, EVHTP_RES_SERVERR);
            g_free (blk_meta);
            goto out;
        }
        json_array_append_new (array, json_integer(blk_meta->size));
        g_free (blk_meta);
    }

    data = json_dumps (array, JSON_COMPACT);
    evbuffer_add (req->buffer_out, data, strlen (data));
    evhtp_send_reply (req, EVHTP_RES_OK);

out:
    g_free (store_id);
    seafile_unref (file);
    if (array)
        json_decref (array);
    if (data)
        free (data);
    g_strfreev (parts);
}

static void
http_request_init (HttpServerStruct *server)
{
    HttpServer *priv = server->priv;

    evhtp_set_cb (priv->evhtp,
                  GET_PROTO_PATH, get_protocol_cb,
                  NULL);

    evhtp_set_regex_cb (priv->evhtp,
                        GET_CHECK_QUOTA_REGEX, get_check_quota_cb,
                        priv);

    evhtp_set_regex_cb (priv->evhtp,
                        OP_PERM_CHECK_REGEX, get_check_permission_cb,
                        priv);

    evhtp_set_regex_cb (priv->evhtp,
                        HEAD_COMMIT_OPER_REGEX, head_commit_oper_cb,
                        priv);

    evhtp_set_regex_cb (priv->evhtp,
                        COMMIT_OPER_REGEX, commit_oper_cb,
                        priv);

    evhtp_set_regex_cb (priv->evhtp,
                        GET_FS_OBJ_ID_REGEX, get_fs_obj_id_cb,
                        priv);

    evhtp_set_regex_cb (priv->evhtp,
                        BLOCK_OPER_REGEX, block_oper_cb,
                        priv);

    evhtp_set_regex_cb (priv->evhtp,
                        POST_CHECK_FS_REGEX, post_check_fs_cb,
                        priv);

    evhtp_set_regex_cb (priv->evhtp,
                        POST_CHECK_BLOCK_REGEX, post_check_block_cb,
                        priv);

    evhtp_set_regex_cb (priv->evhtp,
                        POST_RECV_FS_REGEX, post_recv_fs_cb,
                        priv);

    evhtp_set_regex_cb (priv->evhtp,
                        POST_PACK_FS_REGEX, post_pack_fs_cb,
                        priv);

    evhtp_set_regex_cb (priv->evhtp,
                        GET_BLOCK_MAP_REGEX, get_block_map_cb,
                        priv);

    /* Web access file */
    access_file_init (priv->evhtp);

    /* Web upload file */
    upload_file_init (priv->evhtp, server->http_temp_dir);
}

static void
token_cache_value_free (gpointer data)
{
    TokenInfo *token_info = (TokenInfo *)data;
    if (token_info != NULL) {
        g_free (token_info->repo_id);
        g_free (token_info->email);
        g_free (token_info);
    }
}

static gboolean
is_token_expire (gpointer key, gpointer value, gpointer arg)
{
    TokenInfo *token_info = (TokenInfo *)value;

    if(token_info && token_info->expire_time <= (gint64)time(NULL)) {
        return TRUE;
    }

    return FALSE;
}

static void
perm_cache_value_free (gpointer data)
{
    PermInfo *perm_info = data;
    g_free (perm_info->perm);
    g_free (perm_info);
}

static gboolean
is_perm_expire (gpointer key, gpointer value, gpointer arg)
{
    PermInfo *perm_info = (PermInfo *)value;

    if(perm_info && perm_info->expire_time <= (gint64)time(NULL)) {
        return TRUE;
    }

    return FALSE;
}

static gboolean
is_vir_repo_info_expire (gpointer key, gpointer value, gpointer arg)
{
    VirRepoInfo *vinfo = (VirRepoInfo *)value;

    if(vinfo && vinfo->expire_time <= (gint64)time(NULL)) {
        return TRUE;
    }

    return FALSE;
}

static void
free_vir_repo_info (gpointer data)
{
    if (!data)
        return;

    VirRepoInfo *vinfo = data;

    if (vinfo->store_id)
        g_free (vinfo->store_id);

    g_free (vinfo);
}

static void
remove_expire_cache_cb (evutil_socket_t sock, short type, void *data)
{
    HttpServer *htp_server = data;

    pthread_mutex_lock (&htp_server->token_cache_lock);
    g_hash_table_foreach_remove (htp_server->token_cache, is_token_expire, NULL);
    pthread_mutex_unlock (&htp_server->token_cache_lock);

    pthread_mutex_lock (&htp_server->perm_cache_lock);
    g_hash_table_foreach_remove (htp_server->perm_cache, is_perm_expire, NULL);
    pthread_mutex_unlock (&htp_server->perm_cache_lock);

    pthread_mutex_lock (&htp_server->vir_repo_info_cache_lock);
    g_hash_table_foreach_remove (htp_server->vir_repo_info_cache,
                                 is_vir_repo_info_expire, NULL);
    pthread_mutex_unlock (&htp_server->vir_repo_info_cache_lock);
}

static void *
http_server_run (void *arg)
{
    HttpServerStruct *server = arg;
    HttpServer *priv = server->priv;

    priv->evbase = event_base_new();
    priv->evhtp = evhtp_new(priv->evbase, NULL);

    if (evhtp_bind_socket(priv->evhtp,
                          server->bind_addr,
                          server->bind_port, 128) < 0) {
        seaf_warning ("Could not bind socket: %s\n", strerror (errno));
        exit(-1);
    }

    http_request_init (server);

    evhtp_use_threads (priv->evhtp, NULL, DEFAULT_THREADS, NULL);

    struct timeval tv;
    tv.tv_sec = CLEANING_INTERVAL_SEC;
    tv.tv_usec = 0;
    priv->reap_timer = event_new (priv->evbase,
                                  -1,
                                  EV_PERSIST,
                                  remove_expire_cache_cb,
                                  priv);
    evtimer_add (priv->reap_timer, &tv);

    event_base_loop (priv->evbase, 0);

    return NULL;
}

HttpServerStruct *
seaf_http_server_new (struct _SeafileSession *session)
{
    HttpServerStruct *server = g_new0 (HttpServerStruct, 1);
    HttpServer *priv = g_new0 (HttpServer, 1);

    priv->evbase = NULL;
    priv->evhtp = NULL;

    load_http_config (server, session);

    priv->token_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                               g_free, token_cache_value_free);
    pthread_mutex_init (&priv->token_cache_lock, NULL);

    priv->perm_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                              g_free, perm_cache_value_free);
    pthread_mutex_init (&priv->perm_cache_lock, NULL);

    priv->vir_repo_info_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                       g_free, free_vir_repo_info);
    pthread_mutex_init (&priv->vir_repo_info_cache_lock, NULL);

    server->http_temp_dir = g_build_filename (session->seaf_dir, "httptemp", NULL);

    server->seaf_session = session;
    server->priv = priv;

    return server;
}

int
seaf_http_server_start (HttpServerStruct *server)
{
    server->priv->cevent_id = cevent_manager_register (seaf->ev_mgr,
                                    (cevent_handler)publish_repo_event,
                                                       NULL);

   int ret = pthread_create (&server->priv->thread_id, NULL, http_server_run, server);
   if (ret != 0)
       return -1;

   pthread_detach (server->priv->thread_id);
   return 0;
}

int
seaf_http_server_invalidate_tokens (HttpServerStruct *htp_server,
                                    const GList *tokens)
{
    const GList *p;

    pthread_mutex_lock (&htp_server->priv->token_cache_lock);
    for (p = tokens; p; p = p->next) {
        const char *token = (char *)p->data;
        g_hash_table_remove (htp_server->priv->token_cache, token);
    }
    pthread_mutex_unlock (&htp_server->priv->token_cache_lock);
    return 0;
}
