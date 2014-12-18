#include "common.h"

#include <pthread.h>
#include <curl/curl.h>
#include <jansson.h>
#include <event2/buffer.h>

#include "seafile-session.h"
#include "http-tx-mgr.h"

#include "seafile-error.h"
#include "utils.h"
#include "diff-simple.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_NO_QUOTA 443
#define HTTP_REPO_DELETED 444
#define HTTP_INTERNAL_SERVER_ERROR 500

#define RESET_BYTES_INTERVAL_MSEC 1000

struct _Connection {
    CURL *curl;
    gint64 ctime;               /* Used to clean up unused connection. */
};
typedef struct _Connection Connection;

struct _ConnectionPool {
    char *host;
    GQueue *queue;
    pthread_mutex_t lock;
};
typedef struct _ConnectionPool ConnectionPool;

struct _HttpTxPriv {
    GHashTable *download_tasks;
    GHashTable *upload_tasks;

    GHashTable *connection_pools; /* host -> connection pool */
    pthread_mutex_t pools_lock;

    CcnetTimer *reset_bytes_timer;
};
typedef struct _HttpTxPriv HttpTxPriv;

/* Http Tx Task */

static HttpTxTask *
http_tx_task_new (HttpTxManager *mgr,
                  const char *repo_id,
                  int repo_version,
                  int type,
                  gboolean is_clone,
                  const char *host,
                  const char *token,
                  const char *passwd,
                  const char *worktree)
{
    HttpTxTask *task = g_new0 (HttpTxTask, 1);

    task->manager = mgr;
    memcpy (task->repo_id, repo_id, 36);
    task->repo_version = repo_version;
    task->type = type;
    task->is_clone = is_clone;

    task->host = g_strdup(host);
    task->token = g_strdup(token);

    if (passwd)
        task->passwd = g_strdup(passwd);
    if (worktree)
        task->worktree = g_strdup(worktree);

    return task;
}

static void
http_tx_task_free (HttpTxTask *task)
{
    g_free (task->host);
    g_free (task->token);
    g_free (task->passwd);
    g_free (task->worktree);
    g_free (task);
}

static const char *http_task_state_str[] = {
    "normal",
    "canceled",
    "finished",
    "error",
};

static const char *http_task_rt_state_str[] = {
    "init",
    "check",
    "commit",
    "fs",
    "data",
    "update-branch",
    "finished",
};

static const char *http_task_error_strs[] = {
    "Successful",
    "Permission denied",
    "Network error",
    "Server error",
    "Bad request",
    "Internal data corrupt on the client",
    "Not enough memory",
    "Failed to write data on the client",
    "Storage quota full",
    "Files are locked by other application",
    "Unknown error",
};

/* Http connection and connection pool. */

static Connection *
connection_new ()
{
    Connection *conn = g_new0 (Connection, 1);

    conn->curl = curl_easy_init();
    conn->ctime = (gint64)time(NULL);

    return conn;
}

static void
connection_free (Connection *conn)
{
    curl_easy_cleanup (conn->curl);
    g_free (conn);
}

static ConnectionPool *
connection_pool_new (const char *host)
{
    ConnectionPool *pool = g_new0 (ConnectionPool, 1);
    pool->host = g_strdup(host);
    pool->queue = g_queue_new ();
    pthread_mutex_init (&pool->lock, NULL);
    return pool;
}

static ConnectionPool *
find_connection_pool (HttpTxPriv *priv, const char *host)
{
    ConnectionPool *pool;

    pthread_mutex_lock (&priv->pools_lock);
    pool = g_hash_table_lookup (priv->connection_pools, host);
    if (!pool) {
        pool = connection_pool_new (host);
        g_hash_table_insert (priv->connection_pools, g_strdup(host), pool);
    }
    pthread_mutex_unlock (&priv->pools_lock);

    return pool;
}

static Connection *
connection_pool_get_connection (ConnectionPool *pool)
{
    Connection *conn = NULL;

    pthread_mutex_lock (&pool->lock);
    conn = g_queue_pop_head (pool->queue);
    if (!conn) {
        conn = connection_new ();
    }
    pthread_mutex_unlock (&pool->lock);

    return conn;
}

static void
connection_pool_return_connection (ConnectionPool *pool, Connection *conn)
{
    if (!conn)
        return;

    curl_easy_reset (conn->curl);

    pthread_mutex_lock (&pool->lock);
    g_queue_push_tail (pool->queue, conn);
    pthread_mutex_unlock (&pool->lock);
}

HttpTxManager *
http_tx_manager_new (struct _SeafileSession *seaf)
{
    HttpTxManager *mgr = g_new0 (HttpTxManager, 1);
    HttpTxPriv *priv = g_new0 (HttpTxPriv, 1);

    mgr->seaf = seaf;

    priv->download_tasks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                  g_free,
                                                  (GDestroyNotify)http_tx_task_free);
    priv->upload_tasks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free,
                                                (GDestroyNotify)http_tx_task_free);

    priv->connection_pools = g_hash_table_new (g_str_hash, g_str_equal);
    pthread_mutex_init (&priv->pools_lock, NULL);

    mgr->priv = priv;

    return mgr;
}

static int
reset_bytes (void *vdata)
{
    HttpTxManager *mgr = vdata;
    HttpTxPriv *priv = mgr->priv;
    GHashTableIter iter;
    gpointer key, value;
    HttpTxTask *task;

    g_hash_table_iter_init (&iter, priv->download_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        task->last_tx_bytes = g_atomic_int_get (&task->tx_bytes);
        g_atomic_int_set (&task->tx_bytes, 0);
    }

    g_hash_table_iter_init (&iter, priv->upload_tasks);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        task = value;
        task->last_tx_bytes = g_atomic_int_get (&task->tx_bytes);
        g_atomic_int_set (&task->tx_bytes, 0);
    }

    return 1;
}

int
http_tx_manager_start (HttpTxManager *mgr)
{
    curl_global_init (CURL_GLOBAL_ALL);

    /* TODO: add a timer to clean up unused Http connections. */

    mgr->priv->reset_bytes_timer = ccnet_timer_new (reset_bytes,
                                                    mgr,
                                                    RESET_BYTES_INTERVAL_MSEC);

    return 0;
}

/* Common Utility Functions. */

typedef struct _HttpResponse {
    char *content;
    size_t size;
} HttpResponse;

static size_t
recv_response (void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    HttpResponse *rsp = userp;

    rsp->content = g_realloc (rsp->content, rsp->size + realsize);
    if (!rsp->content) {
        seaf_warning ("Not enough memory.\n");
        /* return a value other than realsize to signify an error. */
        return 0;
    }

    memcpy (rsp->content + rsp->size, contents, realsize);
    rsp->size += realsize;

    return realsize;
}

#define HTTP_TIMEOUT_SEC 45

typedef size_t (*HttpRecvCallback) (void *, size_t, size_t, void *);

static int
http_get (CURL *curl, const char *url, const char *token,
          int *rsp_status, char **rsp_content, gint64 *rsp_size,
          HttpRecvCallback callback, void *cb_data)
{
    char *token_header;
    struct curl_slist *headers = NULL;
    int ret = 0;

    if (token) {
        token_header = g_strdup_printf ("Seafile-Repo-Token: %s", token);
        headers = curl_slist_append (headers, token_header);
        g_free (token_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    /* Set low speed limit to 1 bytes. This effectively means no data. */
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, HTTP_TIMEOUT_SEC);

    if (seaf->disable_verify_certificate) {
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    HttpResponse rsp;
    memset (&rsp, 0, sizeof(rsp));
    if (rsp_content) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_response);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rsp);
    } else if (callback) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, cb_data);
    }

    int rc = curl_easy_perform (curl);
    if (rc != 0) {
        seaf_warning ("libcurl failed to GET %s: %s.\n",
                      url, curl_easy_strerror(rc));
        ret = -1;
        goto out;
    }

    long status;
    rc = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc != CURLE_OK) {
        seaf_warning ("Failed to get status code for GET %s.\n", url);
        ret = -1;
        goto out;
    }

    *rsp_status = status;

    if (rsp_content) {
        *rsp_content = rsp.content;
        *rsp_size = rsp.size;
    }

out:
    if (ret < 0)
        g_free (rsp.content);
    return ret;
}

typedef struct _HttpRequest {
    const char *content;
    size_t size;
} HttpRequest;

static size_t
send_request (void *ptr, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size *nmemb;
    size_t copy_size;
    HttpRequest *req = userp;

    if (req->size == 0)
        return 0;

    copy_size = MIN(req->size, realsize);
    memcpy (ptr, req->content, copy_size);
    req->size -= copy_size;
    req->content = req->content + copy_size;

    return copy_size;
}

typedef size_t (*HttpSendCallback) (void *, size_t, size_t, void *);

static int
http_put (CURL *curl, const char *url, const char *token,
          const char *req_content, gint64 req_size,
          HttpSendCallback callback, void *cb_data,
          int *rsp_status, char **rsp_content, gint64 *rsp_size)
{
    char *token_header;
    struct curl_slist *headers = NULL;
    int ret = 0;

    if (token) {
        token_header = g_strdup_printf ("Seafile-Repo-Token: %s", token);
        headers = curl_slist_append (headers, token_header);
        g_free (token_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    /* Set low speed limit to 1 bytes. This effectively means no data. */
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, HTTP_TIMEOUT_SEC);

    if (seaf->disable_verify_certificate) {
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    HttpRequest req;
    if (req_content) {
        memset (&req, 0, sizeof(req));
        req.content = req_content;
        req.size = req_size;
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, send_request);
        curl_easy_setopt(curl, CURLOPT_READDATA, &req);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)req_size);
    } else if (callback != NULL) {
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, cb_data);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)req_size);
    } else {
        curl_easy_setopt (curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)0);
    }

    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    HttpResponse rsp;
    memset (&rsp, 0, sizeof(rsp));
    if (rsp_content) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_response);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rsp);
    }

    int rc = curl_easy_perform (curl);
    if (rc != 0) {
        seaf_warning ("libcurl failed to PUT %s: %s.\n",
                      url, curl_easy_strerror(rc));
        ret = -1;
        goto out;
    }

    long status;
    rc = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc != CURLE_OK) {
        seaf_warning ("Failed to get status code for PUT %s.\n", url);
        ret = -1;
        goto out;
    }

    *rsp_status = status;

    if (rsp_content) {
        *rsp_content = rsp.content;
        *rsp_size = rsp.size;
    }

out:
    if (ret < 0)
        g_free (rsp.content);
    return ret;
}

static int
http_post (CURL *curl, const char *url, const char *token,
           const char *req_content, gint64 req_size,
           int *rsp_status, char **rsp_content, gint64 *rsp_size)
{
    char *token_header;
    struct curl_slist *headers = NULL;
    int ret = 0;

    g_return_val_if_fail (req_content != NULL, -1);

    if (token) {
        token_header = g_strdup_printf ("Seafile-Repo-Token: %s", token);
        headers = curl_slist_append (headers, token_header);
        g_free (token_header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    /* Set low speed limit to 1 bytes. This effectively means no data. */
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, HTTP_TIMEOUT_SEC);

    if (seaf->disable_verify_certificate) {
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt (curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    HttpRequest req;
    memset (&req, 0, sizeof(req));
    req.content = req_content;
    req.size = req_size;
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, send_request);
    curl_easy_setopt(curl, CURLOPT_READDATA, &req);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)req_size);

    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    HttpResponse rsp;
    memset (&rsp, 0, sizeof(rsp));
    if (rsp_content) {
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_response);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rsp);
    }

    int rc = curl_easy_perform (curl);
    if (rc != 0) {
        seaf_warning ("libcurl failed to POST %s: %s.\n",
                      url, curl_easy_strerror(rc));
        ret = -1;
        goto out;
    }

    long status;
    rc = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc != CURLE_OK) {
        seaf_warning ("Failed to get status code for POST %s.\n", url);
        ret = -1;
        goto out;
    }

    *rsp_status = status;

    if (rsp_content) {
        *rsp_content = rsp.content;
        *rsp_size = rsp.size;
    }

out:
    if (ret < 0)
        g_free (rsp.content);
    return ret;
}

static void
handle_http_errors (HttpTxTask *task, int status)
{
    if (status == HTTP_BAD_REQUEST)
        task->error = HTTP_TASK_ERR_BAD_REQUEST;
    else if (status == HTTP_FORBIDDEN)
        task->error = HTTP_TASK_ERR_FORBIDDEN;
    else if (status >= HTTP_INTERNAL_SERVER_ERROR)
        task->error = HTTP_TASK_ERR_SERVER;
    else if (status == HTTP_NOT_FOUND)
        task->error = HTTP_TASK_ERR_SERVER;
    else if (status == HTTP_NO_QUOTA)
        task->error = HTTP_TASK_ERR_NO_QUOTA;
    else
        task->error = HTTP_TASK_ERR_UNKNOWN;
}

static void
emit_transfer_done_signal (HttpTxTask *task)
{
    if (task->type == HTTP_TASK_TYPE_DOWNLOAD)
        g_signal_emit_by_name (seaf, "repo-http-fetched", task);
    else
        g_signal_emit_by_name (seaf, "repo-http-uploaded", task);
}

static void
transition_state (HttpTxTask *task, int state, int rt_state)
{
    seaf_message ("Transfer repo '%.8s': ('%s', '%s') --> ('%s', '%s')\n",
                  task->repo_id,
                  http_task_state_to_str(task->state),
                  http_task_rt_state_to_str(task->runtime_state),
                  http_task_state_to_str(state),
                  http_task_rt_state_to_str(rt_state));

    if (state != task->state)
        task->state = state;
    task->runtime_state = rt_state;

    if (rt_state == HTTP_TASK_RT_STATE_FINISHED) {
        /* Clear download head info. */
        if (task->type == HTTP_TASK_TYPE_DOWNLOAD &&
            state == HTTP_TASK_STATE_FINISHED)
            seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                                 task->repo_id,
                                                 REPO_PROP_DOWNLOAD_HEAD,
                                                 EMPTY_SHA1);

        emit_transfer_done_signal (task);
    }
}

typedef struct {
    char *host;
    HttpProtocolVersionCallback callback;
    void *user_data;

    gboolean success;
    gboolean not_supported;
    int version;
} CheckProtocolData;

static int
parse_protocol_version (const char *rsp_content, int rsp_size, CheckProtocolData *data)
{
    json_t *object = NULL;
    json_error_t jerror;
    int version;

    object = json_loadb (rsp_content, rsp_size, 0, &jerror);
    if (!object) {
        seaf_warning ("Parse response failed: %s.\n", jerror.text);
        return -1;
    }

    if (json_object_has_member (object, "version")) {
        version = json_object_get_int_member (object, "version");
        data->version = version;
    } else {
        seaf_warning ("Response doesn't contain protocol version.\n");
        json_decref (object);
        return -1;
    }

    json_decref (object);
    return 0;
}

static void *
check_protocol_version_thread (void *vdata)
{
    CheckProtocolData *data = vdata;
    HttpTxPriv *priv = seaf->http_tx_mgr->priv;
    ConnectionPool *pool;
    Connection *conn;
    CURL *curl;
    char *url;
    int status;
    char *rsp_content = NULL;
    gint64 rsp_size;

    pool = find_connection_pool (priv, data->host);
    if (!pool) {
        seaf_warning ("Failed to create connection pool for host %s.\n", data->host);
        return vdata;
    }

    conn = connection_pool_get_connection (pool);
    if (!conn) {
        seaf_warning ("Failed to get connection to host %s.\n", data->host);
        return vdata;
    }

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/protocol-version", data->host);

    if (http_get (curl, url, NULL, &status, &rsp_content, &rsp_size, NULL, NULL) < 0) {
        goto out;
    }

    data->success = TRUE;

    if (status == HTTP_OK) {
        if (rsp_size == 0)
            data->not_supported = TRUE;
        else if (parse_protocol_version (rsp_content, rsp_size, data) < 0)
            data->not_supported = TRUE;
    } else {
        seaf_warning ("Bad response code for GET %s: %d.\n", url, status);
        data->not_supported = TRUE;
    }

out:
    g_free (url);
    g_free (rsp_content);
    connection_pool_return_connection (pool, conn);

    return vdata;
}

static void
check_protocol_version_done (void *vdata)
{
    CheckProtocolData *data = vdata;
    HttpProtocolVersion result;

    memset (&result, 0, sizeof(result));
    result.check_success = data->success;
    result.not_supported = data->not_supported;
    result.version = data->version;

    data->callback (&result, data->user_data);

    g_free (data->host);
    g_free (data);
}

int
http_tx_manager_check_protocol_version (HttpTxManager *manager,
                                        const char *host,
                                        HttpProtocolVersionCallback callback,
                                        void *user_data)
{
    CheckProtocolData *data = g_new0 (CheckProtocolData, 1);

    data->host = g_strdup(host);
    data->callback = callback;
    data->user_data = user_data;

    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    check_protocol_version_thread,
                                    check_protocol_version_done,
                                    data);

    return 0;
}

/* Check Head Commit. */

typedef struct {
    char repo_id[41];
    int repo_version;
    char *host;
    char *token;
    HttpHeadCommitCallback callback;
    void *user_data;

    gboolean success;
    gboolean is_corrupt;
    gboolean is_deleted;
    char head_commit[41];
} CheckHeadData;

static int
parse_head_commit_info (const char *rsp_content, int rsp_size, CheckHeadData *data)
{
    json_t *object = NULL;
    json_error_t jerror;
    const char *head_commit;

    object = json_loadb (rsp_content, rsp_size, 0, &jerror);
    if (!object) {
        seaf_warning ("Parse response failed: %s.\n", jerror.text);
        return -1;
    }

    if (json_object_has_member (object, "is_corrupted") &&
        json_object_get_int_member (object, "is_corrupted"))
        data->is_corrupt = TRUE;

    if (!data->is_corrupt) {
        head_commit = json_object_get_string_member (object, "head_commit_id");
        if (!head_commit) {
            seaf_warning ("Check head commit for repo %s failed. "
                          "Response doesn't contain head commit id.\n",
                          data->repo_id);
            json_decref (object);
            return -1;
        }
        memcpy (data->head_commit, head_commit, 40);
    }

    json_decref (object);
    return 0;
}

static void *
check_head_commit_thread (void *vdata)
{
    CheckHeadData *data = vdata;
    HttpTxPriv *priv = seaf->http_tx_mgr->priv;
    ConnectionPool *pool;
    Connection *conn;
    CURL *curl;
    char *url;
    int status;
    char *rsp_content = NULL;
    gint64 rsp_size;

    pool = find_connection_pool (priv, data->host);
    if (!pool) {
        seaf_warning ("Failed to create connection pool for host %s.\n", data->host);
        return vdata;
    }

    conn = connection_pool_get_connection (pool);
    if (!conn) {
        seaf_warning ("Failed to get connection to host %s.\n", data->host);
        return vdata;
    }

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/repo/%s/commit/HEAD",
                           data->host, data->repo_id);

    if (http_get (curl, url, data->token, &status, &rsp_content, &rsp_size,
                  NULL, NULL) < 0)
        goto out;

    if (status == HTTP_OK) {
        if (parse_head_commit_info (rsp_content, rsp_size, data) < 0)
            goto out;
        data->success = TRUE;
    } else if (status == HTTP_REPO_DELETED) {
        data->is_deleted = TRUE;
        data->success = TRUE;
    } else {
        seaf_warning ("Bad response code for GET %s: %d.\n", url, status);
    }

out:
    g_free (url);
    g_free (rsp_content);
    connection_pool_return_connection (pool, conn);
    return vdata;
}

static void
check_head_commit_done (void *vdata)
{
    CheckHeadData *data = vdata;
    HttpHeadCommit result;

    memset (&result, 0, sizeof(result));
    result.check_success = data->success;
    result.is_corrupt = data->is_corrupt;
    result.is_deleted = data->is_deleted;
    memcpy (result.head_commit, data->head_commit, 40);

    data->callback (&result, data->user_data);

    g_free (data->host);
    g_free (data->token);
    g_free (data);
}

int
http_tx_manager_check_head_commit (HttpTxManager *manager,
                                   const char *repo_id,
                                   int repo_version,
                                   const char *host,
                                   const char *token,
                                   HttpHeadCommitCallback callback,
                                   void *user_data)
{
    CheckHeadData *data = g_new0 (CheckHeadData, 1);

    memcpy (data->repo_id, repo_id, 36);
    data->repo_version = repo_version;
    data->host = g_strdup(host);
    data->token = g_strdup(token);
    data->callback = callback;
    data->user_data = user_data;

    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    check_head_commit_thread,
                                    check_head_commit_done,
                                    data);

    return 0;
}

/* Get folder permissions. */

void
http_folder_perm_req_free (HttpFolderPermReq *req)
{
    if (!req)
        return;
    g_free (req->token);
    g_free (req);
}

void
http_folder_perm_res_free (HttpFolderPermRes *res)
{
    GList *ptr;

    if (!res)
        return;
    for (ptr = res->user_perms; ptr; ptr = ptr->next)
        folder_perm_free ((FolderPerm *)ptr->data);
    for (ptr = res->group_perms; ptr; ptr = ptr->next)
        folder_perm_free ((FolderPerm *)ptr->data);
    g_free (res);
}

typedef struct {
    char *host;
    GList *requests;
    HttpGetFolderPermsCallback callback;
    void *user_data;

    gboolean success;
    GList *results;
} GetFolderPermsData;

/* Make sure the path starts with '/' but doesn't end with '/'. */
static char *
canonical_perm_path (const char *path)
{
    int len = strlen(path);
    char *copy, *ret;

    if (strcmp (path, "/") == 0)
        return g_strdup(path);

    if (path[0] == '/' && path[len-1] != '/')
        return g_strdup(path);

    copy = g_strdup(path);

    if (copy[len-1] == '/')
        copy[len-1] = 0;

    if (copy[0] != '/')
        ret = g_strconcat ("/", copy, NULL);
    else
        ret = copy;

    return ret;
}

static GList *
parse_permission_list (json_t *array, gboolean *error)
{
    GList *ret = NULL, *ptr;
    json_t *object, *member;
    size_t n;
    int i;
    FolderPerm *perm;
    const char *str;

    *error = FALSE;

    n = json_array_size (array);
    for (i = 0; i < n; ++i) {
        object = json_array_get (array, i);

        perm = g_new0 (FolderPerm, 1);

        member = json_object_get (object, "path");
        if (!member) {
            seaf_warning ("Invalid folder perm response format: no path.\n");
            *error = TRUE;
            goto out;
        }
        str = json_string_value(member);
        if (!str) {
            seaf_warning ("Invalid folder perm response format: invalid path.\n");
            *error = TRUE;
            goto out;
        }
        perm->path = canonical_perm_path (str);

        member = json_object_get (object, "permission");
        if (!member) {
            seaf_warning ("Invalid folder perm response format: no permission.\n");
            *error = TRUE;
            goto out;
        }
        str = json_string_value(member);
        if (!str) {
            seaf_warning ("Invalid folder perm response format: invalid permission.\n");
            *error = TRUE;
            goto out;
        }
        perm->permission = g_strdup(str);

        ret = g_list_append (ret, perm);
    }

out:
    if (*error) {
        for (ptr = ret; ptr; ptr = ptr->next)
            folder_perm_free ((FolderPerm *)ptr->data);
        g_list_free (ret);
        ret = NULL;
    }

    return ret;
}

static int
parse_folder_perms (const char *rsp_content, int rsp_size, GetFolderPermsData *data)
{
    json_t *array = NULL, *object, *member;
    json_error_t jerror;
    size_t n;
    int i;
    GList *results = NULL, *ptr;
    HttpFolderPermRes *res;
    const char *repo_id;
    int ret = 0;
    gboolean error;

    array = json_loadb (rsp_content, rsp_size, 0, &jerror);
    if (!array) {
        seaf_warning ("Parse response failed: %s.\n", jerror.text);
        return -1;
    }

    n = json_array_size (array);
    for (i = 0; i < n; ++i) {
        object = json_array_get (array, i);

        res = g_new0 (HttpFolderPermRes, 1);

        member = json_object_get (object, "repo_id");
        if (!member) {
            seaf_warning ("Invalid folder perm response format: no repo_id.\n");
            ret = -1;
            goto out;
        }
        repo_id = json_string_value(member);
        if (strlen(repo_id) != 36) {
            seaf_warning ("Invalid folder perm response format: invalid repo_id.\n");
            ret = -1;
            goto out;
        }
        memcpy (res->repo_id, repo_id, 36);
 
        member = json_object_get (object, "ts");
        if (!member) {
            seaf_warning ("Invalid folder perm response format: no timestamp.\n");
            ret = -1;
            goto out;
        }
        res->timestamp = json_integer_value (member);

        member = json_object_get (object, "user_perms");
        if (!member) {
            seaf_warning ("Invalid folder perm response format: no user_perms.\n");
            ret = -1;
            goto out;
        }
        res->user_perms = parse_permission_list (member, &error);
        if (error) {
            ret = -1;
            goto out;
        }

        member = json_object_get (object, "group_perms");
        if (!member) {
            seaf_warning ("Invalid folder perm response format: no group_perms.\n");
            ret = -1;
            goto out;
        }
        res->group_perms = parse_permission_list (member, &error);
        if (error) {
            ret = -1;
            goto out;
        }

        results = g_list_append (results, res);
    }

out:
    json_decref (array);

    if (ret < 0) {
        for (ptr = results; ptr; ptr = ptr->next)
            http_folder_perm_res_free ((HttpFolderPermRes *)ptr->data);
        g_list_free (results);
    } else
        data->results = results;

    return ret;
}

static char *
compose_get_folder_perms_request (GList *requests)
{
    GList *ptr;
    HttpFolderPermReq *req;
    json_t *object, *array;
    char *req_str = NULL;

    array = json_array ();

    for (ptr = requests; ptr; ptr = ptr->next) {
        req = ptr->data;

        object = json_object ();
        json_object_set_new (object, "repo_id", json_string(req->repo_id));
        json_object_set_new (object, "token", json_string(req->token));
        json_object_set_new (object, "ts", json_integer(req->timestamp));

        json_array_append_new (array, object);
    }

    req_str = json_dumps (array, 0);
    if (!req_str) {
        seaf_warning ("Faile to json_dumps.\n");
    }

    json_decref (array);
    return req_str;
}

static void *
get_folder_perms_thread (void *vdata)
{
    GetFolderPermsData *data = vdata;
    HttpTxPriv *priv = seaf->http_tx_mgr->priv;
    ConnectionPool *pool;
    Connection *conn;
    CURL *curl;
    char *url;
    char *req_content = NULL;
    int status;
    char *rsp_content = NULL;
    gint64 rsp_size;
    GList *ptr;

    pool = find_connection_pool (priv, data->host);
    if (!pool) {
        seaf_warning ("Failed to create connection pool for host %s.\n", data->host);
        return vdata;
    }

    conn = connection_pool_get_connection (pool);
    if (!conn) {
        seaf_warning ("Failed to get connection to host %s.\n", data->host);
        return vdata;
    }

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/repo/folder-perm", data->host);

    req_content = compose_get_folder_perms_request (data->requests);
    if (!req_content)
        goto out;

    if (http_post (curl, url, NULL, req_content, strlen(req_content),
                   &status, &rsp_content, &rsp_size) < 0)
        goto out;

    if (status == HTTP_OK) {
        if (parse_folder_perms (rsp_content, rsp_size, data) < 0)
            goto out;
        data->success = TRUE;
    } else {
        seaf_warning ("Bad response code for GET %s: %d.\n", url, status);
    }

out:
    for (ptr = data->requests; ptr; ptr = ptr->next)
        http_folder_perm_req_free ((HttpFolderPermReq *)ptr->data);
    g_list_free (data->requests);

    g_free (url);
    g_free (req_content);
    g_free (rsp_content);
    connection_pool_return_connection (pool, conn);
    return vdata;
}

static void
get_folder_perms_done (void *vdata)
{
    GetFolderPermsData *data = vdata;
    HttpFolderPerms cb_data;

    memset (&cb_data, 0, sizeof(cb_data));
    cb_data.success = data->success;
    cb_data.results = data->results;

    data->callback (&cb_data, data->user_data);

    GList *ptr;
    for (ptr = data->results; ptr; ptr = ptr->next)
        http_folder_perm_res_free ((HttpFolderPermRes *)ptr->data);
    g_list_free (data->results);

    g_free (data->host);
    g_free (data);
}

int
http_tx_manager_get_folder_perms (HttpTxManager *manager,
                                  const char *host,
                                  GList *folder_perm_requests,
                                  HttpGetFolderPermsCallback callback,
                                  void *user_data)
{
    GetFolderPermsData *data = g_new0 (GetFolderPermsData, 1);

    data->host = g_strdup(host);
    data->requests = folder_perm_requests;
    data->callback = callback;
    data->user_data = user_data;

    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    get_folder_perms_thread,
                                    get_folder_perms_done,
                                    data);

    return 0;
}

static gboolean
remove_task_help (gpointer key, gpointer value, gpointer user_data)
{
    HttpTxTask *task = value;
    const char *repo_id = user_data;

    if (strcmp(task->repo_id, repo_id) != 0)
        return FALSE;

    return TRUE;
}

static void
clean_tasks_for_repo (HttpTxManager *manager, const char *repo_id)
{
    g_hash_table_foreach_remove (manager->priv->download_tasks,
                                 remove_task_help, (gpointer)repo_id);

    g_hash_table_foreach_remove (manager->priv->upload_tasks,
                                 remove_task_help, (gpointer)repo_id);
}

static int
check_permission (HttpTxTask *task, Connection *conn)
{
    CURL *curl;
    char *url;
    int status;
    int ret = 0;

    curl = conn->curl;

    const char *type = (task->type == HTTP_TASK_TYPE_DOWNLOAD) ? "download" : "upload";
    url = g_strdup_printf ("%s/seafhttp/repo/%s/permission-check/?op=%s",
                           task->host, task->repo_id, type);

    if (http_get (curl, url, task->token, &status, NULL, NULL, NULL, NULL) < 0) {
        task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto out;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for GET %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
    }

out:
    g_free (url);
    curl_easy_reset (curl);

    return ret;
}

/* Upload. */

static void *http_upload_thread (void *vdata);
static void http_upload_done (void *vdata);

int
http_tx_manager_add_upload (HttpTxManager *manager,
                            const char *repo_id,
                            int repo_version,
                            const char *host,
                            const char *token,
                            int protocol_version,
                            GError **error)
{
    HttpTxTask *task;
    SeafRepo *repo;

    if (!repo_id || !token || !host) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Empty argument(s)");
        return -1;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Repo not found");
        return -1;
    }

    clean_tasks_for_repo (manager, repo_id);

    task = http_tx_task_new (manager, repo_id, repo_version,
                             HTTP_TASK_TYPE_UPLOAD, FALSE,
                             host, token, NULL, NULL);

    task->protocol_version = protocol_version;

    task->state = TASK_STATE_NORMAL;

    g_hash_table_insert (manager->priv->upload_tasks,
                         g_strdup(repo_id),
                         task);

    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    http_upload_thread,
                                    http_upload_done,
                                    task);

    return 0;
}

typedef struct {
    HttpTxTask *task;
    gint64 delta;
} CalcQuotaDeltaData;

static int
check_quota_diff_files (int n, const char *basedir, SeafDirent *files[], void *vdata)
{
    CalcQuotaDeltaData *data = vdata;
    SeafDirent *file1 = files[0];
    SeafDirent *file2 = files[1];
    gint64 size1, size2;

    if (file1 && file2) {
        size1 = file1->size;
        size2 = file2->size;
        data->delta += (size1 - size2);
    } else if (file1 && !file2) {
        data->delta += file1->size;
    } else if (!file1 && file2) {
        data->delta -= file2->size;
    }

    return 0;
}

static int
check_quota_diff_dirs (int n, const char *basedir, SeafDirent *dirs[], void *data,
                       gboolean *recurse)
{
    /* Do nothing */
    return 0;
}

static int
calculate_upload_size_delta (HttpTxTask *task, gint64 *delta)
{
    int ret = 0;
    SeafBranch *local = NULL, *master = NULL;
    SeafCommit *local_head = NULL, *master_head = NULL;

    local = seaf_branch_manager_get_branch (seaf->branch_mgr, task->repo_id, "local");
    if (!local) {
        seaf_warning ("Branch local not found for repo %.8s.\n", task->repo_id);
        ret = -1;
        goto out;
    }
    master = seaf_branch_manager_get_branch (seaf->branch_mgr, task->repo_id, "master");
    if (!master) {
        seaf_warning ("Branch master not found for repo %.8s.\n", task->repo_id);
        ret = -1;
        goto out;
    }

    local_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id, task->repo_version,
                                                 local->commit_id);
    if (!local_head) {
        seaf_warning ("Local head commit not found for repo %.8s.\n",
                      task->repo_id);
        ret = -1;
        goto out;
    }
    master_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id, task->repo_version,
                                                 master->commit_id);
    if (!master_head) {
        seaf_warning ("Master head commit not found for repo %.8s.\n",
                      task->repo_id);
        ret = -1;
        goto out;
    }

    CalcQuotaDeltaData data;
    memset (&data, 0, sizeof(data));
    data.task = task;

    DiffOptions opts;
    memset (&opts, 0, sizeof(opts));
    memcpy (opts.store_id, task->repo_id, 36);
    opts.version = task->repo_version;
    opts.file_cb = check_quota_diff_files;
    opts.dir_cb = check_quota_diff_dirs;
    opts.data = &data;

    const char *trees[2];
    trees[0] = local_head->root_id;
    trees[1] = master_head->root_id;
    if (diff_trees (2, trees, &opts) < 0) {
        seaf_warning ("Failed to diff local and master head for repo %.8s.\n",
                      task->repo_id);
        ret = -1;
        goto out;
    }

    *delta = data.delta;

out:
    seaf_branch_unref (local);
    seaf_branch_unref (master);
    seaf_commit_unref (local_head);
    seaf_commit_unref (master_head);

    return ret;
}

static int
check_quota (HttpTxTask *task, Connection *conn)
{
    CURL *curl;
    char *url;
    int status;
    gint64 delta = 0;
    int ret = 0;

    if (calculate_upload_size_delta (task, &delta) < 0) {
        seaf_warning ("Failed to calculate upload size delta for repo %s.\n",
                      task->repo_id);
        task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
        return -1;
    }

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/repo/%s/quota-check/?delta=%"G_GINT64_FORMAT"",
                           task->host, task->repo_id, delta);

    if (http_get (curl, url, task->token, &status, NULL, NULL, NULL, NULL) < 0) {
        task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto out;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for GET %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
    }

out:
    g_free (url);
    curl_easy_reset (curl);

    return ret;
}

static int
send_commit_object (HttpTxTask *task, Connection *conn)
{
    CURL *curl;
    char *url;
    int status;
    char *data;
    int len;
    int ret = 0;

    if (seaf_obj_store_read_obj (seaf->commit_mgr->obj_store,
                                 task->repo_id, task->repo_version,
                                 task->head, (void**)&data, &len) < 0) {
        g_warning ("Failed to read commit %s.\n", task->head);
        task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
        return -1;
    }

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/repo/%s/commit/%s",
                           task->host, task->repo_id, task->head);

    if (http_put (curl, url, task->token,
                  data, len,
                  NULL, NULL,
                  &status, NULL, NULL) < 0) {
        task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto out;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for PUT %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
    }

out:
    g_free (url);
    curl_easy_reset (curl);
    g_free (data);

    return ret;
}

typedef struct {
    GList **pret;
    GHashTable *checked_objs;
} CalcFsListData;

inline static gboolean
dirent_same (SeafDirent *denta, SeafDirent *dentb)
{
    return (strcmp (dentb->id, denta->id) == 0 && denta->mode == dentb->mode);
}

static int
collect_file_ids (int n, const char *basedir, SeafDirent *files[], void *vdata)
{
    SeafDirent *file1 = files[0];
    SeafDirent *file2 = files[1];
    CalcFsListData *data = vdata;
    GList **pret = data->pret;
    int dummy;

    if (!file1 || strcmp (file1->id, EMPTY_SHA1) == 0)
        return 0;

    if (g_hash_table_lookup (data->checked_objs, file1->id))
        return 0;

    if (!file2 || !dirent_same (file1, file2)) {
        *pret = g_list_prepend (*pret, g_strdup(file1->id));
        g_hash_table_insert (data->checked_objs, g_strdup(file1->id), &dummy);
    }

    return 0;
}

static int
collect_dir_ids (int n, const char *basedir, SeafDirent *dirs[], void *vdata,
                 gboolean *recurse)
{
    SeafDirent *dir1 = dirs[0];
    SeafDirent *dir2 = dirs[1];
    CalcFsListData *data = vdata;
    GList **pret = data->pret;
    int dummy;

    if (!dir1 || strcmp (dir1->id, EMPTY_SHA1) == 0)
        return 0;

    if (g_hash_table_lookup (data->checked_objs, dir1->id))
        return 0;

    if (!dir2 || !dirent_same (dir1, dir2)) {
        *pret = g_list_prepend (*pret, g_strdup(dir1->id));
        g_hash_table_insert (data->checked_objs, g_strdup(dir1->id), &dummy);
    }

    return 0;
}

static GList *
calculate_send_fs_object_list (HttpTxTask *task)
{
    GList *ret = NULL;
    SeafBranch *local = NULL, *master = NULL;
    SeafCommit *local_head = NULL, *master_head = NULL;
    GList *ptr;

    local = seaf_branch_manager_get_branch (seaf->branch_mgr, task->repo_id, "local");
    if (!local) {
        seaf_warning ("Branch local not found for repo %.8s.\n", task->repo_id);
        goto out;
    }
    master = seaf_branch_manager_get_branch (seaf->branch_mgr, task->repo_id, "master");
    if (!master) {
        seaf_warning ("Branch master not found for repo %.8s.\n", task->repo_id);
        goto out;
    }

    local_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id, task->repo_version,
                                                 local->commit_id);
    if (!local_head) {
        seaf_warning ("Local head commit not found for repo %.8s.\n",
                      task->repo_id);
        goto out;
    }
    master_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                  task->repo_id, task->repo_version,
                                                  master->commit_id);
    if (!master_head) {
        seaf_warning ("Master head commit not found for repo %.8s.\n",
                      task->repo_id);
        goto out;
    }

    /* Diff won't traverse the root object itself. */
    if (strcmp (local_head->root_id, master_head->root_id) != 0)
        ret = g_list_prepend (ret, g_strdup(local_head->root_id));

    CalcFsListData *data = g_new0(CalcFsListData, 1);
    data->pret = &ret;
    data->checked_objs = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, NULL);

    DiffOptions opts;
    memset (&opts, 0, sizeof(opts));
    memcpy (opts.store_id, task->repo_id, 36);
    opts.version = task->repo_version;
    opts.file_cb = collect_file_ids;
    opts.dir_cb = collect_dir_ids;
    opts.data = data;

    const char *trees[2];
    trees[0] = local_head->root_id;
    trees[1] = master_head->root_id;
    if (diff_trees (2, trees, &opts) < 0) {
        seaf_warning ("Failed to diff local and master head for repo %.8s.\n",
                      task->repo_id);
        for (ptr = ret; ptr; ptr = ptr->next)
            g_free (ptr->data);
        ret = NULL;
    }

    g_hash_table_destroy (data->checked_objs);
    g_free (data);

out:
    seaf_branch_unref (local);
    seaf_branch_unref (master);
    seaf_commit_unref (local_head);
    seaf_commit_unref (master_head);
    return ret;
}

#define ID_LIST_SEGMENT_N 1000

static int
upload_check_id_list_segment (HttpTxTask *task, Connection *conn, const char *url,
                              GList **send_id_list, GList **recv_id_list)
{
    json_t *array;
    json_error_t jerror;
    char *obj_id;
    int n_sent = 0;
    char *data = NULL;
    int len;
    CURL *curl;
    int status;
    char *rsp_content = NULL;
    gint64 rsp_size;
    int ret = 0;

    /* Convert object id list to JSON format. */

    array = json_array ();

    while (*send_id_list != NULL) {
        obj_id = (*send_id_list)->data;
        json_array_append_new (array, json_string(obj_id));

        *send_id_list = g_list_delete_link (*send_id_list, *send_id_list);
        g_free (obj_id);

        if (++n_sent >= ID_LIST_SEGMENT_N)
            break;
    }

    seaf_debug ("Check %d ids for %s:%s.\n",
                n_sent, task->host, task->repo_id);

    data = json_dumps (array, 0);
    len = strlen(data);
    json_decref (array);

    /* Send fs object id list. */

    curl = conn->curl;

    if (http_post (curl, url, task->token,
                   data, len,
                   &status, &rsp_content, &rsp_size) < 0) {
        task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto out;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for POST %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
        goto out;
    }

    /* Process needed object id list. */

    array = json_loadb (rsp_content, rsp_size, 0, &jerror);
    if (!array) {
        seaf_warning ("Invalid JSON response from the server: %s.\n", jerror.text);
        task->error = HTTP_TASK_ERR_SERVER;
        ret = -1;
        goto out;
    }

    int i;
    size_t n = json_array_size (array);
    json_t *str;

    seaf_debug ("%lu objects or blocks are needed for %s:%s.\n",
                n, task->host, task->repo_id);

    for (i = 0; i < n; ++i) {
        str = json_array_get (array, i);
        if (!str) {
            seaf_warning ("Invalid JSON response from the server.\n");
            json_decref (array);
            ret = -1;
            goto out;
        }

        *recv_id_list = g_list_prepend (*recv_id_list, g_strdup(json_string_value(str)));
    }

    json_decref (array);

out:
    curl_easy_reset (curl);
    g_free (data);
    g_free (rsp_content);

    return ret;
}

#define MAX_OBJECT_PACK_SIZE (1 << 20) /* 1MB */

typedef struct {
    char obj_id[40];
    guint32 obj_size;
    guint8 object[0];
} __attribute__((__packed__)) ObjectHeader;

static int
send_fs_objects (HttpTxTask *task, Connection *conn, GList **send_fs_list)
{
    struct evbuffer *buf;
    ObjectHeader hdr;
    char *obj_id;
    char *data;
    int len;
    int total_size;
    unsigned char *package;
    CURL *curl;
    char *url;
    int status;
    int ret = 0;
    int n_sent = 0;

    buf = evbuffer_new ();

    while (*send_fs_list != NULL) {
        obj_id = (*send_fs_list)->data;

        if (seaf_obj_store_read_obj (seaf->fs_mgr->obj_store,
                                     task->repo_id, task->repo_version,
                                     obj_id, (void **)&data, &len) < 0) {
            seaf_warning ("Failed to read fs object %s in repo %s.\n",
                          obj_id, task->repo_id);
            task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
            ret = -1;
            goto out;
        }

        ++n_sent;

        memcpy (hdr.obj_id, obj_id, 40);
        hdr.obj_size = htonl (len);

        evbuffer_add (buf, &hdr, sizeof(hdr));
        evbuffer_add (buf, data, len);

        g_free (data);
        *send_fs_list = g_list_delete_link (*send_fs_list, *send_fs_list);
        g_free (obj_id);

        total_size = evbuffer_get_length (buf);
        if (total_size >= MAX_OBJECT_PACK_SIZE)
            break;
    }

    seaf_debug ("Sending %d fs objects for %s:%s.\n",
                n_sent, task->host, task->repo_id);

    package = evbuffer_pullup (buf, -1);

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/repo/%s/recv-fs/",
                           task->host, task->repo_id);

    if (http_post (curl, url, task->token,
                   package, evbuffer_get_length(buf),
                   &status, NULL, NULL) < 0) {
        task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto out;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for POST %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
    }

out:
    g_free (url);
    evbuffer_free (buf);
    curl_easy_reset (curl);

    return ret;
}

typedef struct {
    GList *block_list;
    GHashTable *added_blocks;
    HttpTxTask *task;
} CalcBlockListData;

static void
add_to_block_list (GList **block_list, GHashTable *added_blocks, const char *block_id)
{
    int dummy;

    if (g_hash_table_lookup (added_blocks, block_id))
        return;

    *block_list = g_list_prepend (*block_list, g_strdup(block_id));
    g_hash_table_insert (added_blocks, g_strdup(block_id), &dummy);
}

static int
block_list_diff_files (int n, const char *basedir, SeafDirent *files[], void *vdata)
{
    SeafDirent *file1 = files[0];
    SeafDirent *file2 = files[1];
    CalcBlockListData *data = vdata;
    HttpTxTask *task = data->task;
    Seafile *f1 = NULL, *f2 = NULL;
    int i;

    if (file1 && strcmp (file1->id, EMPTY_SHA1) != 0) {
        if (!file2) {
            f1 = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                              task->repo_id, task->repo_version,
                                              file1->id);
            if (!f1) {
                seaf_warning ("Failed to get seafile object %s.\n", file1->id);
                return -1;
            }
            for (i = 0; i < f1->n_blocks; ++i)
                add_to_block_list (&data->block_list, data->added_blocks,
                                   f1->blk_sha1s[i]);
            seafile_unref (f1);
        } else if (strcmp (file1->id, file2->id) != 0) {
            f1 = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                              task->repo_id, task->repo_version,
                                              file1->id);
            if (!f1) {
                seaf_warning ("Failed to get seafile object %s.\n", file1->id);
                return -1;
            }
            f2 = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                              task->repo_id, task->repo_version,
                                              file2->id);
            if (!f2) {
                seafile_unref (f1);
                seaf_warning ("Failed to get seafile object %s.\n", file2->id);
                return -1;
            }

            GHashTable *h = g_hash_table_new (g_str_hash, g_str_equal);
            int dummy;
            for (i = 0; i < f2->n_blocks; ++i)
                g_hash_table_insert (h, f2->blk_sha1s[i], &dummy);

            for (i = 0; i < f1->n_blocks; ++i)
                if (!g_hash_table_lookup (h, f1->blk_sha1s[i]))
                    add_to_block_list (&data->block_list, data->added_blocks,
                                       f1->blk_sha1s[i]);

            seafile_unref (f1);
            seafile_unref (f2);
            g_hash_table_destroy (h);
        }
    }

    return 0;
}

static int
block_list_diff_dirs (int n, const char *basedir, SeafDirent *dirs[], void *data,
                      gboolean *recurse)
{
    /* Do nothing */
    return 0;
}

static int
calculate_block_list (HttpTxTask *task, GList **plist)
{
    int ret = 0;
    SeafBranch *local = NULL, *master = NULL;
    SeafCommit *local_head = NULL, *master_head = NULL;

    local = seaf_branch_manager_get_branch (seaf->branch_mgr, task->repo_id, "local");
    if (!local) {
        seaf_warning ("Branch local not found for repo %.8s.\n", task->repo_id);
        ret = -1;
        goto out;
    }
    master = seaf_branch_manager_get_branch (seaf->branch_mgr, task->repo_id, "master");
    if (!master) {
        seaf_warning ("Branch master not found for repo %.8s.\n", task->repo_id);
        ret = -1;
        goto out;
    }

    local_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id, task->repo_version,
                                                 local->commit_id);
    if (!local_head) {
        seaf_warning ("Local head commit not found for repo %.8s.\n",
                      task->repo_id);
        ret = -1;
        goto out;
    }
    master_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id, task->repo_version,
                                                 master->commit_id);
    if (!master_head) {
        seaf_warning ("Master head commit not found for repo %.8s.\n",
                      task->repo_id);
        ret = -1;
        goto out;
    }

    CalcBlockListData data;
    memset (&data, 0, sizeof(data));
    data.added_blocks = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    data.task = task;

    DiffOptions opts;
    memset (&opts, 0, sizeof(opts));
    memcpy (opts.store_id, task->repo_id, 36);
    opts.version = task->repo_version;
    opts.file_cb = block_list_diff_files;
    opts.dir_cb = block_list_diff_dirs;
    opts.data = &data;

    const char *trees[2];
    trees[0] = local_head->root_id;
    trees[1] = master_head->root_id;
    if (diff_trees (2, trees, &opts) < 0) {
        seaf_warning ("Failed to diff local and master head for repo %.8s.\n",
                      task->repo_id);
        g_hash_table_destroy (data.added_blocks);

        GList *ptr;
        for (ptr = data.block_list; ptr; ptr = ptr->next)
            g_free (ptr->data);

        ret = -1;
        goto out;
    }

    g_hash_table_destroy (data.added_blocks);
    *plist = data.block_list;

out:
    seaf_branch_unref (local);
    seaf_branch_unref (master);
    seaf_commit_unref (local_head);
    seaf_commit_unref (master_head);
    return ret;
}

typedef struct {
    char block_id[41];
    BlockHandle *block;
    HttpTxTask *task;
} SendBlockData;

static size_t
send_block_callback (void *ptr, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size *nmemb;
    SendBlockData *data = userp;
    HttpTxTask *task = data->task;
    size_t n;

    if (task->state == HTTP_TASK_STATE_CANCELED)
        return CURL_READFUNC_ABORT;

    n = seaf_block_manager_read_block (seaf->block_mgr,
                                       data->block,
                                       ptr, realsize);
    if (n < 0) {
        seaf_warning ("Failed to read block %s in repo %.8s.\n",
                      data->block_id, task->repo_id);
        task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
        return CURL_READFUNC_ABORT;
    }

    /* Update global transferred bytes. */
    g_atomic_int_add (&(seaf->sync_mgr->sent_bytes), n);

    /* If uploaded bytes exceeds the limit, wait until the counter
     * is reset. We check the counter every 100 milliseconds, so we
     * can waste up to 100 milliseconds without sending data after
     * the counter is reset.
     */
    while (1) {
        gint sent = g_atomic_int_get(&(seaf->sync_mgr->sent_bytes));
        if (seaf->sync_mgr->upload_limit > 0 &&
            sent > seaf->sync_mgr->upload_limit)
            /* 100 milliseconds */
            g_usleep (100000);
        else
            break;
    }

    return n;
}

static int
send_block (HttpTxTask *task, Connection *conn, const char *block_id)
{
    CURL *curl;
    char *url;
    int status;
    BlockMetadata *bmd;
    BlockHandle *block;
    int ret = 0;

    bmd = seaf_block_manager_stat_block (seaf->block_mgr,
                                         task->repo_id, task->repo_version,
                                         block_id);
    if (!bmd) {
        seaf_warning ("Failed to stat block %s in repo %s.\n",
                      block_id, task->repo_id);
        return -1;
    }

    block = seaf_block_manager_open_block (seaf->block_mgr,
                                           task->repo_id, task->repo_version,
                                           block_id, BLOCK_READ);
    if (!block) {
        seaf_warning ("Failed to open block %s in repo %s.\n",
                      block_id, task->repo_id);
        g_free (bmd);
        return -1;
    }

    SendBlockData data;
    memset (&data, 0, sizeof(data));
    memcpy (data.block_id, block_id, 40);
    data.block = block;
    data.task = task;

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/repo/%s/block/%s",
                           task->host, task->repo_id, block_id);

    if (http_put (curl, url, task->token,
                  NULL, bmd->size,
                  send_block_callback, &data,
                  &status, NULL, NULL) < 0) {
        if (task->state == HTTP_TASK_STATE_CANCELED)
            goto out;

        if (task->error == TASK_OK)
            task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto out;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for PUT %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
    }

out:
    g_free (url);
    curl_easy_reset (curl);
    g_free (bmd);
    seaf_block_manager_close_block (seaf->block_mgr, block);
    seaf_block_manager_block_handle_free (seaf->block_mgr, block);

    return ret;
}

static int
update_branch (HttpTxTask *task, Connection *conn)
{
    CURL *curl;
    char *url;
    int status;
    int ret = 0;

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/repo/%s/commit/HEAD/?head=%s",
                           task->host, task->repo_id, task->head);

    if (http_put (curl, url, task->token,
                  NULL, 0,
                  NULL, NULL,
                  &status, NULL, NULL) < 0) {
        task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto out;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for PUT %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
    }

out:
    g_free (url);
    curl_easy_reset (curl);

    return ret;
}

static void
update_master_branch (HttpTxTask *task)
{
    SeafBranch *branch;
    branch = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                             task->repo_id,
                                             "master");
    if (!branch) {
        branch = seaf_branch_new ("master", task->repo_id, task->head);
        seaf_branch_manager_add_branch (seaf->branch_mgr, branch);
        seaf_branch_unref (branch);
    } else {
        seaf_branch_set_commit (branch, task->head);
        seaf_branch_manager_update_branch (seaf->branch_mgr, branch);
        seaf_branch_unref (branch);
    }
}

static void *
http_upload_thread (void *vdata)
{
    HttpTxTask *task = vdata;
    HttpTxPriv *priv = seaf->http_tx_mgr->priv;
    ConnectionPool *pool;
    Connection *conn = NULL;
    char *url = NULL;
    GList *send_fs_list = NULL, *needed_fs_list = NULL;
    GList *block_list = NULL, *needed_block_list = NULL;
    GList *ptr;

    SeafBranch *local = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                        task->repo_id, "local");
    if (!local) {
        seaf_warning ("Failed to get branch local of repo %.8s.\n", task->repo_id);
        task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
        goto out;
    }
    memcpy (task->head, local->commit_id, 40);
    seaf_branch_unref (local);

    pool = find_connection_pool (priv, task->host);
    if (!pool) {
        seaf_warning ("Failed to create connection pool for host %s.\n", task->host);
        task->error = HTTP_TASK_ERR_NOT_ENOUGH_MEMORY;
        goto out;
    }

    conn = connection_pool_get_connection (pool);
    if (!conn) {
        seaf_warning ("Failed to get connection to host %s.\n", task->host);
        task->error = HTTP_TASK_ERR_NOT_ENOUGH_MEMORY;
        goto out;
    }

    seaf_message ("Upload with HTTP sync protocol version %d.\n",
                  task->protocol_version);

    transition_state (task, task->state, HTTP_TASK_RT_STATE_CHECK);

    if (check_permission (task, conn) < 0) {
        seaf_warning ("Upload permission denied for repo %.8s on server %s.\n",
                      task->repo_id, task->host);
        goto out;
    }

    if (check_quota (task, conn) < 0) {
        seaf_warning ("Not enough quota for repo %.8s on server %s.\n",
                      task->repo_id, task->host);
        goto out;
    }

    if (task->state == HTTP_TASK_STATE_CANCELED)
        goto out;

    transition_state (task, task->state, HTTP_TASK_RT_STATE_COMMIT);

    if (send_commit_object (task, conn) < 0) {
        seaf_warning ("Failed to send head commit for repo %.8s.\n", task->repo_id);
        goto out;
    }

    if (task->state == HTTP_TASK_STATE_CANCELED)
        goto out;

    transition_state (task, task->state, HTTP_TASK_RT_STATE_FS);

    send_fs_list = calculate_send_fs_object_list (task);
    if (!send_fs_list) {
        seaf_warning ("Failed to calculate fs object list for repo %.8s.\n",
                      task->repo_id);
        task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
        goto out;
    }

    url = g_strdup_printf ("%s/seafhttp/repo/%s/check-fs/",
                           task->host, task->repo_id);

    while (send_fs_list != NULL) {
        if (upload_check_id_list_segment (task, conn, url,
                                          &send_fs_list, &needed_fs_list) < 0) {
            seaf_warning ("Failed to check fs list for repo %.8s.\n", task->repo_id);
            goto out;
        }

        if (task->state == HTTP_TASK_STATE_CANCELED)
            goto out;
    }
    g_free (url);
    url = NULL;

    while (needed_fs_list != NULL) {
        if (send_fs_objects (task, conn, &needed_fs_list) < 0) {
            seaf_warning ("Failed to send fs objects for repo %.8s.\n", task->repo_id);
            goto out;
        }

        if (task->state == HTTP_TASK_STATE_CANCELED)
            goto out;
    }

    transition_state (task, task->state, HTTP_TASK_RT_STATE_BLOCK);

    if (calculate_block_list (task, &block_list) < 0) {
        seaf_warning ("Failed to calculate block list for repo %.8s.\n",
                      task->repo_id);
        task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
        goto out;
    }

    url = g_strdup_printf ("%s/seafhttp/repo/%s/check-blocks/",
                           task->host, task->repo_id);

    while (block_list != NULL) {
        if (upload_check_id_list_segment (task, conn, url,
                                          &block_list, &needed_block_list) < 0) {
            seaf_warning ("Failed to check block list for repo %.8s.\n",
                          task->repo_id);
            goto out;
        }

        if (task->state == HTTP_TASK_STATE_CANCELED)
            goto out;
    }
    g_free (url);
    url = NULL;

    task->n_blocks = g_list_length (needed_block_list);

    seaf_debug ("%d blocks to send for %s:%s.\n",
                task->n_blocks, task->host, task->repo_id);

    char *block_id;
    for (ptr = needed_block_list; ptr; ptr = ptr->next) {
        block_id = ptr->data;

        if (send_block (task, conn, block_id) < 0) {
            seaf_warning ("Failed to send block %s for repo %.8s.\n",
                          block_id, task->repo_id);
            goto out;
        }

        if (task->state == HTTP_TASK_STATE_CANCELED)
            goto out;

        ++(task->done_blocks);
    }

    transition_state (task, task->state, HTTP_TASK_RT_STATE_UPDATE_BRANCH);

    if (update_branch (task, conn) < 0) {
        seaf_warning ("Failed to update branch of repo %.8s.\n", task->repo_id);
        goto out;
    }

    /* After successful upload, the cached 'master' branch should be updated to
     * the head commit of 'local' branch.
     */
    update_master_branch (task);

out:
    string_list_free (send_fs_list);
    string_list_free (needed_fs_list);
    string_list_free (block_list);
    string_list_free (needed_block_list);

    g_free (url);

    connection_pool_return_connection (pool, conn);

    return vdata;
}

static void
http_upload_done (void *vdata)
{
    HttpTxTask *task = vdata;

    if (task->error != HTTP_TASK_OK)
        transition_state (task, HTTP_TASK_STATE_ERROR, HTTP_TASK_RT_STATE_FINISHED);
    else if (task->state == HTTP_TASK_STATE_CANCELED)
        transition_state (task, task->state, HTTP_TASK_RT_STATE_FINISHED);
    else
        transition_state (task, HTTP_TASK_STATE_FINISHED, HTTP_TASK_RT_STATE_FINISHED);
}

/* Download */

static void *http_download_thread (void *vdata);
static void http_download_done (void *vdata);

int
http_tx_manager_add_download (HttpTxManager *manager,
                              const char *repo_id,
                              int repo_version,
                              const char *host,
                              const char *token,
                              const char *server_head_id,
                              gboolean is_clone,
                              const char *passwd,
                              const char *worktree,
                              int protocol_version,
                              GError **error)
{
    HttpTxTask *task;
    SeafRepo *repo;

    if (!repo_id || !token || !host || !server_head_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Empty argument(s)");
        return -1;
    }

    if (!is_clone) {
        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!repo) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Repo not found");
            return -1;
        }
    }

    clean_tasks_for_repo (manager, repo_id);

    task = http_tx_task_new (manager, repo_id, repo_version,
                             HTTP_TASK_TYPE_DOWNLOAD, is_clone,
                             host, token, passwd, worktree);

    memcpy (task->head, server_head_id, 40);
    task->protocol_version = protocol_version;

    task->state = TASK_STATE_NORMAL;

    g_hash_table_insert (manager->priv->download_tasks,
                         g_strdup(repo_id),
                         task);

    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    http_download_thread,
                                    http_download_done,
                                    task);

    return 0;
}

static int
get_commit_object (HttpTxTask *task, Connection *conn)
{
    CURL *curl;
    char *url;
    int status;
    char *rsp_content = NULL;
    gint64 rsp_size;
    int ret = 0;

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/repo/%s/commit/%s",
                           task->host, task->repo_id, task->head);

    if (http_get (curl, url, task->token, &status,
                  &rsp_content, &rsp_size,
                  NULL, NULL) < 0) {
        task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto out;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for GET %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
        goto out;
    }

    int rc = seaf_obj_store_write_obj (seaf->commit_mgr->obj_store,
                                       task->repo_id, task->repo_version,
                                       task->head,
                                       rsp_content,
                                       rsp_size,
                                       FALSE);
    if (rc < 0) {
        seaf_warning ("Failed to save commit %s in repo %.8s.\n",
                      task->head, task->repo_id);
        task->error = HTTP_TASK_ERR_WRITE_LOCAL_DATA;
        ret = -1;
    }

out:
    g_free (url);
    g_free (rsp_content);
    curl_easy_reset (curl);

    return ret;
}

static int
get_needed_fs_id_list (HttpTxTask *task, Connection *conn, GList **fs_id_list)
{
    SeafBranch *master;
    CURL *curl;
    char *url = NULL;
    int status;
    char *rsp_content = NULL;
    gint64 rsp_size;
    int ret = 0;
    json_t *array;
    json_error_t jerror;
    const char *obj_id;

    if (!task->is_clone) {
        master = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                 task->repo_id,
                                                 "master");
        if (!master) {
            seaf_warning ("Failed to get branch master for repo %.8s.\n",
                          task->repo_id);
            return -1;
        }

        url = g_strdup_printf ("%s/seafhttp/repo/%s/fs-id-list/"
                               "?server-head=%s&client-head=%s",
                               task->host, task->repo_id,
                               task->head, master->commit_id);

        seaf_branch_unref (master);
    } else {
        url = g_strdup_printf ("%s/seafhttp/repo/%s/fs-id-list/?server-head=%s",
                               task->host, task->repo_id, task->head);
    }

    curl = conn->curl;

    if (http_get (curl, url, task->token, &status,
                  &rsp_content, &rsp_size,
                  NULL, NULL) < 0) {
        task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto out;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for GET %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
        goto out;
    }

    array = json_loadb (rsp_content, rsp_size, 0, &jerror);
    if (!array) {
        seaf_warning ("Invalid JSON response from the server: %s.\n", jerror.text);
        task->error = HTTP_TASK_ERR_SERVER;
        ret = -1;
        goto out;
    }

    int i;
    size_t n = json_array_size (array);
    json_t *str;

    seaf_debug ("Received fs object list size %lu from %s:%s.\n",
                n, task->host, task->repo_id);

    GHashTable *checked_objs = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                      g_free, NULL);

    for (i = 0; i < n; ++i) {
        str = json_array_get (array, i);
        if (!str) {
            seaf_warning ("Invalid JSON response from the server.\n");
            json_decref (array);
            string_list_free (*fs_id_list);
            ret = -1;
            goto out;
        }

        obj_id = json_string_value(str);

        if (g_hash_table_lookup (checked_objs, obj_id))
            continue;
        char *key = g_strdup(obj_id);
        g_hash_table_replace (checked_objs, key, key);

        if (!seaf_obj_store_obj_exists (seaf->fs_mgr->obj_store,
                                        task->repo_id, task->repo_version,
                                        obj_id)) {
            *fs_id_list = g_list_prepend (*fs_id_list, g_strdup(obj_id));
        } else if (task->is_clone) {
            gboolean io_error = FALSE;
            gboolean sound;
            sound = seaf_fs_manager_verify_object (seaf->fs_mgr,
                                                   task->repo_id, task->repo_version,
                                                   obj_id, FALSE, &io_error);
            if (!sound && !io_error)
                *fs_id_list = g_list_prepend (*fs_id_list, g_strdup(obj_id));
        }
    }

    json_decref (array);
    g_hash_table_destroy (checked_objs);

out:
    g_free (url);
    g_free (rsp_content);
    curl_easy_reset (curl);

    return ret;
}

#define GET_FS_OBJECT_N 100

static int
get_fs_objects (HttpTxTask *task, Connection *conn, GList **fs_list)
{
    json_t *array;
    json_error_t jerror;
    char *obj_id;
    int n_sent = 0;
    char *data = NULL;
    int len;
    CURL *curl;
    char *url = NULL;
    int status;
    char *rsp_content = NULL;
    gint64 rsp_size;
    int ret = 0;
    GHashTable *requested;

    /* Convert object id list to JSON format. */

    requested = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    array = json_array ();

    while (*fs_list != NULL) {
        obj_id = (*fs_list)->data;
        json_array_append_new (array, json_string(obj_id));

        *fs_list = g_list_delete_link (*fs_list, *fs_list);

        g_hash_table_replace (requested, obj_id, obj_id);

        if (++n_sent >= GET_FS_OBJECT_N)
            break;
    }

    seaf_debug ("Requesting %d fs objects from %s:%s.\n",
                n_sent, task->host, task->repo_id);

    data = json_dumps (array, 0);
    len = strlen(data);
    json_decref (array);

    /* Send fs object id list. */

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/repo/%s/pack-fs/", task->host, task->repo_id);

    if (http_post (curl, url, task->token,
                   data, len,
                   &status, &rsp_content, &rsp_size) < 0) {
        task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto out;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for POST %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
        goto out;
    }

    /* Save received fs objects. */

    int n_recv = 0;
    char *p = rsp_content;
    ObjectHeader *hdr = (ObjectHeader *)p;
    char recv_obj_id[41];
    int n = 0;
    int size;
    int rc;
    while (n < rsp_size) {
        memcpy (recv_obj_id, hdr->obj_id, 40);
        recv_obj_id[40] = 0;
        size = ntohl (hdr->obj_size);
        if (n + sizeof(ObjectHeader) + size > rsp_size) {
            seaf_warning ("Incomplete object package received for repo %.8s.\n",
                          task->repo_id);
            task->error = HTTP_TASK_ERR_SERVER;
            ret = -1;
            goto out;
        }

        ++n_recv;

        rc = seaf_obj_store_write_obj (seaf->fs_mgr->obj_store,
                                       task->repo_id, task->repo_version,
                                       recv_obj_id,
                                       hdr->object,
                                       size, FALSE);
        if (rc < 0) {
            seaf_warning ("Failed to write fs object %s in repo %.8s.\n",
                          recv_obj_id, task->repo_id);
            task->error = HTTP_TASK_ERR_WRITE_LOCAL_DATA;
            ret = -1;
            goto out;
        }

        g_hash_table_remove (requested, recv_obj_id);

        p += (sizeof(ObjectHeader) + size);
        n += (sizeof(ObjectHeader) + size);
        hdr = (ObjectHeader *)p;
    }

    seaf_debug ("Received %d fs objects from %s:%s.\n",
                n_recv, task->host, task->repo_id);

    /* The server may not return all the objects we requested.
     * So we need to add back the remaining object ids into fs_list.
     */
    GHashTableIter iter;
    gpointer key, value;
    g_hash_table_iter_init (&iter, requested);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        obj_id = key;
        *fs_list = g_list_prepend (*fs_list, g_strdup(obj_id));
    }
    g_hash_table_destroy (requested);

out:
    g_free (url);
    g_free (data);
    g_free (rsp_content);
    curl_easy_reset (curl);

    return ret;
}

typedef struct {
    char block_id[41];
    BlockHandle *block;
    HttpTxTask *task;
} GetBlockData;

static size_t
get_block_callback (void *ptr, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size *nmemb;
    SendBlockData *data = userp;
    HttpTxTask *task = data->task;
    size_t n;

    if (task->state == HTTP_TASK_STATE_CANCELED)
        return 0;

    n = seaf_block_manager_write_block (seaf->block_mgr,
                                        data->block,
                                        ptr, realsize);
    if (n < realsize) {
        seaf_warning ("Failed to write block %s in repo %.8s.\n",
                      data->block_id, task->repo_id);
        task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
        return n;
    }

    /* Update global transferred bytes. */
    g_atomic_int_add (&(seaf->sync_mgr->recv_bytes), n);

    /* If uploaded bytes exceeds the limit, wait until the counter
     * is reset. We check the counter every 100 milliseconds, so we
     * can waste up to 100 milliseconds without sending data after
     * the counter is reset.
     */
    while (1) {
        gint sent = g_atomic_int_get(&(seaf->sync_mgr->recv_bytes));
        if (seaf->sync_mgr->download_limit > 0 &&
            sent > seaf->sync_mgr->download_limit)
            /* 100 milliseconds */
            g_usleep (100000);
        else
            break;
    }

    return n;
}

int
get_block (HttpTxTask *task, Connection *conn, const char *block_id)
{
    CURL *curl;
    char *url;
    int status;
    BlockHandle *block;
    int ret = 0;

    block = seaf_block_manager_open_block (seaf->block_mgr,
                                           task->repo_id, task->repo_version,
                                           block_id, BLOCK_WRITE);
    if (!block) {
        seaf_warning ("Failed to open block %s in repo %.8s.\n",
                      block_id, task->repo_id);
        return -1;
    }

    GetBlockData data;
    memcpy (data.block_id, block_id, 40);
    data.block = block;
    data.task = task;

    curl = conn->curl;

    url = g_strdup_printf ("%s/seafhttp/repo/%s/block/%s",
                           task->host, task->repo_id, block_id);

    if (http_get (curl, url, task->token, &status, NULL, NULL,
                  get_block_callback, &data) < 0) {
        if (task->state == HTTP_TASK_STATE_CANCELED)
            goto error;

        if (task->error == HTTP_OK)
            task->error = HTTP_TASK_ERR_NET;
        ret = -1;
        goto error;
    }

    if (status != HTTP_OK) {
        seaf_warning ("Bad response code for GET %s: %d.\n", url, status);
        handle_http_errors (task, status);
        ret = -1;
        goto error;
    }

    seaf_block_manager_close_block (seaf->block_mgr, block);

    if (seaf_block_manager_commit_block (seaf->block_mgr, block) < 0) {
        seaf_warning ("Failed to commit block %s in repo %.8s.\n",
                      block_id, task->repo_id);
        task->error = HTTP_TASK_ERR_WRITE_LOCAL_DATA;
        ret = -1;
    }

    seaf_block_manager_block_handle_free (seaf->block_mgr, block);

    g_free (url);

    return ret;

error:
    g_free (url);

    seaf_block_manager_close_block (seaf->block_mgr, block);
    seaf_block_manager_block_handle_free (seaf->block_mgr, block);

    return ret;
}

int
http_tx_task_download_file_blocks (HttpTxTask *task, const char *file_id)
{
    Seafile *file;
    HttpTxPriv *priv = seaf->http_tx_mgr->priv;
    ConnectionPool *pool;
    Connection *conn;
    int ret = 0;

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                        task->repo_id,
                                        task->repo_version,
                                        file_id);
    if (!file) {
        seaf_warning ("Failed to find seafile object %s in repo %.8s.\n",
                      file_id, task->repo_id);
        return -1;
    }

    pool = find_connection_pool (priv, task->host);
    if (!pool) {
        seaf_warning ("Failed to create connection pool for host %s.\n", task->host);
        task->error = HTTP_TASK_ERR_NOT_ENOUGH_MEMORY;
        seafile_unref (file);
        return -1;
    }

    conn = connection_pool_get_connection (pool);
    if (!conn) {
        seaf_warning ("Failed to get connection to host %s.\n", task->host);
        task->error = HTTP_TASK_ERR_NOT_ENOUGH_MEMORY;
        seafile_unref (file);
        return -1;
    }

    int i;
    char *block_id;
    for (i = 0; i < file->n_blocks; ++i) {
        block_id = file->blk_sha1s[i];
        if (!seaf_block_manager_block_exists (seaf->block_mgr,
                                              task->repo_id,
                                              task->repo_version,
                                              block_id)) {
            ret = get_block (task, conn, block_id);
            if (ret < 0 || task->state == HTTP_TASK_STATE_CANCELED)
                break;
        }
    }

    connection_pool_return_connection (pool, conn);

    seafile_unref (file);

    return ret;
}

static int
update_local_repo (HttpTxTask *task)
{
    SeafRepo *repo;
    SeafCommit *new_head;
    SeafBranch *branch;
    int ret = 0;

    new_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                               task->repo_id,
                                               task->repo_version,
                                               task->head);
    if (!new_head) {
        seaf_warning ("Failed to get commit %s.\n", task->head);
        task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
        return -1;
    }

    /* If repo doesn't exist, create it.
     * Note that branch doesn't exist either in this case.
     */
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, new_head->repo_id);
    if (task->is_clone) {
        if (repo != NULL)
            goto out;

        repo = seaf_repo_new (new_head->repo_id, NULL, NULL);
        if (repo == NULL) {
            /* create repo failed */
            task->error = HTTP_TASK_ERR_NOT_ENOUGH_MEMORY;
            ret = -1;
            goto out;
        }

        seaf_repo_from_commit (repo, new_head);

        seaf_repo_manager_add_repo (seaf->repo_mgr, repo);

        /* If it's a new repo, create 'local' and 'master' branch */
        branch = seaf_branch_new ("local", task->repo_id, task->head);
        seaf_branch_manager_add_branch (seaf->branch_mgr, branch);
        seaf_branch_unref (branch);

        branch = seaf_branch_new ("master", task->repo_id, task->head);
        seaf_branch_manager_add_branch (seaf->branch_mgr, branch);
        seaf_branch_unref (branch);
    } else {
        if (!repo) {
            task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
            ret = -1;
            goto out;
        }

        branch = seaf_branch_manager_get_branch (seaf->branch_mgr, 
                                                 task->repo_id,
                                                 "master");
        if (!branch) {
            seaf_warning ("Branch master not found for repo %.8s.\n", task->repo_id);
            task->error = HTTP_TASK_ERR_BAD_LOCAL_DATA;
            ret = -1;
            goto out;
        }
        seaf_branch_set_commit (branch, new_head->commit_id);
        seaf_branch_manager_update_branch (seaf->branch_mgr, branch);
        seaf_branch_unref (branch);

        /* Update repo head branch. */
        seaf_branch_set_commit (repo->head, new_head->commit_id);
        seaf_branch_manager_update_branch (seaf->branch_mgr, repo->head);
    }

out:
    seaf_commit_unref (new_head);
    return ret;
}

static void *
http_download_thread (void *vdata)
{
    HttpTxTask *task = vdata;
    HttpTxPriv *priv = seaf->http_tx_mgr->priv;
    ConnectionPool *pool;
    Connection *conn = NULL;
    GList *fs_id_list = NULL;

    pool = find_connection_pool (priv, task->host);
    if (!pool) {
        seaf_warning ("Failed to create connection pool for host %s.\n", task->host);
        task->error = HTTP_TASK_ERR_NOT_ENOUGH_MEMORY;
        goto out;
    }

    conn = connection_pool_get_connection (pool);
    if (!conn) {
        seaf_warning ("Failed to get connection to host %s.\n", task->host);
        task->error = HTTP_TASK_ERR_NOT_ENOUGH_MEMORY;
        goto out;
    }

    seaf_message ("Download with HTTP sync protocol version %d.\n",
                  task->protocol_version);

    transition_state (task, task->state, HTTP_TASK_RT_STATE_CHECK);

    if (check_permission (task, conn) < 0) {
        seaf_warning ("Download permission denied for repo %.8s on server %s.\n",
                      task->repo_id, task->host);
        goto out;
    }

    if (task->state == HTTP_TASK_STATE_CANCELED)
        goto out;

    transition_state (task, task->state, HTTP_TASK_RT_STATE_COMMIT);

    if (get_commit_object (task, conn) < 0) {
        seaf_warning ("Failed to get server head commit for repo %.8s on server %s.\n",
                      task->repo_id, task->host);
        goto out;
    }

    if (task->state == HTTP_TASK_STATE_CANCELED)
        goto out;

    transition_state (task, task->state, HTTP_TASK_RT_STATE_FS);

    if (get_needed_fs_id_list (task, conn, &fs_id_list) < 0) {
        seaf_warning ("Failed to get fs id list for repo %.8s on server %s.\n",
                      task->repo_id, task->host);
        goto out;
    }

    if (task->state == HTTP_TASK_STATE_CANCELED)
        goto out;

    while (fs_id_list != NULL) {
        if (get_fs_objects (task, conn, &fs_id_list) < 0) {
            seaf_warning ("Failed to get fs objects for repo %.8s on server %s.\n",
                          task->repo_id, task->host);
            goto out;
        }

        if (task->state == HTTP_TASK_STATE_CANCELED)
            goto out;
    }

    transition_state (task, task->state, HTTP_TASK_RT_STATE_BLOCK);

    /* Record download head commit id, so that we can resume download
     * if this download is interrupted.
     */
    seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                         task->repo_id,
                                         REPO_PROP_DOWNLOAD_HEAD,
                                         task->head);

    int rc = seaf_repo_fetch_and_checkout (NULL, task, TRUE, task->head);
    switch (rc) {
    case FETCH_CHECKOUT_SUCCESS:
        break;
    case FETCH_CHECKOUT_CANCELED:
        goto out;
    case FETCH_CHECKOUT_FAILED:
        task->error = HTTP_TASK_ERR_WRITE_LOCAL_DATA;
        goto out;
    case FETCH_CHECKOUT_TRANSFER_ERROR:
        goto out;
    case FETCH_CHECKOUT_LOCKED:
        task->error = HTTP_TASK_ERR_FILES_LOCKED;
        goto out;
    }

    update_local_repo (task);

out:
    connection_pool_return_connection (pool, conn);
    string_list_free (fs_id_list);
    return vdata;
}

static void
http_download_done (void *vdata)
{
    HttpTxTask *task = vdata;

    if (task->error != HTTP_TASK_OK)
        transition_state (task, HTTP_TASK_STATE_ERROR, HTTP_TASK_RT_STATE_FINISHED);
    else if (task->state == HTTP_TASK_STATE_CANCELED)
        transition_state (task, task->state, HTTP_TASK_RT_STATE_FINISHED);
    else
        transition_state (task, HTTP_TASK_STATE_FINISHED, HTTP_TASK_RT_STATE_FINISHED);
}

GList*
http_tx_manager_get_upload_tasks (HttpTxManager *manager)
{
    return g_hash_table_get_values (manager->priv->upload_tasks);
}

GList*
http_tx_manager_get_download_tasks (HttpTxManager *manager)
{
    return g_hash_table_get_values (manager->priv->download_tasks);
}

HttpTxTask *
http_tx_manager_find_task (HttpTxManager *manager, const char *repo_id)
{
    HttpTxTask *task = NULL;

    task = g_hash_table_lookup (manager->priv->upload_tasks, repo_id);
    if (task)
        return task;

    task = g_hash_table_lookup (manager->priv->download_tasks, repo_id);
    return task;
}

void
http_tx_manager_cancel_task (HttpTxManager *manager,
                             const char *repo_id,
                             int task_type)
{
    HttpTxTask *task = NULL;

    if (task_type == HTTP_TASK_TYPE_DOWNLOAD)
        task = g_hash_table_lookup (manager->priv->download_tasks, repo_id);
    else
        task = g_hash_table_lookup (manager->priv->upload_tasks, repo_id);

    if (!task)
        return;

    if (task->state != HTTP_TASK_STATE_NORMAL) {
        seaf_warning ("Cannot cancel task not in NORMAL state.\n");
        return;
    }

    if (task->runtime_state == HTTP_TASK_RT_STATE_INIT) {
        transition_state (task, TASK_STATE_CANCELED, TASK_RT_STATE_FINISHED);
        return;
    }

    /* Only change state. runtime_state will be changed in worker thread. */
    transition_state (task, TASK_STATE_CANCELED, task->runtime_state);
}

int
http_tx_task_get_rate (HttpTxTask *task)
{
    return task->last_tx_bytes;
}

const char *
http_task_state_to_str (int state)
{
    if (state < 0 || state >= N_HTTP_TASK_STATE)
        return "unknown";

    return http_task_state_str[state];
}

const char *
http_task_rt_state_to_str (int rt_state)
{
    if (rt_state < 0 || rt_state >= N_HTTP_TASK_RT_STATE)
        return "unknown";

    return http_task_rt_state_str[rt_state];
}

const char *
http_task_error_str (int task_errno)
{
    if (task_errno < 0 || task_errno >= N_HTTP_TASK_ERROR)
        return "unknown error";

    return http_task_error_strs[task_errno];
}
