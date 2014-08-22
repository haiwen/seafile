#include "common.h"

#include <pthread.h>
#include <curl/curl.h>
#include <jansson.h>

#include "seafile-session.h"
#include "http-tx-mgr.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#define HTTP_OK 200
#define HTTP_BAD_REQUEST 400
#define HTTP_FORBIDDEN 403
#define HTTP_NOT_FOUND 404
#define HTTP_INTERNAL_SERVER_ERROR 500

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

int
http_tx_manager_start (HttpTxManager *mgr)
{
    curl_global_init (CURL_GLOBAL_ALL);

    /* TODO: add a timer to clean up unused Http connections. */
}

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
    char *token_header;
    char *url;
    struct curl_slist *headers = NULL;

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

    url = g_strdup_printf ("%s/seaf-sync/repo/%s/commit/HEAD",
                           data->host, data->repo_id);

    token_header = g_strdup_printf ("Seafile-Repo-Token: %s", data->token);
    headers = curl_slist_append (headers, token_header);
    g_free (token_header);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    HttpResponse rsp;
    memset (&rsp, 0, sizeof(rsp));
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, recv_response);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &rsp);

    int rc = curl_easy_perform (curl);
    if (rc != 0) {
        seaf_warning ("libcurl failed to GET %s: %s.\n",
                      url, curl_easy_strerror(rc));
        goto out;
    }

    long status;
    rc = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc != CURLE_OK) {
        seaf_warning ("Failed to get status code for GET %s.\n", url);
        goto out;
    }

    if (status == HTTP_OK) {
        if (parse_head_commit_info (rsp.content, rsp.size, data) < 0)
            goto out;
        data->success = TRUE;
    } else if (status == HTTP_NOT_FOUND) {
        data->is_deleted = TRUE;
        data->success = TRUE;
    } else {
        seaf_warning ("Bad response code for GET %s: %ld.\n", url, status);
    }

out:
    g_free (url);
    g_free (rsp.content);
    connection_pool_return_connection (pool, conn);
    return vdata;
}

static void
check_head_commit_done (void *vdata)
{
    CheckHeadData *data = vdata;
    HttpHeadCommit result;

    if (!data->success)
        data->callback (FALSE, NULL, data->user_data);
    else {
        memset (&result, 0, sizeof(result));
        result.is_corrupt = data->is_corrupt;
        result.is_deleted = data->is_deleted;
        memcpy (result.head_commit, data->head_commit, 40);

        data->callback (TRUE, &result, data->user_data);
    }

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
