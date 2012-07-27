#include "common.h"

#ifdef RIAK_BACKEND

#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <glib.h>

#include "log.h"
#include "riak-client.h"

#ifdef RIAK_TEST
#undef seaf_warning
#define seaf_warning g_warning
#endif

struct SeafRiakClient {
    CURL *curl;
    char *host;
    char *port;
};

typedef struct RiakObject {
    void *data;
    size_t size;
} RiakObject;

SeafRiakClient *
seaf_riak_client_new (const char *host, const char *port)
{
    SeafRiakClient *client = g_new0 (SeafRiakClient, 1);

    client->host = g_strdup(host);
    client->port = g_strdup(port);
    client->curl = curl_easy_init();

    return client;
}

void
seaf_riak_client_free (SeafRiakClient *client)
{
    curl_easy_cleanup (client->curl);
    g_free (client->host);
    g_free (client->port);
    g_free (client);
}

static size_t
recv_object (void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    RiakObject *object = userp;

    object->data = g_realloc (object->data, object->size + realsize);
    if (!object->data) {
        seaf_warning ("[riak http] Not enough memory.\n");
        /* return a value other than realsize to signify an error. */
        return 0;
    }

    memcpy (object->data + object->size, contents, realsize);
    object->size += realsize;

    return realsize;
}

int
seaf_riak_client_get (SeafRiakClient *client,
                      const char *bucket,
                      const char *key,
                      void **value,
                      int *size)
{
    CURL *curl = client->curl;
    GString *url = g_string_new (NULL);
    RiakObject *object = g_new0 (RiakObject, 1);
    int rc, ret = 0;

    g_string_append_printf (url, "http://%s:%s/riak/%s/%s?r=1",
                            client->host, client->port, bucket, key);
    curl_easy_setopt (curl, CURLOPT_URL, url->str);

    /* Setup callback for receiving http message body. */
    curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, recv_object);
    curl_easy_setopt (curl, CURLOPT_WRITEDATA, object);
    curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1L);
#ifdef RIAK_TEST
    curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);
#endif

    rc = curl_easy_perform (curl);
    if (rc != 0) {
        ret = -1;
        g_free (object->data);
        goto out;
    }

    *value = object->data;
    *size = (int)object->size;

out:
    /* Clear options for future use. */
    curl_easy_reset (curl);
    g_string_free (url, TRUE);
    g_free (object);
    return ret;
}

static size_t
send_object (void *ptr, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size *nmemb;
    size_t copy_size;
    RiakObject *object = userp;

    if (object->size == 0)
        return 0;

    copy_size = MIN(object->size, realsize);
    memcpy (ptr, object->data, copy_size);
    object->size -= copy_size;
    object->data = object->data + copy_size;

    return copy_size;
}

int
seaf_riak_client_put (SeafRiakClient *client,
                      const char *bucket,
                      const char *key,
                      void *value,
                      int size,
                      int n_w)
{
    CURL *curl = client->curl;
    GString *url = g_string_new (NULL);
    RiakObject *object = g_new0 (RiakObject, 1);
    int rc, ret = 0;
    struct curl_slist *headers = NULL;

    g_string_append_printf (url, "http://%s:%s/riak/%s/%s",
                            client->host, client->port, bucket, key);
    switch (n_w) {
    case RIAK_QUORUM:
        g_string_append (url, "?w=quorum&dw=quorum");
        break;
    case RIAK_ALL:
        g_string_append (url, "?w=all&dw=all");
        break;
    default:
        g_string_append_printf (url, "?w=%d&dw=%d", n_w, n_w);
    }

    curl_easy_setopt (curl, CURLOPT_URL, url->str);
    /* Ask libcurl to send a PUT request. */
    curl_easy_setopt (curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1L);
#ifdef RIAK_TEST
    curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);
#endif

    headers = curl_slist_append (headers, "Content-type: application/binary");
    curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);

    object->data = value;
    object->size = (size_t)size;
    curl_easy_setopt (curl, CURLOPT_READFUNCTION, send_object);
    curl_easy_setopt (curl, CURLOPT_READDATA, object);

    rc = curl_easy_perform (curl);
    if (rc != 0) {
        seaf_warning ("[riak http] Failed to put object [%s:%s]: %s.\n",
                      bucket, key, curl_easy_strerror(rc));
        ret = -1;
    }

    /* Clear options for future use. */
    curl_easy_reset (curl);
    curl_slist_free_all (headers);
    g_string_free (url, TRUE);
    g_free (object);
    return ret;
}

gboolean
seaf_riak_client_query (SeafRiakClient *client,
                        const char *bucket,
                        const char *key)
{
    CURL *curl = client->curl;
    GString *url = g_string_new (NULL);
    int rc;
    gboolean ret;

    g_string_append_printf (url, "http://%s:%s/riak/%s/%s?r=1",
                            client->host, client->port, bucket, key);
    curl_easy_setopt (curl, CURLOPT_URL, url->str);
    curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1L);
#ifdef RIAK_TEST
    curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);
#endif

    /* Ask libcurl to send a HEAD request. */
    curl_easy_setopt (curl, CURLOPT_NOBODY, 1L);

    rc = curl_easy_perform (curl);
    if (rc != 0)
        ret = FALSE;
    else
        ret = TRUE;

    /* Clear options for future use. */
    curl_easy_reset (curl);
    g_string_free (url, TRUE);
    return ret;
}

int
seaf_riak_client_delete (SeafRiakClient *client,
                         const char *bucket,
                         const char *key,
                         int n_w)
{
    CURL *curl = client->curl;
    GString *url = g_string_new (NULL);
    int rc, ret = 0;
    long status;

    g_string_append_printf (url, "http://%s:%s/riak/%s/%s",
                            client->host, client->port, bucket, key);
    switch (n_w) {
    case RIAK_QUORUM:
        g_string_append (url, "?rw=quorum&dw=quorum");
        break;
    case RIAK_ALL:
        g_string_append (url, "?rw=all&dw=all");
        break;
    default:
        g_string_append_printf (url, "?rw=%d&dw=%d", n_w, n_w);
    }

    curl_easy_setopt (curl, CURLOPT_URL, url->str);
    /* Ask libcurl to send a DELETE request. */
    curl_easy_setopt (curl, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1L);
#ifdef RIAK_TEST
    curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);
#endif

    rc = curl_easy_perform (curl);
    status = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &status);
    if (rc != 0 && status != 404) {
        seaf_warning ("[riak http] Failed to delete object [%s:%s]: %s.\n",
                      bucket, key, curl_easy_strerror(rc));
        ret = -1;
    }

    /* Clear options for future use. */
    curl_easy_reset (curl);
    g_string_free (url, TRUE);
    return ret;
}

#endif  /* RIAK_BACKEND */
