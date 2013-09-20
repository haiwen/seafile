#include "common.h"
#include "log.h"
#include "obj-backend.h"

#ifdef RIAK_BACKEND

#include "riak-client.h"

#include <pthread.h>

typedef struct RiakPriv {
    const char *host;
    const char *port;
    const char *bucket;
    int n_write;

    GQueue *conn_pool;
    pthread_mutex_t lock;
} RiakPriv;

static SeafRiakClient *
get_connection (RiakPriv *priv)
{
    SeafRiakClient *connection;

    pthread_mutex_lock (&priv->lock);

    connection = g_queue_pop_head (priv->conn_pool);
    if (!connection)
        connection = seaf_riak_client_new (priv->host, priv->port);
    pthread_mutex_unlock (&priv->lock);
    return connection;
}

static void
return_connection (RiakPriv *priv, SeafRiakClient *connection)
{
    pthread_mutex_lock (&priv->lock);
    g_queue_push_tail (priv->conn_pool, connection);
    pthread_mutex_unlock (&priv->lock);
}

static int
obj_backend_riak_read (ObjBackend *bend,
                       const char *obj_id,
                       void **data,
                       int *len)
{
    SeafRiakClient *conn = get_connection (bend->priv);
    RiakPriv *priv = bend->priv;
    int ret;

    ret = seaf_riak_client_get (conn, priv->bucket, obj_id, data, len);

    return_connection (priv, conn);
    return ret;
}

static int
obj_backend_riak_write (ObjBackend *bend,
                        const char *obj_id,
                        void *data,
                        int len)
{
    SeafRiakClient *conn = get_connection (bend->priv);
    RiakPriv *priv = bend->priv;
    int ret;

    ret = seaf_riak_client_put (conn, priv->bucket, obj_id, data, len,
                                priv->n_write);

    return_connection (priv, conn);
    return ret;
}

static gboolean
obj_backend_riak_exists (ObjBackend *bend,
                         const char *obj_id)
{
    SeafRiakClient *conn = get_connection (bend->priv);
    RiakPriv *priv = bend->priv;
    gboolean ret;

    ret = seaf_riak_client_query (conn, priv->bucket, obj_id);

    return_connection (priv, conn);
    return ret;
}

static void
obj_backend_riak_delete (ObjBackend *bend,
                         const char *obj_id)
{
    SeafRiakClient *conn = get_connection (bend->priv);
    RiakPriv *priv = bend->priv;

    seaf_riak_client_delete (conn, priv->bucket, obj_id, priv->n_write);

    return_connection (priv, conn);
}

ObjBackend *
obj_backend_riak_new (const char *host,
                      const char *port,
                      const char *bucket,
                      const char *write_policy)
{
    ObjBackend *bend;
    RiakPriv *priv;

    bend = g_new0(ObjBackend, 1);
    priv = g_new0(RiakPriv, 1);
    bend->priv = priv;

    priv->host = g_strdup (host);
    priv->port = g_strdup (port);
    priv->bucket = g_strdup (bucket);
    if (strcmp (write_policy, "quorum") == 0)
        priv->n_write = RIAK_QUORUM;
    else if (strcmp (write_policy, "all") == 0)
        priv->n_write = RIAK_ALL;
    else
        g_return_val_if_reached (NULL);

    priv->conn_pool = g_queue_new ();
    pthread_mutex_init (&priv->lock, NULL);

    bend->read = obj_backend_riak_read;
    bend->write = obj_backend_riak_write;
    bend->exists = obj_backend_riak_exists;
    bend->delete = obj_backend_riak_delete;

    return bend;
}

#else

ObjBackend *
obj_backend_riak_new (const char *host,
                      const char *port,
                      const char *bucket,
                      const char *write_policy)
{
    seaf_warning ("Riak backend is not enabled.\n");
    return NULL;
}

#endif  /* RIAK_BACKEND */
