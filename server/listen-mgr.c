#include "common.h"

#include <event2/event.h>
#include <event2/listener.h>

#include "seafile-session.h"
#include "utils.h"
#include "net.h"
#include "listen-mgr.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"


#define DEFAULT_SERVER_PORT 12001

#define TOKEN_LEN                   37   /* a uuid */
#define CHECK_EXPIRE_INTERVAL       1
#define READ_TOKEN_TIMEOUT          180 /* bufferevent read timeout */

struct _SeafListenManagerPriv {
    GHashTable             *token_hash;
    struct evconnlistener  *listener;
    CcnetTimer             *check_timer;
};

typedef struct {
    int ttl;
    ConnAcceptedCB func;
    void  *user_data;
} CallBackStruct;

static void accept_connection (struct evconnlistener *listener,
                               evutil_socket_t connfd,
                               struct sockaddr *saddr,
                               int socklen,
                               void *vmanager);

static int token_expire_pulse (void * vmanager);
static void read_cb (struct bufferevent *bufev, void *user_data);
static void error_cb (struct bufferevent *bufev, short what, void *user_data);

static int
get_listen_port (SeafileSession *session)
{
    char *port_str;
    int port = 0;

    port_str = g_key_file_get_string (session->config, "network", "port", NULL);
    if (port_str) {
        port = atoi(port_str);
    }

    if (port < 1024 || port > 65535)
        port = DEFAULT_SERVER_PORT;

    g_free(port_str);
    return port;
}


SeafListenManager *
seaf_listen_manager_new (SeafileSession *session)
{
    SeafListenManager *mgr;
    mgr = g_new0 (SeafListenManager, 1);
    mgr->port = get_listen_port(session);

    mgr->priv = g_new0 (SeafListenManagerPriv, 1);
    mgr->priv->token_hash = g_hash_table_new_full (
        g_str_hash, g_str_equal, g_free, g_free);

    return mgr;
}

int
seaf_listen_manager_start (SeafListenManager *mgr)
{
    evutil_socket_t listenfd;
    unsigned flags;
    SeafListenManagerPriv *priv = mgr->priv;

    listenfd = ccnet_net_bind_tcp (mgr->port, 1);
    if (listenfd < 0) {
        seaf_warning ("[listen mgr] failed to bind port %d\n", mgr->port);
        return -1;
    }

    flags = LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_EXEC;

    /* start to listen on block transfer port */
    priv->listener = evconnlistener_new (NULL,     /* base */
                                accept_connection, mgr, /* cb & arg */
                                flags,                  /* flags */
                                -1,                     /* backlog */
                                listenfd);              /* socket */

    if (!priv->listener) {
        seaf_warning ("[listen mgr] failed to start evlistener\n");
        evutil_closesocket (listenfd);
        return -1;
    }

    priv->check_timer = ccnet_timer_new (token_expire_pulse, mgr,
                                         CHECK_EXPIRE_INTERVAL * 1000);

    seaf_message ("listen on port %d for block tranfer\n", mgr->port);
    return 0;
}

static void
accept_connection (struct evconnlistener *listener,
                   evutil_socket_t connfd,
                   struct sockaddr *saddr, int socklen,
                   void *vmanager)
{
    struct bufferevent   *bufev;
    struct timeval tv;
    tv.tv_sec = READ_TOKEN_TIMEOUT;
    tv.tv_usec = 0;

    bufev = bufferevent_socket_new (NULL, connfd, 0);
    bufferevent_setcb (bufev, read_cb, NULL, error_cb, vmanager);
    bufferevent_setwatermark (bufev, EV_READ, TOKEN_LEN, TOKEN_LEN);
    bufferevent_set_timeouts (bufev, &tv, NULL);

    bufferevent_enable (bufev, EV_READ);
    /* no write is needed here*/
    bufferevent_disable (bufev, EV_WRITE);
}

static void
read_cb (struct bufferevent *bufev, void *user_data)
{
    char *token;
    CallBackStruct *cbstruct;
    SeafListenManager *mgr = user_data;
    size_t len = EVBUFFER_LENGTH(bufev->input);
    evutil_socket_t connfd = bufferevent_getfd(bufev);

    /* we set the high & low watermark to TOKEN_LEN, so the received data can
     * only be this length. */
    if (len != TOKEN_LEN) {
        seaf_warning ("[listen mgr] token with incorrect length received: %d\n",
                      (int)len);
        goto error;
    }

    token = (char *)(EVBUFFER_DATA (bufev->input));
    cbstruct = g_hash_table_lookup (mgr->priv->token_hash, token);
    if (!cbstruct) {
        seaf_warning ("[listen mgr] unknown token received: %s\n", token);
        goto error;
    }

    /* The connfd should be non-blocking for adding to bufferevent.
     * But now we want it to be blocking again.
     */
    if (ccnet_net_make_socket_blocking (connfd) < 0) {
        seaf_warning ("[listen mgr] Failed to set socket blocking.\n");
        goto error;
    }

    /* client is now connected, execute the callback function  */
    cbstruct->func (connfd, cbstruct->user_data);

    g_hash_table_remove (mgr->priv->token_hash, token);
    bufferevent_free (bufev);
    return;

error:
    evutil_closesocket(connfd);
    bufferevent_free (bufev);
}

static void
error_cb (struct bufferevent *bufev, short what, void *user_data)
{
    if (what & BEV_EVENT_TIMEOUT)
        seaf_warning ("[listen mgr] client timeout\n");
    else
        seaf_warning ("[listen mgr] error when reading token\n");

    /* We don't specify BEV_OPT_CLOSE_ON_FREE, so we need to close the socket
     * manually. */
    evutil_closesocket(bufferevent_getfd(bufev));
    bufferevent_free (bufev);
}


int
seaf_listen_manager_register_token (SeafListenManager *mgr,
                                    const char *token,
                                    ConnAcceptedCB cb,
                                    void *cb_arg,
                                    int timeout_sec)
{
    CallBackStruct *cbstruct;
    if (!token)
        return -1;

    if (timeout_sec <= 0)
        return -1;

    cbstruct = g_new0(CallBackStruct, 1);
    cbstruct->func = cb;
    cbstruct->user_data = cb_arg;
    cbstruct->ttl = timeout_sec;

    g_hash_table_insert (mgr->priv->token_hash, g_strdup(token), cbstruct);
    return 0;
}

char *
seaf_listen_manager_generate_token (SeafListenManager *mgr)
{
    return gen_uuid();
}

static gboolean
is_token_expired (gpointer key, gpointer value, gpointer user_data)
{
    CallBackStruct *cbstruct = value;

    if (cbstruct->ttl == 0) {
        /* client doesn't connect before timeout, so token is expired */
        seaf_warning ("[listen mgr] token timeout\n");
        cbstruct->func (-1, cbstruct->user_data);
        return TRUE;
    }

    --cbstruct->ttl;

    return FALSE;
}

static int
token_expire_pulse (void * vmanager)
{
    SeafListenManager *mgr = vmanager;
    g_hash_table_foreach_remove (mgr->priv->token_hash,
                                 (GHRFunc)is_token_expired,
                                 NULL);

    return TRUE;
}

