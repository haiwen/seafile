#include <event2/event.h>
#include <event2/listener.h>

#include "common.h"
#include "seafile-session.h"
#include "utils.h"
#include "net.h"
#include "listen-mgr.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"


#define DEFAULT_SERVER_PORT 12001

struct _SeafListenManagerPriv {
    GHashTable             *token_hash;
    struct evconnlistener  *listener;
};

typedef struct {
    ConnAcceptedCB func;
    void  *user_data;
} CallBackStruct;

static void accept_connection (struct evconnlistener *listener,
                               evutil_socket_t connfd,
                               struct sockaddr *saddr,
                               int socklen,
                               void *vmanager);

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

    listenfd = ccnet_net_bind_tcp (mgr->port, 1);
    if (listenfd < 0) {
        seaf_warning ("[listen mgr] failed to bind port %d\n", mgr->port);
        return -1;
    }

    flags = LEV_OPT_REUSEABLE | LEV_OPT_CLOSE_ON_EXEC | LEV_OPT_LEAVE_SOCKETS_BLOCKING;

    /* start to listen on block transfer port */
    mgr->priv->listener = evconnlistener_new (NULL,     /* base */
                                accept_connection, mgr, /* cb & arg */
                                flags,                  /* flags */
                                -1,                     /* backlog */
                                listenfd);              /* socket */

    if (!mgr->priv->listener) {
        seaf_warning ("[listen mgr] failed to start evlistener\n");
        evutil_closesocket (listenfd);
        return -1;
    }

    seaf_message ("listen on port %d for block tranfer\n", mgr->port);
    return 0;
}

#define TOKEN_LEN 37            /* a uuid */

typedef struct {
    char token[TOKEN_LEN];
    evutil_socket_t connfd;
} ListenResult;

static void *
read_token(void *vdata)
{
    evutil_socket_t connfd = (evutil_socket_t)(long)vdata;
    char buf[TOKEN_LEN];
    ssize_t len;
    
    len = readn (connfd, buf, TOKEN_LEN);
    if (len != TOKEN_LEN || buf[TOKEN_LEN - 1] != '\0') {
        evutil_closesocket (connfd);
        seaf_warning ("[listen mgr] invalid token received\n");
        return NULL;
        
    } else {
        ListenResult *result = g_new0(ListenResult, 1);
        result->connfd = connfd;
        memcpy (result->token, buf, TOKEN_LEN);
        
        return result;
    }
}

static void
read_token_done (void *vdata)
{
    CallBackStruct *cb;
    ListenResult *result = vdata;
    if (!result)
        return;

    cb = g_hash_table_lookup (seaf->listen_mgr->priv->token_hash, result->token);
    if (!cb) {
        evutil_closesocket (result->connfd);
        seaf_warning ("[listen mgr] unknown token received: %s\n", result->token);
        g_free (result);
        return;
    }

    cb->func (result->connfd, cb->user_data);
    g_free (result);
}


static void
accept_connection (struct evconnlistener *listener,
                   evutil_socket_t connfd,
                   struct sockaddr *saddr, int socklen,
                   void *vmanager)
{
    /* wait in another thread for client to send the token. */
    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    read_token,
                                    read_token_done,
                                    (void *)(long)connfd);
}

int
seaf_listen_manager_register_token (SeafListenManager *mgr,
                                    const char *token,
                                    ConnAcceptedCB cb,
                                    void *cb_arg)
{
    CallBackStruct *cbstruct;
    if (!token)
        return -1;
    
    cbstruct = g_new0(CallBackStruct, 1);
    cbstruct->func = cb;
    cbstruct->user_data = cb_arg;

    g_hash_table_insert (mgr->priv->token_hash, g_strdup(token), cbstruct);
    return 0;
}

void
seaf_listen_manager_unregister_token (SeafListenManager *mgr,
                                      const char *token)
{
    if (token)
        g_hash_table_remove (mgr->priv->token_hash, token);
}

char *
seaf_listen_manager_generate_token (SeafListenManager *mgr)
{
    return gen_uuid();
}
