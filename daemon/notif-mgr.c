/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <libwebsockets.h>
#include <string.h>
#include <glib.h>

#include "seafile-session.h"
#include "notif-mgr.h"
#include "sync-mgr.h"

#define DEBUG_FLAG SEAFILE_DEBUG_NOTIFICATION
#include "log.h"

#define NOTIF_PORT 8083

#define RECONNECT_INTERVAL 60 /* 60s */

#define STATUS_DISCONNECTED 0
#define STATUS_CONNECTED    1
#define STATUS_ERROR        2
#define STATUS_CANCELLED    3

typedef struct NotifServer {
    struct lws_context *context;
    struct lws_client_connect_info i;
    struct lws		*wsi;

    // status of the notification server.
    int      status;
    // whether to close the connection to the server.
    gboolean close;

    GHashTable *subscriptions;
    pthread_mutex_t sub_lock;
    GAsyncQueue *messages;

    gboolean use_ssl;
    char    *server_url;
    char    *addr;
    char    *path;
    int     port;

    gint    refcnt;
} NotifServer;

struct _SeafNotifManagerPriv {
    pthread_mutex_t server_lock;
    // Only maintain connection to the notification server associated with current account.
    NotifServer *server;
    GHashTable *servers;
};

// The Message structure is used to send messages to the server.
typedef struct Message {
    void    *payload;
    size_t  len;
    int     type;
} Message;

static Message*
notif_message_new (const char *str, int type)
{
    int len, n;

    len = strlen(str) + 1;
    Message *msg = g_new0 (Message, 1);
    msg->payload = malloc((unsigned int)(LWS_PRE + len));
    if (!msg->payload) {
        g_free (msg);
        return NULL;
    }

    // The libwebsockets library requires the message to be sent with a LWS_PRE header.
    n = lws_snprintf((char *)msg->payload + LWS_PRE, (unsigned int)len, "%s", str);
    msg->len = (unsigned int)n;
    msg->type = type;

    return msg;
}

static void
notif_message_free (Message *msg)
{
    if (!msg)
        return;
    g_free (msg->payload);
    g_free (msg);
}

SeafNotifManager *
seaf_notif_manager_new (SeafileSession *seaf)
{
    SeafNotifManager *mgr = g_new0 (SeafNotifManager, 1);
    mgr->seaf = seaf;

    mgr->priv = g_new0 (SeafNotifManagerPriv, 1);    
    pthread_mutex_init (&mgr->priv->server_lock, NULL);
    mgr->priv->servers = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, NULL);

    return mgr;
}

typedef struct URI {
    char *scheme;
    char *host;
    int  port;
} URI;

// Assume that the input url format is http[s]://host:port.
static URI*
parse_notification_url (const char *url)
{
    const char *server = url;
    char *colon;
    char *url_no_port;
    char *scheme = NULL;
    URI *uri = NULL;
    int port;
    

    if (strncmp(url, "https://", 8) == 0) {
        scheme = g_strdup ("https");
        server = url + 8;
        port = 443;
    } else if (strncmp (url, "http://", 7) == 0) {
        scheme = g_strdup ("http");
        server = url + 7;
        port = 80;
    }
    
    if (!server) {
        return NULL;
    }

    uri = g_new0 (URI, 1);
    uri->scheme = scheme;

    colon = strrchr (server, ':');
    if (colon) {
        url_no_port = g_strndup(server, colon - server);
        uri->host = g_strdup (url_no_port);
        if (colon + 1)
            port = atoi (colon + 1);

        uri->host = url_no_port;
        uri->port = port;

        return uri;
    } 

    uri->host = g_strdup (server);
    uri->port = port;

    return uri;
}

static void
notif_server_ref (NotifServer *server);

static struct lws_context *
lws_context_new (int port);

static NotifServer*
notif_new_server (const char *server_url, gboolean use_notif_server_port)
{
    NotifServer *server = NULL;
    static struct lws_context *context;
    URI *uri = NULL;
    int port = NOTIF_PORT;
    gboolean use_ssl = FALSE;

    uri = parse_notification_url (server_url);
    if (!uri) {
        seaf_warning ("failed to parse notification url from %s\n", server_url);
        return NULL;
    }

    // If use_notif_server_port is FALSE, the server should be deployed behind Nginx.
    // In this case we'll use the same port as Seafile server.
    if (!use_notif_server_port) {
        port = uri->port;
    }

    if (strncmp(server_url, "https", 5) == 0) {
        use_ssl = TRUE;
    }
    

    context = lws_context_new (use_ssl);
    if (!context) {
        g_free (uri->scheme);
        g_free (uri->host);
        g_free (uri);
        seaf_warning ("failed to create libwebsockets context\n");
        return NULL;
    }

    server = g_new0 (NotifServer, 1);

    server->messages = g_async_queue_new ();

    server->context = context;
    server->server_url = g_strdup (server_url);
    server->addr = g_strdup (uri->host);
    server->use_ssl = use_ssl;
    if (use_notif_server_port)
        server->path = g_strdup ("/");
    else
        server->path = g_strdup ("/notification");
    server->port = port;

    pthread_mutex_init (&server->sub_lock, NULL);
    server->subscriptions = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                   g_free, NULL);
    notif_server_ref (server);

    g_free (uri->scheme);
    g_free (uri->host);
    g_free (uri);
    return server;
}

NotifServer*
get_notif_server (SeafNotifManager *mgr, const char *url)
{
    NotifServer *server = NULL;

    pthread_mutex_lock (&mgr->priv->server_lock);
    server = mgr->priv->server;
    server = g_hash_table_lookup (mgr->priv->servers, url);
    if (!server) {
        pthread_mutex_unlock (&mgr->priv->server_lock);
        return NULL;
    }
    notif_server_ref (server);
    pthread_mutex_unlock (&mgr->priv->server_lock);

    return server;
}

static void
delete_subscribed_repos (NotifServer *server);

static void
delete_unsent_messages (NotifServer *server);

static void
notif_server_free (NotifServer *server)
{
    if (!server)
        return;
    if (server->context)
        lws_context_destroy(server->context);
    g_free (server->server_url);
    g_free (server->addr);
    g_free (server->path);
    if (server->subscriptions)
        g_hash_table_destroy (server->subscriptions);

    delete_unsent_messages (server);
    g_async_queue_unref (server->messages);

    g_free (server);
}

static void
notif_server_ref (NotifServer *server)
{
    g_atomic_int_inc (&server->refcnt);
}

static void
notif_server_unref (NotifServer *server)
{
    if (!server)
        return;
    if (g_atomic_int_dec_and_test (&server->refcnt))
        notif_server_free (server);
}

static void
init_client_connect_info (NotifServer *server);

static void *
notification_worker (void *vdata);

// This function will automatically disconnect the previous server, then create a new server.
// The host is the server's url and use_notif_server_port is used to check whether the server has nginx deployed.
void
seaf_notif_manager_connect_server (SeafNotifManager *mgr, const char *host, gboolean use_notif_server_port)
{
    pthread_t tid;
    int rc;
    NotifServer *old_server = NULL;
    NotifServer *server = NULL;

    // close the old ws client.
    old_server = get_notif_server (mgr, host);
    if (old_server) {
        notif_server_unref (old_server);
        return;
    }

    server = notif_new_server (host, use_notif_server_port);
    if (!server) {
        return;
    }

    init_client_connect_info (server);

    rc = pthread_create (&tid, NULL, notification_worker, server);
    if (rc != 0) {
        seaf_warning ("Failed to create event notification new thread: %s.\n", strerror(rc));
        notif_server_unref (server);
        return;
    }

    pthread_mutex_lock (&mgr->priv->server_lock);
    g_hash_table_insert (mgr->priv->servers, g_strdup (host), server);
    pthread_mutex_unlock (&mgr->priv->server_lock);

    return;
}

// This policy will send a ping packet to the server per second.
// If we don't receive pong messages within 5 seconds, it is considered that the connection is unavailable.
// We will exit the event loop, and reconnect to the notification server.
static const lws_retry_bo_t ping_policy = {
	.secs_since_valid_ping		= 1,
	.secs_since_valid_hangup	= 5,
};

static void
init_client_connect_info (NotifServer *server)
{
    struct lws_client_connect_info *i = &server->i;
    memset(i, 0, sizeof(server->i));

    i->context = server->context;
    i->port = server->port;
    i->address = server->addr;
    i->path = server->path;
    i->host = i->address;
    i->origin = i->address;
    if (server->use_ssl) {
        i->ssl_connection = LCCSCF_USE_SSL | LCCSCF_ALLOW_SELFSIGNED;
    }
    i->protocol = "notification.seafile.com";
    i->local_protocol_name = "notification.seafile.com";
    i->pwsi = &server->wsi;
    i->retry_and_idle_policy = &ping_policy;
    i->userdata = server;
}

static void
handle_messages (const char *msg, size_t len);

// success:0
static int
event_callback (struct lws *wsi, enum lws_callback_reasons reason,
                void *user, void *in, size_t len)
{
    NotifServer *server = (NotifServer *)user;
    Message *msg = NULL;
    int m;
    int ret = 0;
    if (!server) {
        return ret;
    }

    seaf_debug ("Notification event: %d\n", reason);

    switch (reason) {
    case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
        server->status = STATUS_ERROR;
        seaf_debug ("websocket connection error: %s\n",
            in ? (char *)in : "(null)");
        ret = -1;
        break;
    case LWS_CALLBACK_CLIENT_RECEIVE:
        handle_messages (in, len);
        break;
    case LWS_CALLBACK_CLIENT_WRITEABLE:
        msg = g_async_queue_try_pop (server->messages);
        if (!msg) {
            break;
        }

        /* notice we allowed for LWS_PRE in the payload already */
        m = lws_write(wsi, ((unsigned char *)msg->payload) + LWS_PRE,
                  msg->len, msg->type);
        if (m < (int)msg->len) {
            notif_message_free (msg);
            seaf_warning ("Failed to write message to websocket\n");
            server->status = STATUS_ERROR;
            return -1;
        }

        notif_message_free (msg);
        break;
    case LWS_CALLBACK_CLIENT_ESTABLISHED:
        seaf_sync_manager_check_locks_and_folder_perms (seaf->sync_mgr, server->server_url);
        server->status = STATUS_CONNECTED;
        seaf_debug ("Successfully connected to the server: %s\n", server->server_url);
        break;
    case LWS_CALLBACK_CLIENT_CLOSED:
        ret = -1;
        server->status = STATUS_ERROR;
        break;
    case LWS_CALLBACK_EVENT_WAIT_CANCELLED:
        ret = -1;
        server->status = STATUS_CANCELLED;
        break;
    default:
        break;
    }

    return ret;
}

static int
handle_repo_update (json_t *content)
{
    json_t *member;
    const char *repo_id;
    const char *commit_id;
    SeafRepo *repo = NULL;

    member = json_object_get (content, "repo_id");
    if (!member) {
        seaf_warning ("Invalid repo update notification: no repo_id.\n");
        return -1;
    }
    repo_id = json_string_value (member);

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        return -1;
    }

    if (!seaf_notif_manager_is_repo_subscribed (seaf->notif_mgr, repo)) {
        return -1;
    }

    member = json_object_get (content, "commit_id");
    if (!member) {
        seaf_warning ("Invalid repo update notification: no commit_id.\n");
        return -1;
    }
    commit_id = json_string_value (member);
    if (!commit_id) {
        seaf_warning ("Invalid repo update notification: commit_id is null.\n");
        return -1;
    }

    seaf_sync_manager_update_repo (seaf->sync_mgr, repo, commit_id);

    return 0;
}

static int
handle_file_lock (json_t *content)
{
    json_t *member;
    const char *repo_id;
    const char *change_event;
    const char *path;
    const char *lock_user;
    SeafRepo *repo = NULL;

    member = json_object_get (content, "repo_id");
    if (!member) {
        seaf_warning ("Invalid file lock notification: no repo_id.\n");
        return -1;
    }
    repo_id = json_string_value (member);

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        return -1;
    }

    if (!seaf_repo_manager_server_is_pro (seaf->repo_mgr, repo->server_url))
        return -1;

    if (!seaf_notif_manager_is_repo_subscribed (seaf->notif_mgr, repo)) {
        return -1;
    }

    member = json_object_get (content, "path");
    if (!member) {
        seaf_warning ("Invalid file lock notification: no path.\n");
        return -1;
    }
    path = json_string_value (member);
    if (!path) {
        seaf_warning ("Invalid repo file lock notification: path is null.\n");
        return -1;
    }

    member = json_object_get (content, "change_event");
    if (!member) {
        seaf_warning ("Invalid file lock notification: no change_event.\n");
        return -1;
    }
    change_event = json_string_value (member);

    if (g_strcmp0 (change_event, "locked") == 0) {
        member = json_object_get (content, "lock_user");
        if (!member) {
            seaf_warning ("Invalid file lock notification: no lock_user.\n");
            return -1;
        }
        lock_user = json_string_value (member);

        FileLockType type = LOCKED_OTHERS;
        if (g_strcmp0 (lock_user, repo->email) == 0)
            type = LOCKED_MANUAL;

        seaf_filelock_manager_lock_file (seaf->filelock_mgr, repo_id, path, type);
    } else if (g_strcmp0 (change_event, "unlocked") == 0) {
        seaf_filelock_manager_mark_file_unlocked (seaf->filelock_mgr, repo_id, path);
    }

    return 0;
}

static int
handle_folder_perm (json_t *content)
{
    json_t *member;
    const char *repo_id;
    const char *change_event;
    const char *type;
    const char *path;
    const char *permission;
    SeafRepo *repo = NULL;

    member = json_object_get (content, "repo_id");
    if (!member) {
        seaf_warning ("Invalid folder perm notification: no repo_id.\n");
        return -1;
    }
    repo_id = json_string_value (member);

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        return -1;
    }

    if (!seaf_repo_manager_server_is_pro (seaf->repo_mgr, repo->server_url))
        return -1;

    if (!seaf_notif_manager_is_repo_subscribed (seaf->notif_mgr, repo)) {
        return -1;
    }

    member = json_object_get (content, "path");
    if (!member) {
        seaf_warning ("Invalid folder perm notification: no path.\n");
        return -1;
    }
    path = json_string_value (member);
    if (!path) {
        seaf_warning ("Invalid repo folder perm notification: path is null.\n");
        return -1;
    }

    member = json_object_get (content, "type");
    if (!member) {
        seaf_warning ("Invalid folder perm notification: no type.\n");
        return -1;
    }
    type = json_string_value (member);

    member = json_object_get (content, "change_event");
    if (!member) {
        seaf_warning ("Invalid folder perm notification: no change_event.\n");
        return -1;
    }
    change_event = json_string_value (member);

    member = json_object_get (content, "perm");
    if (!member) {
        seaf_warning ("Invalid folder perm notification: no perm.\n");
        return -1;
    }
    permission = json_string_value (member);

    FolderPerm *perm = g_new0 (FolderPerm, 1);
    perm->path = g_strdup (path);
    perm->permission = g_strdup (permission);

    if (g_strcmp0 (type, "user") == 0) {
        if (g_strcmp0 (change_event, "add") == 0 || g_strcmp0 (change_event, "modify") == 0)
            seaf_repo_manager_update_folder_perm (seaf->repo_mgr, repo_id,
                                                  FOLDER_PERM_TYPE_USER,
                                                  perm);
        else if (g_strcmp0 (change_event, "del") == 0)
            seaf_repo_manager_delete_folder_perm (seaf->repo_mgr, repo_id,
                                                  FOLDER_PERM_TYPE_USER,
                                                  perm);
    } else if (g_strcmp0 (type, "group") == 0) {
        if (g_strcmp0 (change_event, "add") == 0 || g_strcmp0 (change_event, "modify") == 0)
            seaf_repo_manager_update_folder_perm (seaf->repo_mgr, repo_id,
                                                  FOLDER_PERM_TYPE_GROUP,
                                                  perm);
        else if (g_strcmp0 (change_event, "del") == 0)
            seaf_repo_manager_delete_folder_perm (seaf->repo_mgr, repo_id,
                                                  FOLDER_PERM_TYPE_USER,
                                                  perm);
    }
    g_free (perm);

    return 0;
}

static void
handle_messages (const char *msg, size_t len)
{
    json_t *object, *content, *member;
    json_error_t jerror;
    const char *type;

    seaf_debug ("Receive repo notification: %s\n", msg);

    object = json_loadb (msg, len, 0, &jerror);
    if (!object) {
        seaf_warning ("Failed to parse notification: %s.\n", jerror.text);
        return;
    }

    member = json_object_get (object, "type");
    if (!member) {
        seaf_warning ("Invalid notification info: no type.\n");
        goto out;
    }

    type = json_string_value (member);

    content = json_object_get (object, "content");
    if (!content) {
        seaf_warning ("Invalid notification info: no content.\n");
        goto out;
    }

    if (g_strcmp0 (type, "repo-update") == 0) {
        if (handle_repo_update (content) < 0) {
            goto out;
        }
    } else if (g_strcmp0 (type, "file-lock-changed") == 0) {
        if (handle_file_lock (content) < 0) {
            goto out;
        }
    } else if (g_strcmp0 (type, "folder-perm-changed") == 0) {
        if (handle_folder_perm (content) < 0) {
            goto out;
        }
    }

out:
    if (object)
        json_decref (object);
}

static const struct lws_protocols protocols[] = {
    { "notification.seafile.com", event_callback, 0, 0, 0, NULL, 0 },
    LWS_PROTOCOL_LIST_TERM
};

static struct lws_context *
lws_context_new (gboolean use_ssl)
{
    struct lws_context_creation_info info;
    struct lws_context *context = NULL;

    memset(&info, 0, sizeof info);
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    // Since we know this lws context is only ever going to be used with
    // one client wsis / fds / sockets at a time, let lws know it doesn't
    // have to use the default allocations for fd tables up to ulimit -n.
    // It will just allocate for 1 internal and 1 (+ 1 http2 nwsi) that we will use.
    info.fd_limit_per_thread = 1 + 1 + 1;
    char *ca_path = g_build_filename (seaf->seaf_dir, "ca-bundle.pem", NULL);
    if (use_ssl) {
         info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
         info.client_ssl_ca_filepath = ca_path;
    }

    context = lws_create_context(&info);
    if (!context) {
        g_free (ca_path);
        seaf_warning ("failed to create libwebsockets context\n");
        return NULL;
    }

    g_free (ca_path);
    return context;
}

static void
delete_subscribed_repos (NotifServer *server)
{
    GHashTableIter iter;
    gpointer key, value;

    if (!server->subscriptions)
        return;

    pthread_mutex_lock (&server->sub_lock);
    g_hash_table_iter_init (&iter, server->subscriptions);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        g_hash_table_iter_remove (&iter);
    }
    pthread_mutex_unlock (&server->sub_lock);
}

static void
delete_unsent_messages (NotifServer *server)
{
    Message *msg = NULL;

    if (!server->messages)
        return;

    while (1) {
        msg = g_async_queue_try_pop (server->messages);
        if (!msg) {
            break;
        }
        notif_message_free (msg);
    }

    return;
}

static void *
notification_worker (void *vdata)
{
    NotifServer *server = (NotifServer *)vdata;

    if (!server) {
        return 0;
    }

    struct lws_client_connect_info *i = &server->i;
    int n = 0;

    while (!server->close) {
        // We don't need to check the return value of this function, the connection will be processed in the event loop.
        lws_client_connect_via_info(i);

        while (n >= 0 && !server->close &&
               server->status != STATUS_ERROR &&
               server->status != STATUS_CANCELLED) {
            n = lws_service(server->context, 0);
        }

        delete_subscribed_repos (server);
        delete_unsent_messages (server);

        if (server->status == STATUS_CANCELLED)
            break;

        // Wait a minute to reconnect to the notification server.
        g_usleep (RECONNECT_INTERVAL * G_USEC_PER_SEC);
        n = 0;
        server->status = STATUS_DISCONNECTED;

        lws_context_destroy(server->context);
        server->context = NULL;
        server->context = lws_context_new (server->use_ssl);
        if (!server->context)
            break;
        i->context = server->context;
    }

    seaf_message ("Exit notification server %s success.\n", server->server_url);
    pthread_mutex_lock (&server->sub_lock);
    g_hash_table_remove (seaf->notif_mgr->priv->servers, server->server_url);
    pthread_mutex_unlock (&server->sub_lock);
    notif_server_unref (server);

    return 0;
}

void
seaf_notif_manager_subscribe_repo (SeafNotifManager *mgr, SeafRepo *repo)
{
    NotifServer *server = NULL;
    json_t *json_msg = NULL;
    json_t *content = NULL;
    char *str = NULL;
    char *sub_id = NULL;
    json_t *array, *obj;
    char *repo_id = repo->id;

    server = get_notif_server (mgr, repo->server_url);
    if (!server || server->status != STATUS_CONNECTED)
        goto out;

    json_msg = json_object ();
    json_object_set_new (json_msg, "type", json_string("subscribe"));

    content = json_object ();

    array = json_array ();

    obj = json_object ();
    json_object_set_new (obj, "id", json_string(repo_id));
    //TODO: "jwt_token" JWT token to authorize access to this repo
    json_array_append_new (array, obj);

    json_object_set_new (content, "repos", array);

    json_object_set_new (json_msg, "content", content);

    str = json_dumps (json_msg, JSON_COMPACT);
    if (!str)
        goto out;

    Message *msg = notif_message_new (str, LWS_WRITE_TEXT);
    if (!msg)
        goto out;

    g_async_queue_push (server->messages, msg);

    sub_id = g_strdup (repo_id);

    pthread_mutex_lock (&server->sub_lock);
    g_hash_table_insert (server->subscriptions, sub_id, sub_id);
    pthread_mutex_unlock (&server->sub_lock);

    seaf_debug ("Successfully subscribe repo %s\n", repo_id);

out:
    g_free (str);
    json_decref (json_msg);
    notif_server_unref (server);
}

void
seaf_notif_manager_unsubscribe_repo (SeafNotifManager *mgr, SeafRepo *repo)
{
    NotifServer *server = NULL;
    json_t *json_msg = NULL;
    json_t *content = NULL;
    char *str = NULL;
    json_t *array, *obj;
    char *repo_id = repo->id;

    server = get_notif_server (mgr, repo->server_url);
    if (!server || server->status != STATUS_CONNECTED) {
        goto out;
    }

    json_msg = json_object ();
    json_object_set_new (json_msg, "type", json_string("unsubscribe"));

    content = json_object ();

    array = json_array ();

    obj = json_object ();
    json_object_set_new (obj, "id", json_string(repo_id));
    json_array_append_new (array, obj);

    json_object_set_new (content, "repos", array);

    json_object_set_new (json_msg, "content", content);

    str = json_dumps (json_msg, JSON_COMPACT);
    if (!str)
        goto out;

    Message *msg = notif_message_new (str, LWS_WRITE_TEXT);
    if (!msg)
        goto out;

    g_async_queue_push (server->messages, msg);

    pthread_mutex_lock (&server->sub_lock);
    g_hash_table_remove (server->subscriptions, repo_id);
    pthread_mutex_unlock (&server->sub_lock);

    seaf_debug ("Successfully unsubscribe repo %s\n", repo_id);

out:
    g_free (str);
    json_decref (json_msg);
    notif_server_unref (server);
}

gboolean
seaf_notif_manager_is_repo_subscribed (SeafNotifManager *mgr, SeafRepo *repo)
{
    NotifServer *server = NULL;
    gboolean subscribed = FALSE;

    server = get_notif_server (mgr, repo->server_url);
    if (!server || server->status != STATUS_CONNECTED) {
        goto out;
    }

    pthread_mutex_lock (&server->sub_lock);
    if (g_hash_table_lookup (server->subscriptions, repo->id)) {
        pthread_mutex_unlock (&server->sub_lock);
        subscribed = TRUE;
        goto out;
    }
    pthread_mutex_unlock (&server->sub_lock);

out:
    notif_server_unref (server);
    return subscribed;
}
