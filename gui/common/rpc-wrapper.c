#include <ccnet.h>
#include <ccnetrpc-transport.h>
#include <seafile.h>

#include "rpc-wrapper.h"
#include "applet-log.h"
#include "utils.h"
#include "seafile-applet.h"

#include <searpc-client.h>


void 
applet_init_ccnet_rpc (CcnetClient *sync_client)
{
    applet->ccnet_rpc_client = ccnet_create_rpc_client (
        sync_client, NULL, "ccnet-rpcserver");
}

void 
applet_init_seafile_rpc (CcnetClient *client)
{
    /* async searpc client, for invoking seafile rpc */    
    applet->seafile_rpc_client = ccnet_create_async_rpc_client (
        client, NULL, "seafile-rpcserver");
}

gboolean 
need_login_relay (void)
{
    char *login_finished = ccnet_get_config (applet->ccnet_rpc_client, "login_finished");
    gboolean ret = TRUE;
    
    if (!login_finished) {
        return TRUE;
    } else {
        ret = !(strcmp(login_finished, "true") == 0);
        g_free (login_finished);
    }

    return ret;
}

gboolean 
need_set_relay (void)
{
    if (!need_login_relay ()) {
        return FALSE;
    }

    CcnetPeer *relay = ccnet_get_default_relay (applet->ccnet_rpc_client);
    if (relay) {
        g_object_unref (relay);
        return FALSE;
    }

    g_object_unref (relay);
    return TRUE;
}

void
do_login_relay (const char *username, const char *passwd)
{
    CcnetPeer *relay = ccnet_get_default_relay (applet->ccnet_rpc_client);
    if (!relay) {
        applet_warning ("Relay is not set\n");
        return;
    }

    ccnet_login_to_relay (applet->ccnet_rpc_client, relay->id, username, passwd);
    g_object_unref (relay);
}

int
get_login_status (void)
{
    CcnetPeer *relay = ccnet_get_default_relay (applet->ccnet_rpc_client);
    if (!relay)
        return -1;

    if (relay->bind_status == BIND_YES) {
        g_object_unref (relay);
        return 0;
    }
    
    int result = 1;
    if (!relay->login_started) {
        result = -1;
    } else if (relay->login_error) {
        result = -1;
    }

    g_object_unref (relay);
    return result;
}

int
get_conn_relay_status (void)
{
    CcnetPeer *relay = ccnet_get_default_relay (applet->ccnet_rpc_client);
    if (!relay) {
        applet_warning ("get_default_relay() returned NULL\n");
        return -1;
    }
    
    int result;
    if (relay->net_state == PEER_CONNECTED) {
        result = 0;
    } else if (relay->in_connection) {
        result = 1;
    } else {
        result = -1;
        applet_warning ("failed to connect relay\n");
    }
    
    g_object_unref (relay);
    return result;
}

int
call_seafile_create_repo (const char *name_in, const char *desc_in,
                          const char *path_in, const char *relay_id,
                          const char *passwd, int keep_local_history,
                          AsyncCallback callback, void *data)
{
    char *name, *desc, *path;
    name = ccnet_locale_to_utf8(name_in);
    desc = ccnet_locale_to_utf8(desc_in);
    path = ccnet_locale_to_utf8(path_in);

    int res = seafile_create_repo_async (applet->seafile_rpc_client, name, desc, path,
                                         passwd, relay_id, keep_local_history, 
                                         callback, data);

    applet_message ("creating repo: name = %s\n, desc = %s\n, path = %s\n, relay_id = %s\n",
                    name_in, desc_in, path_in, relay_id);
    
    g_free (name);
    g_free (desc);
    g_free (path);

    return res;
}

int
call_seafile_get_config (char *key, AsyncCallback callback, void *data)
{
    return seafile_get_config_async (applet->seafile_rpc_client, key,
                                     callback, data);
}

int
call_seafile_set_config (char *key, char *value,
                         AsyncCallback callback, void *data)
{
    return seafile_set_config_async (applet->seafile_rpc_client, key, value,
                                     callback, data);
}

char *
relay_name_to_id (GList *relays, const char *name)
{
    GList *ptr;
    for (ptr = relays; ptr; ptr = ptr->next) {
        CcnetPeer *relay = ptr->data;
        if (g_strcmp0(relay->name, name) == 0) {
            return g_strdup(relay->id);
        }
    }
    return NULL;
}

void
free_relay_list (GList *relays)
{
    GList *ptr;
    for (ptr = relays; ptr; ptr = ptr->next) {
        CcnetPeer *relay = ptr->data;
        g_object_unref (relay);
    }
}

GList *
get_relay_list (void)
{
    GList *relays = ccnet_get_peers_by_role (applet->ccnet_rpc_client, "MyRelay");
    if (!relays) return NULL;

    
    CcnetPeer *default_relay = ccnet_get_default_relay (applet->ccnet_rpc_client);
    if (!default_relay)
        return relays;

    /* append default relay to head */
    GList *ptr;
    for (ptr = relays; ptr; ptr = ptr->next) {
        CcnetPeer *relay = ptr->data;
        if (g_strcmp0(relay->id, default_relay->id) == 0) {
            relays = g_list_remove (relays, relay);
            relays = g_list_prepend (relays, relay);
            break;
        }
    }

    g_object_unref (default_relay);
    return relays;
}
