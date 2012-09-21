#include <ccnet.h>
#include <ccnet/ccnetrpc-transport.h>
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

int call_seafile_disable_auto_sync (AsyncCallback callback, void *data)
{
    return seafile_disable_auto_sync_async (applet->seafile_rpc_client, callback, data);
}

int call_seafile_enable_auto_sync (AsyncCallback callback, void *data)
{
    return seafile_enable_auto_sync_async (applet->seafile_rpc_client, callback, data);
}
