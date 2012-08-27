#include <stdio.h>
#include <stdarg.h>

#include <ccnet.h>

#include "seafile-applet.h"
#include "opendir-proc.h"
#include "applet-rpc-service.h"

#include <searpc.h>

#include "searpc-signature.h"
#include "searpc-marshal.h"

#include <ccnet/rpcserver-proc.h>


static int
applet_get_auto_start (GError **error)
{
#ifdef WIN32
    return get_seafile_auto_start();
#else
    return 0;
#endif   
}

static int applet_set_auto_start (const char *on_off, GError **error)
{
    if (g_strcmp0(on_off, "on") == 0) {
        return set_seafile_auto_start(TRUE);
    } else if (g_strcmp0(on_off, "off") == 0) {
        return set_seafile_auto_start(FALSE);
    } else {
        g_set_error (error, APPLET_DOMAIN, APPLET_ERR_BAD_ARGS, "on_off should be either 'on' or 'off'");
        return -1;
    }

    return 0;
}

static int applet_open_dir (const char *path, GError **error)
{
    return ccnet_open_dir(path);
}

void
applet_start_rpc_service (CcnetClient *client)
{
    ccnet_register_service (client, "applet-opendir", "inner",
                            CCNET_TYPE_OPENDIR_PROC, NULL);

    searpc_server_init (register_marshals);

    searpc_create_service ("applet-rpcserver");
    ccnet_register_service (client, "applet-rpcserver", "rpc-inner",
                            CCNET_TYPE_RPCSERVER_PROC,
                            NULL);

    searpc_server_register_function ("applet-rpcserver",
                                     applet_get_auto_start,
                                     "applet_get_auto_start",
                                     searpc_signature_int__void());

    searpc_server_register_function ("applet-rpcserver",
                                     applet_set_auto_start,
                                     "applet_set_auto_start",
                                     searpc_signature_int__string());

    searpc_server_register_function ("applet-rpcserver",
                                     applet_open_dir,
                                     "applet_open_dir",
                                     searpc_signature_int__string());
}

