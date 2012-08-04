#ifndef APPLET_RPC_SERVICE_H
#define APPLET_RPC_SERVICE_H

#define APPLET_ERR_BAD_ARGS 503

#define APPLET_DOMAIN g_quark_from_string("Seafile-applet")

void applet_start_rpc_service(struct _CcnetClient *client);

#endif
