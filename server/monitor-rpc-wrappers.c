#include "monitor-rpc-wrappers.h"

#include <ccnet/ccnetrpc-transport.h>
#include "seafile-session.h"

static SearpcClient rpc_client;

#if 0
SEARPC_CLIENT_DEFUN_INT64__STRING(monitor_get_repos_size);

SEARPC_CLIENT_ASYNC_DEFUN_INT64__STRING(monitor_get_repos_size, 0);

gint64
monitor_get_repos_size_wrapper (const char *peer_id,
                                const char *repo_list, 
                                GError **error)
{
    CcnetrpcTransportParam priv;

    priv.session = seaf->session;
    priv.peer_id = (char *)peer_id;
    priv.service = "monitor";

    rpc_client.transport = ccnetrpc_transport_send;
    rpc_client.arg = &priv;

    return monitor_get_repos_size (&rpc_client, repo_list, error);
}

void
monitor_get_repos_size_async_wrapper (const char *peer_id,
                                      const char *repo_list,
                                      AsyncCallback callback,
                                      void *user_data)
{
    CcnetrpcAsyncTransportParam priv;

    priv.session = seaf->session;
    priv.peer_id = (char *)peer_id;
    priv.service = "monitor-rpcserver";

    rpc_client.async_send = ccnetrpc_async_transport_send;
    rpc_client.async_arg = &priv;

    monitor_get_repos_size_async (&rpc_client, repo_list,
                                  callback, user_data);
}
#endif

void
monitor_compute_repo_size_async_wrapper (const char *peer_id,
                                         const char *repo_id,
                                         AsyncCallback callback,
                                         void *user_data)
{
    CcnetrpcAsyncTransportParam priv;

    priv.session = seaf->session;
    priv.peer_id = (char *)peer_id;
    priv.service = "monitor-rpcserver";

    rpc_client.async_send = ccnetrpc_async_transport_send;
    rpc_client.async_arg = &priv;

    searpc_client_async_call__int (&rpc_client, "compute_repo_size", callback,
                                   user_data, 1, "string", repo_id);
}
