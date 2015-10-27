#ifndef CHECK_QUOTA_COMMON_H
#define CHECK_QUOTA_COMMON_H

#include <ccnet.h>
#include <searpc-client.h>
#include <ccnet/ccnetrpc-transport.h>

static SearpcClient *
create_sync_ccnetrpc_client (const char *central_config_dir, const char *config_dir, const char *service)
{
    if (!config_dir || !service)
        return NULL;
    
    CcnetClient *sync_client;
    SearpcClient *rpc_client;

    sync_client = ccnet_client_new ();
    if ((ccnet_client_load_confdir(sync_client, central_config_dir, config_dir)) < 0 ) {
        return NULL;
    }

    if (ccnet_client_connect_daemon (sync_client, CCNET_CLIENT_SYNC) < 0)
    {
        g_object_unref ((GObject *)sync_client);
        return NULL;
    }

    rpc_client = ccnet_create_rpc_client (sync_client, NULL, service);

    return rpc_client;
}

static void
free_sync_rpc_client (SearpcClient *rpc_client)
{
    CcnetrpcTransportParam *priv = rpc_client->arg;
    CcnetClient *client = priv->session;

    /* No need to call ccnet_client_disconnect_daemon. It's called in object
     * finalize function of ccnet client class. */
    g_object_unref ((GObject *)client);
    ccnet_rpc_client_free (rpc_client);
}

static int
check_repo_owner_quota (CcnetProcessor *processor,
                        SearpcClient *rpc_client,
                        const char *repo_id)
{
    USE_PRIV;
    char *user = NULL;
    int org_id;
    gint64 quota, usage;
    int ret = 0;

    /* repo is guranteed to exist before check_repo_owner_quota */
    user = seaf_repo_manager_get_repo_owner (seaf->repo_mgr, repo_id);
    if (user != NULL) {
        quota = seaf_quota_manager_get_user_quota (seaf->quota_mgr, user);
        if (quota <= 0)
            quota = seaf->quota_mgr->default_quota;
    } else {
        org_id = seaf_repo_manager_get_repo_org (seaf->repo_mgr, repo_id);
        if (org_id < 0) {
            priv->rsp_code = g_strdup (SC_QUOTA_ERROR);
            priv->rsp_msg = g_strdup (SS_QUOTA_ERROR);
            ret = -1;
            goto out;
        }

        quota = seaf_quota_manager_get_org_quota (seaf->quota_mgr, org_id);
        if (quota <= 0)
            quota = seaf->quota_mgr->default_quota;
    }

    if (quota == INFINITE_QUOTA)
        return ret;

    if (user)
        usage = seaf_quota_manager_get_user_usage (seaf->quota_mgr, user);
    else
        usage = seaf_quota_manager_get_org_usage (seaf->quota_mgr, org_id);

    g_debug ("quota is %"G_GINT64_FORMAT", usage is %"G_GINT64_FORMAT"\n",
             quota, usage);

    if (usage < 0) {
        priv->rsp_code = g_strdup (SC_QUOTA_ERROR);
        priv->rsp_msg = g_strdup (SS_QUOTA_ERROR);
        ret = -1;
        goto out;

    } else if (usage >= quota) {
        priv->rsp_code = g_strdup (SC_QUOTA_FULL);
        priv->rsp_msg = g_strdup (SS_QUOTA_FULL);
        ret = -1;
        goto out;
    }

out:
    g_free (user);
    
    return ret;
}

#endif
