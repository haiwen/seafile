#ifndef CHECK_QUOTA_COMMON_H
#define CHECK_QUOTA_COMMON_H

#define DEFAULT_USER_QUOTA ((gint64)1 << 31) /* 2 GB. */
#define DEFAULT_ORG_QUOTA 5 * ((gint64)1 << 30) /* 5 GB. */

static gint64
get_quota (SearpcClient *rpc_client, const char *user)
{
    CcnetOrganization *org;
    int org_id;
    gint64 quota;

    org = (CcnetOrganization *)ccnet_get_org_by_user (rpc_client, user);
    if (org) {
        g_object_get (org, "org_id", &org_id, NULL);

        /* First try to get per user quota in the organization. */
        quota = seaf_quota_manager_get_org_user_quota (seaf->quota_mgr,
                                                       org_id, user);
        if (quota > 0)
            goto out;

        /* If per user quota is not set, return the total quota for this org. */
        quota = seaf_quota_manager_get_org_quota (seaf->quota_mgr, org_id);
        if (quota <= 0)
            quota = DEFAULT_ORG_QUOTA;
    } else {
        /* If this user doesn't belong to an org, return personal quota. */
        quota = seaf_quota_manager_get_user_quota (seaf->quota_mgr, user);
        if (quota <= 0)
            quota = DEFAULT_USER_QUOTA;
    }

out:
    if (org)
        g_object_unref (org);
    return quota;
}

#include <ccnet.h>
#include <searpc-client.h>
#include <ccnetrpc-transport.h>

static SearpcClient *
create_sync_ccnetrpc_client (const char *config_dir, const char *service)
{
    if (!config_dir || !service)
        return NULL;
    
    CcnetClient *sync_client;
    SearpcClient *rpc_client;

    sync_client = ccnet_client_new ();
    if ((ccnet_client_load_confdir(sync_client, config_dir)) < 0 ) {
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
    char *email = NULL;
    gint64 quota, usage;
    int ret = 0;

    /* repo is guranteed to exist before check_repo_owner_quota */
    email = seaf_repo_manager_get_repo_owner (seaf->repo_mgr, repo_id);
    if (!email) {
        priv->rsp_code = g_strdup (SC_QUOTA_ERROR);
        priv->rsp_msg = g_strdup (SS_QUOTA_ERROR);
        ret = -1;
        goto out;
    }

    quota = get_quota (rpc_client, email);
    usage = get_user_quota_usage (seaf, email);

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
    g_free (email);
    
    return ret;
}

#endif
