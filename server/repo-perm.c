/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet.h>
#include <ccnet/ccnet-object.h>
#include "utils.h"
#include "log.h"
#include "seafile.h"

#include "seafile-session.h"
#include "repo-mgr.h"


/*
 * Permission priority: owner --> personal share --> group share --> public.
 * Permission with higher priority overwrites those with lower priority.
 */
static char *
check_repo_share_permission (SeafRepoManager *mgr,
                             const char *repo_id,
                             const char *user_name)
{
    SearpcClient *rpc_client;
    GList *groups, *p1;
    GList *group_perms, *p2;
    CcnetGroup *group;
    GroupPerm *perm;
    int group_id;
    char *permission;

    permission = seaf_share_manager_check_permission (seaf->share_mgr,
                                                      repo_id,
                                                      user_name);
    if (permission != NULL)
        return permission;
    g_free (permission);

    rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                 NULL,
                                                 "ccnet-threaded-rpcserver");
    if (!rpc_client)
        return NULL;

    /* Get the groups this user belongs to. */
    groups = ccnet_get_groups_by_user (rpc_client, user_name);

    ccnet_rpc_client_free (rpc_client);

    /* Get the groups this repo shared to. */
    group_perms = seaf_repo_manager_get_group_perm_by_repo (mgr, repo_id, NULL);

    permission = NULL;
    /* Check if any one group overlaps. */
    for (p1 = groups; p1 != NULL; p1 = p1->next) {
        group = p1->data;
        g_object_get (group, "id", &group_id, NULL);

        for (p2 = group_perms; p2 != NULL; p2 = p2->next) {
            perm = p2->data;
            if (group_id == perm->group_id) {
                /* If the repo is shared to more than 1 groups,
                 * and user is in more than 1 of these groups,
                 * "rw" permission will overwrite "ro" permission.
                 */
                if (g_strcmp0(perm->permission, "rw") == 0) {
                    permission = perm->permission;
                    goto group_out;
                } else if (g_strcmp0(perm->permission, "r") == 0 &&
                           !permission) {
                    permission = perm->permission;
                }
            }
        }
    }

group_out:
    if (permission != NULL)
        permission = g_strdup(permission);

    for (p1 = groups; p1 != NULL; p1 = p1->next)
        g_object_unref ((GObject *)p1->data);
    g_list_free (groups);
    for (p2 = group_perms; p2 != NULL; p2 = p2->next)
        g_free (p2->data);
    g_list_free (group_perms);

    if (permission != NULL)
        return permission;

    if (!mgr->seaf->cloud_mode)
        return seaf_repo_manager_get_inner_pub_repo_perm (mgr, repo_id);

    return NULL;
}

static char *
check_org_repo_share_permission (SeafRepoManager *mgr,
                                 int org_id,
                                 const char *repo_id,
                                 const char *user_name)
{
    SearpcClient *rpc_client;
    GList *groups, *p1;
    GList *group_perms, *p2;
    CcnetGroup *group;
    GroupPerm *perm;
    int group_id;
    char *permission;

    rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                 NULL,
                                                 "ccnet-threaded-rpcserver");
    if (!rpc_client)
        return NULL;

    if (!ccnet_org_user_exists (rpc_client, org_id, user_name)) {
        ccnet_rpc_client_free (rpc_client);
        return NULL;
    }

    permission = seaf_share_manager_check_permission (seaf->share_mgr,
                                                      repo_id,
                                                      user_name);
    if (permission != NULL) {
        ccnet_rpc_client_free (rpc_client);
        return permission;
    }
    g_free (permission);

    /* Get the groups this user belongs to. */
    groups = ccnet_get_groups_by_user (rpc_client, user_name);

    ccnet_rpc_client_free (rpc_client);

    /* Get the groups this repo shared to. */
    group_perms = seaf_repo_manager_get_org_group_perm_by_repo (mgr,
                                                                org_id,
                                                                repo_id,
                                                                NULL);

    permission = NULL;
    /* Check if any one group overlaps. */
    for (p1 = groups; p1 != NULL; p1 = p1->next) {
        group = p1->data;
        g_object_get (group, "id", &group_id, NULL);

        for (p2 = group_perms; p2 != NULL; p2 = p2->next) {
            perm = p2->data;
            if (group_id == perm->group_id) {
                /* If the repo is shared to more than 1 groups,
                 * and user is in more than 1 of these groups,
                 * "rw" permission will overwrite "ro" permission.
                 */
                if (g_strcmp0(perm->permission, "rw") == 0) {
                    permission = perm->permission;
                    goto group_out;
                } else if (g_strcmp0(perm->permission, "r") == 0 &&
                           !permission) {
                    permission = perm->permission;
                }
            }
        }
    }

group_out:
    if (permission != NULL)
        permission = g_strdup(permission);

    for (p1 = groups; p1 != NULL; p1 = p1->next)
        g_object_unref ((GObject *)p1->data);
    g_list_free (groups);
    for (p2 = group_perms; p2 != NULL; p2 = p2->next)
        g_free (p2->data);
    g_list_free (group_perms);

    if (permission != NULL)
        return permission;

    return seaf_repo_manager_get_org_inner_pub_repo_perm (mgr, org_id, repo_id);
}

/*
 * Comprehensive repo access permission checker.
 *
 * Returns read/write permission.
 */
char *
seaf_repo_manager_check_permission (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *user,
                                    GError **error)
{
    char *owner = NULL;
    int org_id;
    char *permission = NULL;

    owner = seaf_repo_manager_get_repo_owner (mgr, repo_id);
    if (owner != NULL) {
        if (strcmp (owner, user) == 0)
            permission = g_strdup("rw");
        else
            permission = check_repo_share_permission (mgr, repo_id, user);
    } else if (mgr->seaf->cloud_mode) {
        /* Org repo. */
        owner = seaf_repo_manager_get_org_repo_owner (mgr, repo_id);
        if (!owner) {
            seaf_warning ("Failed to get owner of org repo %.10s.\n", repo_id);
            goto out;
        }

        org_id = seaf_repo_manager_get_repo_org (mgr, repo_id);
        if (org_id < 0) {
            seaf_warning ("Failed to get org of repo %.10s.\n", repo_id);
            goto out;
        }

        if (strcmp (owner, user) == 0)
            permission = g_strdup("rw");
        else
            permission = check_org_repo_share_permission (mgr, org_id,
                                                          repo_id, user);
    }

out:
    g_free (owner);
    return permission;
}
