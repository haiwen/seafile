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
check_virtual_repo_permission (SeafRepoManager *mgr,
                               const char *repo_id,
                               const char *origin_repo_id,
                               const char *user,
                               GError **error)
{
    char *owner = NULL, *orig_owner = NULL;
    char *permission = NULL;

    owner = seaf_repo_manager_get_repo_owner (mgr, repo_id);
    if (!owner) {
        seaf_warning ("Failed to get owner for virtual repo %.10s.\n", repo_id);
        goto out;
    }

    /* If this virtual repo is not created by @user, it is shared by others. */
    if (strcmp (user, owner) != 0) {
        permission = check_repo_share_permission (mgr, repo_id, user);
        goto out;
    }

    /* otherwise check @user's permission to the origin repo. */
    permission =  seaf_repo_manager_check_permission (mgr, origin_repo_id,
                                                      user, error);

out:
    g_free (owner);
    g_free (orig_owner);
    return permission;
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
    SeafVirtRepo *vinfo;
    char *owner = NULL;
    char *permission = NULL;

    /* This is a virtual repo.*/
    vinfo = seaf_repo_manager_get_virtual_repo_info (mgr, repo_id);
    if (vinfo) {
        permission = check_virtual_repo_permission (mgr, repo_id,
                                                    vinfo->origin_repo_id,
                                                    user, error);
        goto out;
    }

    owner = seaf_repo_manager_get_repo_owner (mgr, repo_id);
    if (owner != NULL) {
        if (strcmp (owner, user) == 0)
            permission = g_strdup("rw");
        else
            permission = check_repo_share_permission (mgr, repo_id, user);
    }

out:
    seaf_virtual_repo_info_free (vinfo);
    g_free (owner);
    return permission;
}
