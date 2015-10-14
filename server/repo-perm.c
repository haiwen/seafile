/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet.h>
#include <ccnet/ccnet-object.h>
#include "utils.h"
#include "log.h"
#include "seafile.h"

#include "seafile-session.h"
#include "repo-mgr.h"

#include "seafile-error.h"

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
    char *owner = NULL;
    char *permission = NULL;

    /* If I'm the owner of origin repo, I have full access to sub-repos. */
    owner = seaf_repo_manager_get_repo_owner (mgr, origin_repo_id);
    if (g_strcmp0 (user, owner) == 0) {
        permission = g_strdup("rw");
        return permission;
    }
    g_free (owner);

    /* If I'm not the owner of origin repo, this sub-repo can be created
     * from a shared repo by me or directly shared by others to me.
     * The priority of shared sub-folder is higher than top-level repo.
     */
    permission = check_repo_share_permission (mgr, repo_id, user);
    if (permission)
        return permission;

    permission = check_repo_share_permission (mgr, origin_repo_id, user);
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

/*
 * Directories are always before files. Otherwise compare the names.
 */
static gint
comp_dirent_func (gconstpointer a, gconstpointer b)
{
    const SeafDirent *dent_a = a, *dent_b = b;

    if (S_ISDIR(dent_a->mode) && S_ISREG(dent_b->mode))
        return -1;

    if (S_ISREG(dent_a->mode) && S_ISDIR(dent_b->mode))
        return 1;

    return strcasecmp (dent_a->name, dent_b->name);
}

GList *
seaf_repo_manager_list_dir_with_perm (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      const char *dir_path,
                                      const char *dir_id,
                                      const char *user,
                                      int offset,
                                      int limit,
                                      GError **error)
{
    SeafRepo *repo;
    char *perm = NULL;
    SeafDir *dir;
    SeafDirent *dent;
    SeafileDirent *d;
    GList *res = NULL;
    GList *p;

    if (!repo_id || !is_uuid_valid(repo_id) || dir_id == NULL || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_DIR_ID, "Bad dir id");
        return NULL;
    }

    perm = seaf_repo_manager_check_permission (mgr, repo_id, user, error);
    if (!perm) {
        if (*error == NULL)
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Access denied");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad repo id");
        g_free (perm);
        return NULL;
    }

    dir = seaf_fs_manager_get_seafdir (seaf->fs_mgr,
                                       repo->store_id, repo->version, dir_id);
    if (!dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_DIR_ID, "Bad dir id");
        seaf_repo_unref (repo);
        g_free (perm);
        return NULL;
    }

    dir->entries = g_list_sort (dir->entries, comp_dirent_func);

    if (offset < 0) {
        offset = 0;
    }

    int index = 0;
    gboolean is_shared;
    char *cur_path;
    GHashTable *shared_sub_dirs = NULL;

    if (!repo->virtual_info) {
        char *repo_owner = seaf_repo_manager_get_repo_owner (seaf->repo_mgr, repo_id);
        if (repo_owner && strcmp (user, repo_owner) == 0) {
            shared_sub_dirs = seaf_share_manager_get_shared_sub_dirs (seaf->share_mgr,
                                                                      repo->store_id,
                                                                      dir_path);
        }
        g_free (repo_owner);
    }

    for (p = dir->entries; p != NULL; p = p->next, index++) {
        if (index < offset) {
            continue;
        }

        if (limit > 0) {
            if (index >= offset + limit)
                break;
        }

        dent = p->data;

        if (!is_object_id_valid (dent->id))
            continue;

        d = g_object_new (SEAFILE_TYPE_DIRENT,
                          "obj_id", dent->id,
                          "obj_name", dent->name,
                          "mode", dent->mode,
                          "version", dent->version,
                          "mtime", dent->mtime,
                          "size", dent->size,
                          "permission", perm,
                          NULL);

        if (shared_sub_dirs && S_ISDIR(dent->mode)) {
            if (strcmp (dir_path, "/") == 0) {
                cur_path = g_strconcat (dir_path, dent->name, NULL);
            } else {
                cur_path = g_strconcat (dir_path, "/", dent->name, NULL);
            }
            is_shared = g_hash_table_lookup (shared_sub_dirs, cur_path) ? TRUE : FALSE;
            g_free (cur_path);
            g_object_set (d, "is_shared", is_shared, NULL);
        }
        res = g_list_prepend (res, d);
    }

    if (shared_sub_dirs)
        g_hash_table_destroy (shared_sub_dirs);
    seaf_dir_free (dir);
    seaf_repo_unref (repo);
    g_free (perm);
    if (res)
        res = g_list_reverse (res);

    return res;
}
