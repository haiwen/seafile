/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#if !defined(_MSC_VER)
#include <config.h>
#endif
#include <stdint.h>
#if !defined(_MSC_VER)
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <searpc-client.h>
#include "seafile-object.h"

char *
seafile_get_config (SearpcClient *client, const char *key)
{
    if (!key)
        return NULL;

    return searpc_client_call__string (
        client, "seafile_get_config", NULL, 
        1, "string", key);
}

int
seafile_set_config (SearpcClient *client, const char *key, const char *value)
{
    if (!key || !value)
        return -1;

    return searpc_client_call__int (
        client, "seafile_set_config", NULL,
        2, "string", key, "string", value);
}

int
seafile_destroy_repo (SearpcClient *client,
                      const char *repo_id, GError **error)
{
    g_return_val_if_fail (client && repo_id, -1);

    return searpc_client_call__int (
        client, "seafile_destroy_repo", error,
        1, "string", repo_id);
}

int
seafile_set_repo_token (SearpcClient *client,
                        const char *repo_id,
                        const char *token,
                        GError **error)
{
    g_return_val_if_fail (client && repo_id && token, -1);

    return searpc_client_call__int (
        client, "seafile_set_repo_token", error,
        2, "string", repo_id, "string", token);
}

char *
seafile_get_repo_token (SearpcClient *client,
                        const char *repo_id,
                        GError **error)
{
    g_return_val_if_fail (client && repo_id, NULL);

    return searpc_client_call__string (
        client, "seafile_get_repo_token", error,
        1, "string", repo_id);
}

GList *
seafile_get_repo_list (SearpcClient *client,
                       int offset,
                       int limit, GError **error)
{
    return searpc_client_call__objlist (
        client, "seafile_get_repo_list", SEAFILE_TYPE_REPO, error,
        2, "int", offset, "int", limit);
}

GObject *
seafile_get_repo (SearpcClient *client,
                  const char *repo_id,
                  GError **error)
{
    g_return_val_if_fail (client && repo_id, NULL);

    return searpc_client_call__object (
        client, "seafile_get_repo", SEAFILE_TYPE_REPO, error,
        1, "string", repo_id);
}

int
seafile_set_repo_property (SearpcClient *client,
                           const char *repo_id,
                           const char *key,
                           const char *value,
                           GError **error)
{
    g_return_val_if_fail (client && repo_id && key, -1);

    return searpc_client_call__int (
        client, "seafile_set_repo_property", error,
        3, "string", repo_id, "string", key, "string", value);
}

char *
seafile_get_repo_property (SearpcClient *client,
                           const char *repo_id,
                           const char *key,
                           GError **error)
{
    g_return_val_if_fail (client && repo_id, NULL);

    return searpc_client_call__string (
        client, "seafile_get_repo_property", error,
        2, "string", repo_id, "string", key);
}


int
seafile_calc_dir_size (SearpcClient *client, const char *path, GError **error)
{
    return searpc_client_call__int (client, "seafile_calc_dir_size", error,
                                    1, "string", path);
}
