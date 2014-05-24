/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <config.h>
#include <stdint.h>
#include <unistd.h>
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
seafile_get_config_async (SearpcClient *client, const char *key,
                          AsyncCallback callback, void *user_data)
{
    if (!key)
        return -1;

    return searpc_client_async_call__string (
        client, "seafile_get_config", callback, user_data,
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


int seafile_set_config_async (SearpcClient *client,
                              const char *key, const char *value,
                              AsyncCallback callback, void *user_data)
{
    if (!key || !value)
        return -1;

    return searpc_client_async_call__int (
        client, "seafile_set_config", callback, user_data,
        2, "string", key, "string", value);   
}

char *
seafile_create_repo (SearpcClient *client,
                     const gchar *name, 
                     const gchar *description,
                     const gchar *worktree,
                     const gchar *passwd,
                     const gchar *relay_id,
                     int keep_local_history,
                     GError **error)
{
    g_return_val_if_fail (client && name && description && worktree, NULL);

    return searpc_client_call__string (
        client, "seafile_create_repo", error,
        6, "string", name, "string", description,
        "string", worktree, "string", passwd,
        "string", relay_id, "int", keep_local_history);
}

int
seafile_create_repo_async (SearpcClient *client,
                           const gchar *name, 
                           const gchar *description,
                           const gchar *worktree,
                           const gchar *passwd,
                           const gchar *relay_id,
                           int keep_local_history,
                           AsyncCallback callback, void *user_data)
{
    g_return_val_if_fail (client && name && description && worktree, -1);

    return searpc_client_async_call__string (
        client, "seafile_create_repo", callback, user_data,
        6, "string", name, "string", description,
        "string", worktree, "string", passwd,
        "string", relay_id, "int", keep_local_history);
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


int
seafile_add_chunk_server (SearpcClient *client,
                          const char *server_id, GError **error)
{
    if (!server_id)
        return -1;

    return searpc_client_call__int (
        client, "seafile_add_chunk_server", error, 
        1, "string", server_id);
}

int
seafile_del_chunk_server (SearpcClient *client,
                          const char *server_id, GError **error)
{
    if (!server_id)
        return -1;

    return searpc_client_call__int (
        client, "seafile_del_chunk_server", error, 
        1, "string", server_id);
}

char *
seafile_list_chunk_servers (SearpcClient *client, GError **error)
{
    return searpc_client_call__string (
        client, "seafile_list_chunk_servers", error,
        0);
}

char *
seafile_repo_query_access_property (SearpcClient *client,
                                    const char *repo_id,
                                    GError **error)
{
    return searpc_client_call__string (
        client, "seafile_repo_query_access_property", error,
        1, "string", repo_id);
}

GObject *
seafile_web_query_access_token (SearpcClient *client,
                                const char *token,
                                GError **error)
{
    return searpc_client_call__object (
        client, "seafile_web_query_access_token", SEAFILE_TYPE_WEB_ACCESS, error,
        1, "string", token);
}

GObject *
seafile_get_decrypt_key (SearpcClient *client,
                         const char *repo_id,
                         const char *user,
                         GError **error)
{
    return searpc_client_call__object (
        client, "seafile_get_decrypt_key", SEAFILE_TYPE_CRYPT_KEY, error,
        2, "string", repo_id, "string", user);
}

char *
seafile_put_file (SearpcClient *client,
                  const char *repo_id,
                  const char *file_path,
                  const char *parent_dir,
                  const char *file_name,
                  const char *user,
                  const char *head_id,
                  GError **error)
{
    return searpc_client_call__string (client, "seafile_put_file", error,
                                    6, "string", repo_id,
                                    "string", file_path,
                                    "string", parent_dir,
                                    "string", file_name,
                                    "string", user,
                                    "string", head_id);
}

char *
seafile_put_file_blocks (SearpcClient *client,
                         const char *repo_id,
                         const char *parent_dir,
                         const char *file_name,
                         const char *blockids_json,
                         const char *paths_json,
                         const char *user,
                         const char *head_id,
                         gint64 file_size,
                         GError **error)
{
    return searpc_client_call__string (client, "seafile_put_file_blocks", error,
                                       8, "string", repo_id,
                                       "string", parent_dir,
                                       "string", file_name,
                                       "string", blockids_json,
                                       "string", paths_json,
                                       "string", user,
                                       "string", head_id,
                                       "int64", &file_size);
}

int
seafile_post_file (SearpcClient *client,
                   const char *repo_id,
                   const char *file_path,
                   const char *parent_dir,
                   const char *file_name,
                   const char *user,
                   GError **error)
{
    return searpc_client_call__int (client, "seafile_post_file", error,
                                    5, "string", repo_id,
                                    "string", file_path,
                                    "string", parent_dir,
                                    "string", file_name,
                                    "string", user);
}

char *
seafile_post_file_blocks (SearpcClient *client,
                          const char *repo_id,
                          const char *parent_dir,
                          const char *file_name,
                          const char *blockids_json,
                          const char *paths_json,
                          const char *user,
                          gint64 file_size,
                          int replace_existed,
                          GError **error)
{
    return searpc_client_call__string (client, "seafile_post_file_blocks", error,
                                       8, "string", repo_id,
                                       "string", parent_dir,
                                       "string", file_name,
                                       "string", blockids_json,
                                       "string", paths_json,
                                       "string", user,
                                       "int64", &file_size,
                                       "int", replace_existed);
}

char *
seafile_post_multi_files (SearpcClient *client,
                          const char *repo_id,
                          const char *parent_dir,
                          const char *filenames_json,
                          const char *paths_json,
                          const char *user,
                          int replace_existed,
                          GError **error)
{
    return searpc_client_call__string (client, "seafile_post_multi_files", error,
                                       6, "string", repo_id,
                                       "string", parent_dir,
                                       "string", filenames_json,
                                       "string", paths_json,
                                       "string", user,
                                       "int", replace_existed);
}

int
seafile_set_user_quota (SearpcClient *client,
                        const char *user,
                        gint64 quota,
                        GError **error)
{
    return searpc_client_call__int (client, "set_user_quota", error,
                                    2, "string", user, "int64", &quota);
}

int
seafile_set_org_quota (SearpcClient *client,
                       int org_id,
                       gint64 quota,
                       GError **error)
{
    return searpc_client_call__int (client, "set_org_quota", error,
                                    2, "int", org_id, "int64", &quota);
}

int
seafile_set_org_user_quota (SearpcClient *client,
                            int org_id,
                            const char *user,
                            gint64 quota,
                            GError **error)
{
    return searpc_client_call__int (client, "set_org_user_quota", error,
                                    3, "int", org_id,
                                    "string", user,
                                    "int64", &quota);
}

int
seafile_check_quota (SearpcClient *client,
                     const char *repo_id,
                     GError **error)
{
    return searpc_client_call__int (client, "check_quota", error,
                                    1, "string", repo_id);
}

int
seafile_disable_auto_sync_async (SearpcClient *client,
                                 AsyncCallback callback,
                                 void *user_data)
{
    return searpc_client_async_call__int (client,
                                          "seafile_disable_auto_sync",
                                          callback, user_data, 0);
}

int
seafile_enable_auto_sync_async (SearpcClient *client,
                                 AsyncCallback callback,
                                 void *user_data)
{
    return searpc_client_async_call__int (client,
                                          "seafile_enable_auto_sync",
                                          callback, user_data, 0);
}

int
seafile_is_auto_sync_enabled_async (SearpcClient *client,
                                    AsyncCallback callback,
                                    void *user_data)
{
    return searpc_client_async_call__int (client,
                                          "seafile_is_auto_sync_enabled",
                                          callback, user_data, 0);
}
