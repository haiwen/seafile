/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_H
#define SEAFILE_H

char *
seafile_create_repo (SearpcClient *client,
                     const gchar *name, 
                     const gchar *description,
                     const gchar *worktree,
                     const gchar *passwd,
                     const gchar *relay_id,
                     int keep_local_history, GError **error);

int
seafile_create_repo_async (SearpcClient *client,
                           const gchar *name, 
                           const gchar *description,
                           const gchar *worktree,
                           const gchar *passwd,
                           const gchar *relay_id,
                           int keep_local_history,
                           AsyncCallback callback, void *user_data);

int seafile_destroy_repo (SearpcClient *client,
                          const char *repo_id, GError **error);

int seafile_set_repo_token (SearpcClient *client,
                            const char *repo_id,
                            const char *token,
                            GError **error);

char *
seafile_get_repo_token (SearpcClient *client,
                        const char *repo_id,
                        GError **error);


int
seafile_set_repo_property (SearpcClient *client,
                           const char *repo_id,
                           const char *key,
                           const char *value,
                           GError **error);

GList *
seafile_get_repo_list (SearpcClient *client,
                       int offset,
                       int limit, GError **error);

GObject *
seafile_get_repo (SearpcClient *client,
                  const char *repo_id,
                  GError **error);


char *seafile_get_config (SearpcClient *client, const char *key, GError **error);

int seafile_get_config_async (SearpcClient *client, const char *key,
                              AsyncCallback callback, void *user_data);

int seafile_set_config_async (SearpcClient *client,
                              const char *key, const char *value,
                              AsyncCallback callback, void *user_data);

int seafile_calc_dir_size (SearpcClient *client, const char *path, GError **error);


/* server  */
int seafile_add_chunk_server (SearpcClient *client, const char *server_id,
                              GError **error);
int seafile_del_chunk_server (SearpcClient *client, const char *server_id,
                              GError **error);
char *seafile_list_chunk_servers (SearpcClient *client, GError **error);

char *
seafile_repo_query_access_property (SearpcClient *client,
                                    const char *repo_id,
                                    GError **error);

GObject *
seafile_web_query_access_token (SearpcClient *client,
                                const char *token,
                                GError **error);

GObject *
seafile_get_decrypt_key (SearpcClient *client,
                         const char *repo_id,
                         const char *user,
                         GError **error);

char *
seafile_put_file (SearpcClient *client,
                  const char *repo_id,
                  const char *file_path,
                  const char *parent_dir,
                  const char *file_name,
                  const char *user,
                  const char *head_id,
                  GError **error);

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
                         GError **error);


int
seafile_post_file (SearpcClient *client,
                   const char *repo_id,
                   const char *file_path,
                   const char *parent_dir,
                   const char *file_name,
                   const char *user,
                   GError **error);

#define POST_FILE_ERR_FILENAME 401

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
                          GError **error);

char *
seafile_post_multi_files (SearpcClient *client,
                          const char *repo_id,
                          const char *parent_dir,
                          const char *filenames_json,
                          const char *paths_json,
                          const char *user,
                          int replace_existed,
                          GError **error);

int
seafile_set_user_quota (SearpcClient *client,
                        const char *user,
                        gint64 quota,
                        GError **error);

int
seafile_set_org_quota (SearpcClient *client,
                       int org_id,
                       gint64 quota,
                       GError **error);

int
seafile_set_org_user_quota (SearpcClient *client,
                            int org_id,
                            const char *user,
                            gint64 quota,
                            GError **error);

int
seafile_check_quota (SearpcClient *client,
                     const char *repo_id,
                     GError **error);

int
seafile_disable_auto_sync_async (SearpcClient *client,
                                 AsyncCallback callback,
                                 void *user_data);
int
seafile_enable_auto_sync_async (SearpcClient *client,
                                AsyncCallback callback,
                                void *user_data);

int
seafile_is_auto_sync_enabled_async (SearpcClient *client,
                                    AsyncCallback callback,
                                    void *user_data);

#endif
