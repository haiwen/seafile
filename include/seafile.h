/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_H
#define SEAFILE_H

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

int seafile_calc_dir_size (SearpcClient *client, const char *path, GError **error);


#endif
