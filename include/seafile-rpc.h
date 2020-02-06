
#ifndef _SEAFILE_RPC_H
#define _SEAFILE_RPC_H

#include <jansson.h>
#include "seafile-object.h"

/**
 * seafile_get_repo_list:
 *
 * Returns repository list.
 */
GList* seafile_get_repo_list (int start, int limit, GError **error);

/**
 * seafile_get_repo:
 *
 * Returns: repo
 */
GObject* seafile_get_repo (const gchar* id, GError **error);

GObject *
seafile_get_repo_sync_task (const char *repo_id, GError **error);

/* [seafile_get_config] returns the value of the config entry whose name is
 * [key] in config.db
 */
char *seafile_get_config (const char *key, GError **error);

/* [seafile_set_config] set the value of config key in config.db; old value
 * would be overwritten. */
int seafile_set_config (const char *key, const char *value, GError **error);

int
seafile_set_config_int (const char *key, int value, GError **error);

int
seafile_get_config_int (const char *key, GError **error);

int
seafile_set_upload_rate_limit (int limit, GError **error);

int
seafile_set_download_rate_limit (int limit, GError **error);

/**
 * seafile_destroy_repo:
 * @repo_id: repository id.
 */
int seafile_destroy_repo (const gchar *repo_id, GError **error);

int
seafile_unsync_repos_by_account (const char *server_url, const char *email, GError **error);

int
seafile_remove_repo_tokens_by_account (const char *server_url, const char *email, GError **error);

int
seafile_set_repo_token (const char *repo_id, const char *token, GError **error);

int
seafile_get_download_rate(GError **error);

int
seafile_get_upload_rate(GError **error);

int
seafile_set_repo_property (const char *repo_id,
                           const char *key,
                           const char *value,
                           GError **error);

gchar *
seafile_get_repo_property (const char *repo_id,
                           const char *key,
                           GError **error);

int
seafile_update_repos_server_host (const char *old_server_url,
                                  const char *new_server_url,
                                  GError **error);

int seafile_disable_auto_sync (GError **error);

int seafile_enable_auto_sync (GError **error);

int seafile_is_auto_sync_enabled (GError **error);

char *
seafile_get_path_sync_status (const char *repo_id,
                              const char *path,
                              int is_dir,
                              GError **error);

int
seafile_mark_file_locked (const char *repo_id, const char *path, GError **error);

int
seafile_mark_file_unlocked (const char *repo_id, const char *path, GError **error);

char *
seafile_get_server_property (const char *server_url, const char *key, GError **error);

int
seafile_set_server_property (const char *server_url,
                             const char *key,
                             const char *value,
                             GError **error);

GList *
seafile_get_file_sync_errors (int offset, int limit, GError **error);

int
seafile_del_file_sync_error_by_id (int id, GError **error);

char *
seafile_gen_default_worktree (const char *worktree_parent,
                              const char *repo_name,
                              GError **error);
int
seafile_check_path_for_clone(const char *path, GError **error);

/**
 * seafile_clone:
 *
 * Fetch a new repo and then check it out.
 */
char *
seafile_clone (const char *repo_id, 
               int repo_version,
               const char *repo_name,
               const char *worktree,
               const char *token,
               const char *passwd,
               const char *magic,
               const char *email,
               const char *random_key,
               int enc_version,
               const char *more_info,
               GError **error);

char *
seafile_download (const char *repo_id, 
                  int repo_version,
                  const char *repo_name,
                  const char *wt_parent,
                  const char *token,
                  const char *passwd,
                  const char *magic,
                  const char *email,
                  const char *random_key,
                  int enc_version,
                  const char *more_info,
                  GError **error);

int
seafile_cancel_clone_task (const char *repo_id, GError **error);

/**
 * seafile_get_clone_tasks:
 *
 * Get a list of clone tasks.
 */
GList *
seafile_get_clone_tasks (GError **error);

/**
 * seafile_sync:
 *
 * Sync a repo with relay.
 */
int seafile_sync (const char *repo_id, const char *peer_id, GError **error);

/* -----------------  Task Related --------------  */

/**
 * seafile_find_transfer:
 *
 * Find a non finished task of a repo
 */
GObject *
seafile_find_transfer_task (const char *repo_id, GError *error);


int seafile_cancel_task (const gchar *task_id, int task_type, GError **error);

/**
 * Remove finished upload task
 */
int seafile_remove_task (const char *task_id, int task_type, GError **error);


/* ------------------ Relay specific RPC calls. ------------ */

/**
 * seafile_diff:
 *
 * Show the difference between @old commit and @new commit. If @old is NULL, then
 * show the difference between @new commit and its parent.
 *
 * @old and @new can also be branch name.
 */
GList *
seafile_diff (const char *repo_id, const char *old, const char *new,
              int fold_dir_diff, GError **error);

GObject *
seafile_generate_magic_and_random_key(int enc_version,
                                      const char* repo_id,
                                      const char *passwd,
                                      GError **error);
json_t * seafile_get_sync_notification (GError **error);

int
seafile_shutdown (GError **error);

char*
seafile_sync_error_id_to_str (int error_id, GError **error);
#endif
