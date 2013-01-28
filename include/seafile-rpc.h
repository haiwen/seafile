
#ifndef _SEAFILE_RPC_H
#define _SEAFILE_RPC_H

#include "seafile-object.h"

/**
 * seafile_get_session_info:
 *
 * Returns: a SeafileSessionInfo object.
 */
GObject *
seafile_get_session_info (GError **error);

/**
 * seafile_get_repo_list:
 *
 * Returns repository list.
 */
GList* seafile_get_repo_list (int start, int limit, GError **error);

/**
 * seafile_get_commit_list:
 *
 * @limit: if limit <= 0, all commits start from @offset will be returned.
 *
 * Returns: commit list of a given repo.
 *
 * Possible Error:
 *    1. Bad Argument
 *    2. No head and branch master
 *    3. Failed to list commits
 */
GList* seafile_get_commit_list (const gchar *repo,
                                int offset,
                                int limit,
                                GError **error);

/**
 * seafile_get_commit:
 * @id: the commit id.
 *
 * Returns: the commit object.
 */
GObject* seafile_get_commit (const gchar *id, GError **error);

/**
 * seafile_get_repo:
 *
 * Returns: repo
 */
GObject* seafile_get_repo (const gchar* id, GError **error);

GObject *
seafile_get_repo_sync_task (const char *repo_id, GError **error);

/**
 * seafile_get_repo_sync_info:
 */
GObject *
seafile_get_repo_sync_info (const char *repo_id, GError **error);

GList*
seafile_get_repo_sinfo (const char *repo_id, GError **error);

/* [seafile_get_config] returns the value of the config entry whose name is
 * [key] in config.db
 */
char *seafile_get_config (const char *key, GError **error);

/* [seafile_set_config] set the value of config key in config.db; old value
 * would be overwritten. */
int seafile_set_config (const char *key, const char *value, GError **error);

/**
 * seafile_destroy_repo:
 * @repo_id: repository id.
 */
int seafile_destroy_repo (const gchar *repo_id, GError **error);

/**
 * seafile_edit_repo:
 * @repo_id: repository id.
 * @name: new name of the repository, NULL if unchanged.
 * @description: new description of the repository, NULL if unchanged.
 */
int seafile_edit_repo (const gchar *repo_id, 
		       const gchar *name, 
		       const gchar *description,
		       GError **error);

/**
 * seafile_repo_size:
 * 
 * Returns: the size of a repo
 *
 * Possible Error:
 *   1. Bad Argument
 *   2. No local branch (No local branch record in branch.db)
 *   3. Database error
 *   4. Calculate branch size error
 */
gint64
seafile_repo_size(const gchar *repo_id, GError **error);

int
seafile_repo_last_modify(const char *repo_id, GError **error);

int seafile_set_repo_lantoken (const gchar *repo_id,
                               const gchar *token,
                               GError **error);

gchar* seafile_get_repo_lantoken (const gchar *repo_id,
                                  GError **error);

int
seafile_set_repo_property (const char *repo_id,
                           const char *key,
                           const char *value,
                           GError **error);

gchar *
seafile_get_repo_property (const char *repo_id,
                           const char *key,
                           GError **error);

char *
seafile_get_repo_relay_address (const char *repo_id,
                                GError **error);

char *
seafile_get_repo_relay_port (const char *repo_id,
                             GError **error);

int
seafile_update_repo_relay_info (const char *repo_id,
                                const char *new_addr,
                                const char *new_port,
                                GError **error);

int seafile_disable_auto_sync (GError **error);

int seafile_enable_auto_sync (GError **error);

int seafile_is_auto_sync_enabled (GError **error);


/**
 * seafile_add:
 * Add a file or files under a directory to the index of a repository.
 * @repo_id: repository id.
 * @path: the path of a file or a directory, if path is empty
 * string(""), the repo root directory will be added.
 */
int seafile_add (const gchar *repo_id, const gchar *path, GError **error);

/**
 * seafile_rm:
 * Remove a file or files under a directory from the index of a repository.
 */
int seafile_rm (const gchar *repo_id, const gchar *path, GError **error);

/**
 * seafile_repo_gets:
 * Get branches of a repo.
 */
GList *seafile_branch_gets (const gchar *repo_id, GError **error);

/**
 * seafile_branch_add:
 * Add a new branch.
 * @original_branch: the original branch, if it is NULL or it is "HEAD",
 * the commit of the new branch will be set to the HEAD commit.
 */
int seafile_branch_add (const gchar *repo_id, const gchar *branch_name,
                        const char *original_branch, GError **error);

/**
 * seafile_branch_del:
 * Del a branch.
 */
int seafile_branch_del (const gchar *repo_id, const gchar *branch_name, GError **error);

/**
 * seafile_status:
 * Show the working tree status.
 */
const gchar *seafile_status (const gchar *repo_id, GError **error);

/**
 * seafile_commit:
 * Commit current index.
 */
const gchar* seafile_commit (const gchar *repo_id, const gchar *desc, GError **error);


/**
 * seafile_set_worktree:
 *
 */
int seafile_set_worktree (const gchar *repo_id,
                          const char *path,
                          GError **error);


/**
 * seafile_checkout:
 * @repo_id:
 * @passwd: password to decrypt if the repo is encrypted
 *
 * Checkout the content of "local" branch.
 *  
 * Returns: 0 if ok, -1 on error.
 */
int seafile_checkout (const gchar *repo_id,
                      const char *passwd,
                      GError **error);

/**
 * seafile_list_dir:
 * List a directory.
 *
 * Returns: a list of dirents.
 */
GList * seafile_list_dir (const char *dir_id, GError **error);

/**
 * seafile_list_dir_by_path:
 * List a directory in a commit by the path of the directory.
 *
 * Returns: a list of dirents.
 */
GList * seafile_list_dir_by_path (const char *commit_id, const char *path, GError **error);

/**
 * seafile_get_dirid_by_path:
 * Get the dir_id of the path
 *
 * Returns: the dir_id of the path
 */
char * seafile_get_dirid_by_path (const char *commit_id, const char *path, GError **error);

/**
 * seafile_reset:
 * Reset the repo head to a commit.
 */
int seafile_reset (const char *repo_id, const char *commit, GError **error);

/**
 * seafile_revert:
 * Reset the repo to a previous state by creating a new commit.
 */
int seafile_revert (const char *repo_id, const char *commit, GError **error);

/**
 * seafile_merge:
 *
 */
int seafile_merge (const char *repo_id, const char *branch, GError **error);

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
              GError **error);

char *
seafile_gen_default_worktree (const char *worktree_parent,
                              const char *repo_name,
                              GError **error);

/**
 * seafile_clone:
 *
 * Fetch a new repo and then check it out.
 */
char *
seafile_clone (const char *repo_id, 
               const char *peer_id,
               const char *repo_name,
               const char *worktree,
               const char *token,
               const char *passwd,
               const char *magic,
               const char *peer_addr,
               const char *peer_port,
               const char *email,
               GError **error);

char *
seafile_download (const char *repo_id, 
                  const char *peer_id,
                  const char *repo_name,
                  const char *wt_parent,
                  const char *token,
                  const char *passwd,
                  const char *magic,
                  const char *peer_addr,
                  const char *peer_port,
                  const char *email,
                  GError **error);

int
seafile_cancel_clone_task (const char *repo_id, GError **error);

int
seafile_remove_clone_task (const char *repo_id, GError **error);

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

/**
 * seafile_synclan:
 *
 * Sync a repo with a peer in lan.
 */
int
seafile_synclan (const char *repo_id, const char *peer_id,
                 const char *token, GError **error);

/**
 * seafile_upload:
 *
 * Returns: task id.
 */
char *seafile_upload (const gchar *repo_id,
                    const gchar *from_branch,
                    const gchar *to_branch,
                    GError **error);

/**
 * seafile_fetch:
 *
 * Returns: task id.
 */
char *seafile_fetch (const gchar *repo_id,
                     const char *peer_id,
                     const gchar *from_branch,
                     const gchar *to_branch,
                     const gchar *token, 
                     GError **error);

/**
 * seafile_fetchlan:
 *
 * Returns: task id.
 */
char *
seafile_fetchlan (const char *repo_id, 
                  const char *peer_id,
                  const char *from_branch, 
                  const char *to_branch, 
                  const char *token,
                  GError **error);

/**
 * seafile_get_total_block_size:
 *
 * Get the sum of size of all the blocks.
 */
gint64
seafile_get_total_block_size (GError **error);


/**
 * seafile_get_commit_tree_block_number:
 *
 * Get the number of blocks belong to the commit tree.
 *
 * @commit_id: the head of the commit tree.
 *
 * Returns: -1 if the calculation is in progress, -2 if error, >=0 otherwise.
 */
int
seafile_get_commit_tree_block_number (const char *commit_id, GError **error);


/**
 * seafile_gc:
 * Start garbage collection.
 */
int
seafile_gc (GError **error);

/**
 * seafile_gc_get_progress:
 * Get progress of GC.
 *
 * Returns:
 *     progress of GC in precentage.
 *     -1 if GC is not running.
 */
/* int */
/* seafile_gc_get_progress (GError **error); */

/* -----------------  Task Related --------------  */

/**
 * seafile_get_upload_task_list:
 *
 * List all the upload tasks.
 *
 * Returns: A list of task info.
 */
GList* seafile_get_upload_task_list (GError **error);


/**
 * seafile_get_download_task_list:
 *
 * List all the download tasks.
 *
 * Returns: A list of task info.
 */
GList* seafile_get_download_task_list (GError **error);


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
 * Return 1 if user is the owner of repo, otherwise return 0.
 */
int
seafile_is_repo_owner (const char *email, const char *repo_id,
                       GError **error);
/**
 * Return owner id of repo
 */
char *
seafile_get_repo_owner(const char *repo_id, GError **error);


GList *
seafile_list_owned_repos (const char *email, GError **error);

/**
 * seafile_add_chunk_server:
 * @server: ID for the chunk server.
 *
 * Add a chunk server on a relay server.
 */
int seafile_add_chunk_server (const char *server, GError **error);

/**
 * seafile_del_chunk_server:
 * @server: ID for the chunk server.
 *
 * Delete a chunk server on a relay server.
 */
int seafile_del_chunk_server (const char *server, GError **error);

/**
 * seafile_list_chunk_servers:
 *
 * List chunk servers set on a relay server.
 */
char *seafile_list_chunk_servers (GError **error);

int seafile_set_monitor (const char *monitor, GError **error);

char *seafile_get_monitor (GError **error);

gint64 seafile_get_user_quota_usage (const char *email, GError **error);

gint64 seafile_get_user_share_usage (const char *email, GError **error);

gint64 seafile_get_org_quota_usage (int org_id, GError **error);

gint64
seafile_get_org_user_quota_usage (int org_id, const char *user, GError **error);

gint64
seafile_server_repo_size(const char *repo_id, GError **error);

int
seafile_repo_set_access_property (const char *repo_id, const char *ap,
                                  GError **error);

char *
seafile_repo_query_access_property (const char *repo_id, GError **error);

char *
seafile_web_get_access_token (const char *repo_id,
                              const char *obj_id,
                              const char *op,
                              const char *username,
                              GError **error);

GObject *
seafile_web_query_access_token (const char *token, GError **error);

GObject *
seafile_get_checkout_task (const char *repo_id, GError **error);

GList *
seafile_get_sync_task_list (GError **error);

int
seafile_add_share (const char *repo_id, const char *from_email,
                   const char *to_email, const char *permission,
                   GError **error);

GList *
seafile_list_share_repos (const char *email, const char *type,
                          int start, int limit, GError **error);

GList *
seafile_list_org_share_repos (int org_id, const char *email, const char *type,
                              int start, int limit, GError **error);

int
seafile_remove_share (const char *repo_id, const char *from_email,
                      const char *to_email, GError **error);

int
seafile_group_share_repo (const char *repo_id, int group_id,
                          const char *user_name, const char *permission,
                          GError **error);
int
seafile_group_unshare_repo (const char *repo_id, int group_id,
                            const char *user_name, GError **error);

/* Get groups that a repo is shared to */
char *
seafile_get_shared_groups_by_repo(const char *repo_id, GError **error);

char *
seafile_get_group_repoids (int group_id, GError **error);

GList *
seafile_get_group_repos_by_owner (char *user, GError **error);

char *
seafile_get_group_repo_owner (const char *repo_id, GError **error);

int
seafile_remove_repo_group(int group_id, const char *username, GError **error);

GList *
seafile_get_org_repo_list (int org_id, int start, int limit, GError **error);

int
seafile_remove_org_repo_by_org_id (int org_id, GError **error);

GList *
seafile_list_org_repos_by_owner (int org_id, const char *user, GError **error);

char *
seafile_get_org_repo_owner (const char *repo_id, GError **error);

gint64
seafile_get_file_size (const char *file_id, GError **error);

gint64
seafile_get_dir_size (const char *dir_id, GError **error);

int
seafile_set_repo_history_limit (const char *repo_id,
                                int days,
                                GError **error);

int
seafile_get_repo_history_limit (const char *repo_id,
                                GError **error);

int
seafile_set_passwd (const char *repo_id,
                    const char *user,
                    const char *passwd,
                    GError **error);

int
seafile_unset_passwd (const char *repo_id,
                      const char *user,
                      GError **error);

int
seafile_is_passwd_set (const char *repo_id, const char *user, GError **error);

GObject *
seafile_get_decrypt_key (const char *repo_id, const char *user, GError **error);

int
seafile_revert_on_server (const char *repo_id,
                          const char *commit_id,
                          const char *user_name,
                          GError **error);

/**
 * Add a file into the repo on server.
 * The content of the file is stored in a temporary file.
 * @repo_id: repo id
 * @temp_file_path: local file path, should be a temp file just uploaded.
 * @parent_dir: the parent directory to put the file in.
 * @file_name: the name of the target file.
 * @user: the email of the user who uploaded the file.
 */
int
seafile_post_file (const char *repo_id, const char *temp_file_path,
                  const char *parent_dir, const char *file_name,
                  const char *user,
                  GError **error);

/**
 * Add multiple files at once.
 *
 * @filenames_json: json array of filenames
 * @paths_json: json array of temp file paths
 */
int
seafile_post_multi_files (const char *repo_id,
                          const char *parent_dir,
                          const char *filenames_json,
                          const char *paths_json,
                          const char *user,
                          GError **error);

int
seafile_post_empty_file (const char *repo_id, const char *parent_dir,
                         const char *new_file_name, const char *user,
                         GError **error);

/**
 * Update an existing file in a repo
 * @params: same as seafile_post_file
 * @head_id: the commit id for the original file version.
 *           It's optional. If it's NULL, the current repo head will be used.
 */
int
seafile_put_file (const char *repo_id, const char *temp_file_path,
                  const char *parent_dir, const char *file_name,
                  const char *user, const char *head_id,
                  GError **error);

int
seafile_post_dir (const char *repo_id, const char *parent_dir,
                  const char *new_dir_name, const char *user,
                  GError **error);

/**
 * delete a file/directory from the repo on server.
 * @repo_id: repo id
 * @parent_dir: the parent directory of the file to be deleted
 * @file_name: the name of the target file.
 * @user: the email of the user who uploaded the file.
 */
int
seafile_del_file (const char *repo_id, 
                  const char *parent_dir, const char *file_name,
                  const char *user,
                  GError **error);

/**
 * copy a file/directory from a repo to another on server.
 */
int
seafile_copy_file (const char *src_repo_id,
                   const char *src_dir,
                   const char *src_filename,
                   const char *dst_repo_id,
                   const char *dst_dir,
                   const char *dst_filename,
                   const char *user,
                   GError **error);


int
seafile_move_file (const char *src_repo_id,
                   const char *src_dir,
                   const char *src_filename,
                   const char *dst_repo_id,
                   const char *dst_dir,
                   const char *dst_filename,
                   const char *user,
                   GError **error);

int
seafile_rename_file (const char *repo_id,
                     const char *parent_dir,
                     const char *oldname,
                     const char *newname,
                     const char *user,
                     GError **error);

/**
 * Return non-zero if filename is valid.
 */
int
seafile_is_valid_filename (const char *repo_id,
                           const char *filename,
                           GError **error);


int
seafile_set_user_quota (const char *user, gint64 quota, GError **error);

gint64
seafile_get_user_quota (const char *user, GError **error);

int
seafile_set_org_quota (int org_id, gint64 quota, GError **error);

gint64
seafile_get_org_quota (int org_id, GError **error);

int
seafile_set_org_user_quota (int org_id, const char *user, gint64 quota, GError **error);

gint64
seafile_get_org_user_quota (int org_id, const char *user, GError **error);

int
seafile_check_quota (const char *repo_id, GError **error);

char *
seafile_get_file_id_by_path (const char *repo_id, const char *path,
                             GError **error);

char *
seafile_get_dir_id_by_path (const char *repo_id, const char *path,
                            GError **error);

/**
 * Return a list of commits where every commit contains a unique version of
 * the file.
 */
GList *
seafile_list_file_revisions (const char *repo_id,
                             const char *path,
                             int limit,
                             GError **error);

GList *
seafile_calc_files_last_modified (const char *repo_id,
                                  const char *parent_dir,
                                  int limit,
                                  GError **error);

int
seafile_revert_file (const char *repo_id,
                     const char *commit_id,
                     const char *path,
                     const char *user,
                     GError **error);

int
seafile_revert_dir (const char *repo_id,
                    const char *commit_id,
                    const char *path,
                    const char *user,
                    GError **error);

/*
 * @show_days: return deleted files in how many days, return all if 0.
 */
GList *
seafile_get_deleted (const char *repo_id, int show_days, GError **error);

int seafile_set_repo_token (const char *repo_id,
                            const char *email,
                            const char *token,
                            GError **error);

/**
 * Returns the token of the repo for the specified email user. If the token
 * not exist yet, a new one is generated.
 */
char* seafile_get_repo_token_nonnull (const char *repo_id,
                                      const char *email,
                                      GError **error);

/**
 * create a repo on seahub
 */
char *
seafile_create_repo (const char *repo_name,
                     const char *repo_desc,
                     const char *owner_email,
                     const char *passwd,
                     GError **error);

char *
seafile_create_org_repo (const char *repo_name,
                         const char *repo_desc,
                         const char *user,
                         const char *passwd,
                         int org_id,
                         GError **error);

int
seafile_get_org_id_by_repo_id (const char *repo_id, GError **error);

char *
seafile_check_permission (const char *repo_id, const char *user, GError **error);

int
seafile_add_org_group_repo (const char *repo_id,
                            int org_id,
                            int group_id,
                            const char *owner,
                            const char *permission,
                            GError **error);

int
seafile_del_org_group_repo (const char *repo_id,
                            int org_id,
                            int group_id,
                            GError **error);

char *
seafile_get_org_group_repoids (int org_id, int group_id, GError **error);

char *
seafile_get_org_group_repo_owner (int org_id, int group_id,
                                  const char *repo_id, GError **error);

GList *
seafile_get_org_group_repos_by_owner (int org_id, const char *user,
                                      GError **error);

char *
seafile_get_org_groups_by_repo (int org_id, const char *repo_id,
                                GError **error);

int
seafile_set_inner_pub_repo (const char *repo_id,
                            const char *permission,
                            GError **error);

int
seafile_unset_inner_pub_repo (const char *repo_id, GError **error);

GList *
seafile_list_inner_pub_repos (GError **error);

GList *
seafile_list_inner_pub_repos_by_owner (const char *user, GError **error);

int
seafile_is_inner_pub_repo (const char *repo_id, GError **error);

int
seafile_set_org_inner_pub_repo (int org_id,
                                const char *repo_id,
                                const char *permission,
                                GError **error);

int
seafile_unset_org_inner_pub_repo (int org_id, const char *repo_id, GError **error);

GList *
seafile_list_org_inner_pub_repos (int org_id, GError **error);

GList *
seafile_list_org_inner_pub_repos_by_owner (int org_id,
                                           const char *user,
                                           GError **error);

int
seafile_set_share_permission (const char *repo_id,
                              const char *from_email,
                              const char *to_email,
                              const char *permission,
                              GError **error);

int
seafile_set_group_repo_permission (int group_id,
                                   const char *repo_id,
                                   const char *permission,
                                   GError **error);

int
seafile_set_org_group_repo_permission (int org_id,
                                       int group_id,
                                       const char *repo_id,
                                       const char *permission,
                                       GError **error);
char *
seafile_get_file_id_by_commit_and_path(const char *commit_id,
                                       const char *path,
                                       GError **error);

/* ------------------ Public RPC calls. ------------ */

GList* seafile_get_repo_list_pub (int start, int limit, GError **error);

GObject* seafile_get_repo_pub (const gchar* id, GError **error);

GList* seafile_get_commit_list_pub (const gchar *repo,
                                    int offset,
                                    int limit,
                                    GError **error);

GObject* seafile_get_commit_pub (const gchar *id, GError **error);

char *seafile_diff_pub (const char *repo_id, const char *old, const char *new,
                        GError **error);

GList * seafile_list_dir_pub (const char *dir_id, GError **error);

#endif
