/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_REPO_MGR_H
#define SEAF_REPO_MGR_H

#include "seafile-object.h"
#include "commit-mgr.h"
#include "branch-mgr.h"

#define REPO_AUTO_SYNC        "auto-sync"
#define REPO_AUTO_FETCH       "auto-fetch"
#define REPO_AUTO_UPLOAD      "auto-upload"
#define REPO_AUTO_MERGE       "auto-merge"
#define REPO_AUTO_COMMIT      "auto-commit"
#define REPO_RELAY_ID         "relay-id"
#define REPO_NET_BROWSABLE    "net-browsable"
#define REPO_DOUBLE_SYNC      "double-sync"
#define REPO_REMOTE_HEAD      "remote-head"
#define REPO_ENCRYPTED 0x1

struct _SeafRepoManager;
typedef struct _SeafRepo SeafRepo;

typedef struct SeafVirtRepo {
    char        repo_id[37];
    char        origin_repo_id[37];
    char        *path;
    char        base_commit[41];
} SeafVirtRepo;

struct _SeafRepo {
    struct _SeafRepoManager *manager;

    gchar       id[37];
    gchar      *name;
    gchar      *desc;
    gboolean    encrypted;
    int         enc_version;
    gchar       magic[65];       /* hash(repo_id + passwd), key stretched. */
    gchar       random_key[97];
    gboolean    no_local_history;

    SeafBranch *head;

    gboolean    is_corrupted;
    gboolean    repaired;
    int         ref_cnt;

    SeafVirtRepo *virtual_info;

    int version;
    /* Used to access fs and block sotre.
     * This id is different from repo_id when this repo is virtual.
     * Virtual repos share fs and block store with its origin repo.
     * However, commit store for each repo is always independent.
     * So always use repo_id to access commit store.
     */
    gchar       store_id[37];
};

gboolean is_repo_id_valid (const char *id);

SeafRepo* 
seaf_repo_new (const char *id, const char *name, const char *desc);

void
seaf_repo_free (SeafRepo *repo);

void
seaf_repo_ref (SeafRepo *repo);

void
seaf_repo_unref (SeafRepo *repo);

int
seaf_repo_set_head (SeafRepo *repo, SeafBranch *branch);

/* Update repo name, desc, magic etc from commit.
 */
void
seaf_repo_from_commit (SeafRepo *repo, SeafCommit *commit);

/* Update repo-related fields to commit. 
 */
void
seaf_repo_to_commit (SeafRepo *repo, SeafCommit *commit);

/*
 * Returns a list of all commits belongs to the repo.
 * The commits in the repos are all unique.
 */
GList *
seaf_repo_get_commits (SeafRepo *repo);

GList *
seaf_repo_diff (SeafRepo *repo, const char *arg1, const char *arg2, int fold_dir_diff, char **error);

typedef struct _SeafRepoManager SeafRepoManager;
typedef struct _SeafRepoManagerPriv SeafRepoManagerPriv;

struct _SeafRepoManager {
    struct _SeafileSession *seaf;

    SeafRepoManagerPriv *priv;
};

SeafRepoManager* 
seaf_repo_manager_new (struct _SeafileSession *seaf);

int
seaf_repo_manager_init (SeafRepoManager *mgr);

int
seaf_repo_manager_start (SeafRepoManager *mgr);

/*
 * Repo Management functions. 
 */

int
seaf_repo_manager_add_repo (SeafRepoManager *mgr, SeafRepo *repo);

int
seaf_repo_manager_del_repo (SeafRepoManager *mgr,
                            const char *repo_id);

int
seaf_repo_manager_del_virtual_repo (SeafRepoManager *mgr,
                                    const char *repo_id);

SeafRepo* 
seaf_repo_manager_get_repo (SeafRepoManager *manager, const gchar *id);

/* Return repo object even if it's corrupted. */
SeafRepo*
seaf_repo_manager_get_repo_ex (SeafRepoManager *manager, const gchar *id);

gboolean
seaf_repo_manager_repo_exists (SeafRepoManager *manager, const gchar *id);

GList* 
seaf_repo_manager_get_repo_list (SeafRepoManager *mgr, int start, int limit);

GList*
seaf_repo_manager_get_trash_repo_list (SeafRepoManager *mgr,
                                       int start,
                                       int limit,
                                       GError **error);

GList *
seaf_repo_manager_get_trash_repos_by_owner (SeafRepoManager *mgr,
                                            const char *owner,
                                            GError **error);

int
seaf_repo_manager_del_repo_from_trash (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       GError **error);

/* Remove all entries in the repo trash. */
int
seaf_repo_manager_empty_repo_trash (SeafRepoManager *mgr, GError **error);

int
seaf_repo_manager_empty_repo_trash_by_owner (SeafRepoManager *mgr,
                                             const char *owner,
                                             GError **error);

int
seaf_repo_manager_restore_repo_from_trash (SeafRepoManager *mgr,
                                           const char *repo_id,
                                           GError **error);

GList *
seaf_repo_manager_get_repo_id_list (SeafRepoManager *mgr);

int
seaf_repo_manager_branch_repo_unmap (SeafRepoManager *manager, SeafBranch *branch);

/*
 * Repo properties functions.
 */

#define MAX_REPO_TOKEN 64
#define DEFAULT_REPO_TOKEN "default"

char *
seaf_repo_manager_get_email_by_token (SeafRepoManager *manager,
                                      const char *repo_id,
                                      const char *token);
char *
seaf_repo_manager_generate_repo_token (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *email,
                                       GError **error);

int
seaf_repo_manager_add_token_peer_info (SeafRepoManager *mgr,
                                       const char *token,
                                       const char *peer_id,
                                       const char *peer_ip,
                                       const char *peer_name,
                                       gint64 sync_time);

int
seaf_repo_manager_update_token_peer_info (SeafRepoManager *mgr,
                                          const char *token,
                                          const char *peer_ip,
                                          gint64 sync_time);

gboolean
seaf_repo_manager_token_peer_info_exists (SeafRepoManager *mgr,
                                          const char *token);

int
seaf_repo_manager_delete_token (SeafRepoManager *mgr,
                                const char *repo_id,
                                const char *token,
                                const char *user,
                                GError **error);

GList *
seaf_repo_manager_list_repo_tokens (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    GError **error);
GList *
seaf_repo_manager_list_repo_tokens_by_email (SeafRepoManager *mgr,
                                             const char *email,
                                             GError **error);
int
seaf_repo_manager_delete_repo_tokens_by_peer_id (SeafRepoManager *mgr,
                                                 const char *email,
                                                 const char *peer_id,
                                                 GList **tokens,
                                                 GError **error);

int
seaf_repo_manager_delete_repo_tokens_by_email (SeafRepoManager *mgr,
                                               const char *email,
                                               GError **error);

gint64
seaf_repo_manager_get_repo_size (SeafRepoManager *mgr, const char *repo_id);

int
seaf_repo_manager_set_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id,
                                          int days);

/*
 * > 0: keep a period of history;
 * = 0: don't keep history;
 * < 0: keep full history.
 */
int
seaf_repo_manager_get_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id);

int
seaf_repo_manager_set_repo_valid_since (SeafRepoManager *mgr,
                                        const char *repo_id,
                                        gint64 timestamp);

gint64
seaf_repo_manager_get_repo_valid_since (SeafRepoManager *mgr,
                                        const char *repo_id);

/*
 * Return the timestamp to stop traversing history.
 * Returns > 0 if traverse a period of history;
 * Returns = 0 if only traverse the head commit;
 * Returns < 0 if traverse full history.
 */
gint64
seaf_repo_manager_get_repo_truncate_time (SeafRepoManager *mgr,
                                          const char *repo_id);

/*
 * Repo Operations.
 */

int
seaf_repo_manager_revert_on_server (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *commit_id,
                                    const char *user_name,
                                    GError **error);

/**
 * Add a new file in a repo.
 * The content of the file is stored in a temporary file.
 * @repo_id:        id of the repo
 * @temp_file_path: path of the temporary file 
 * @parent_dir:     the directory to add this file
 * @file_name:      the name of the new file
 * @user:           author of this operation
 */
int
seaf_repo_manager_post_file (SeafRepoManager *mgr,
                             const char *repo_id,
                             const char *temp_file_path,
                             const char *parent_dir,
                             const char *file_name,
                             const char *user,
                             GError **error);

int
seaf_repo_manager_post_multi_files (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *parent_dir,
                                    const char *filenames_json,
                                    const char *paths_json,
                                    const char *user,
                                    int replace_existed,
                                    char **new_ids,
                                    GError **error);

int
seaf_repo_manager_post_file_blocks (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *parent_dir,
                                    const char *file_name,
                                    const char *blockids_json,
                                    const char *paths_json,
                                    const char *user,
                                    gint64 file_size,
                                    int replace_existed,
                                    char **new_id,
                                    GError **error);

int
seaf_repo_manager_post_empty_file (SeafRepoManager *mgr,
                                   const char *repo_id,
                                   const char *parent_dir,
                                   const char *new_file_name,
                                   const char *user,
                                   GError **error);

int
seaf_repo_manager_post_dir (SeafRepoManager *mgr,
                            const char *repo_id,
                            const char *parent_dir,
                            const char *new_dir_name,
                            const char *user,
                            GError **error);

/**
 * Update an existing file in a repo
 * @params: same as seaf_repo_manager_post_file
 * @head_id: the commit id for the original file version.
 *           It's optional. If it's NULL, the current repo head will be used.
 * @new_file_id: The return location of the new file id
 */
int
seaf_repo_manager_put_file (SeafRepoManager *mgr,
                            const char *repo_id,
                            const char *temp_file_path,
                            const char *parent_dir,
                            const char *file_name,
                            const char *user,
                            const char *head_id,
                            char **new_file_id,                            
                            GError **error);

int
seaf_repo_manager_put_file_blocks (SeafRepoManager *mgr,
                                   const char *repo_id,
                                   const char *parent_dir,
                                   const char *file_name,
                                   const char *blockids_json,
                                   const char *paths_json,
                                   const char *user,
                                   const char *head_id,
                                   gint64 file_size,
                                   char **new_file_id,
                                   GError **error);

int
seaf_repo_manager_del_file (SeafRepoManager *mgr,
                            const char *repo_id,
                            const char *parent_dir,
                            const char *file_name,
                            const char *user,
                            GError **error);

SeafileCopyResult *
seaf_repo_manager_copy_file (SeafRepoManager *mgr,
                             const char *src_repo_id,
                             const char *src_dir,
                             const char *src_filename,
                             const char *dst_repo_id,
                             const char *dst_dir,
                             const char *dst_filename,
                             const char *user,
                             int need_progress,
                             int synchronous,
                             GError **error);

SeafileCopyResult *
seaf_repo_manager_move_file (SeafRepoManager *mgr,
                             const char *src_repo_id,
                             const char *src_dir,
                             const char *src_filename,
                             const char *dst_repo_id,
                             const char *dst_dir,
                             const char *dst_filename,
                             const char *user,
                             int need_progress,
                             int synchronous,
                             GError **error);

int
seaf_repo_manager_rename_file (SeafRepoManager *mgr,
                               const char *repo_id,
                               const char *parent_dir,
                               const char *oldname,
                               const char *newname,
                               const char *user,
                               GError **error);

int
seaf_repo_manager_is_valid_filename (SeafRepoManager *mgr,
                                     const char *repo_id,
                                     const char *filename,
                                     GError **error);

char *
seaf_repo_manager_create_new_repo (SeafRepoManager *mgr,
                                   const char *repo_name,
                                   const char *repo_desc,
                                   const char *owner_email,
                                   const char *passwd,
                                   GError **error);

char *
seaf_repo_manager_create_enc_repo (SeafRepoManager *mgr,
                                   const char *repo_id,
                                   const char *repo_name,
                                   const char *repo_desc,
                                   const char *owner_email,
                                   const char *magic,
                                   const char *random_key,
                                   int enc_version,
                                   GError **error);

/* Give a repo and a path in this repo, returns a list of commits, where every
 * commit contains a unique version of the file. The commits are sorted in
 * ascending order of commit time. */
GList *
seaf_repo_manager_list_file_revisions (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *start_commit_id,
                                       const char *path,
                                       int max_revision,
                                       int limit,
                                       GError **error);

GList *
seaf_repo_manager_calc_files_last_modified (SeafRepoManager *mgr,
                                            const char *repo_id,
                                            const char *parent_dir,
                                            int limit,
                                            GError **error);

int
seaf_repo_manager_revert_file (SeafRepoManager *mgr,
                               const char *repo_id,
                               const char *commit_id,
                               const char *path,
                               const char *user,
                               GError **error);

int
seaf_repo_manager_revert_dir (SeafRepoManager *mgr,
                              const char *repo_id,
                              const char *old_commit_id,
                              const char *dir_path,
                              const char *user,
                              GError **error);

/*
 * Return deleted files/dirs.
 */
GList *
seaf_repo_manager_get_deleted_entries (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       int show_days,
                                       const char *path,
                                       GError **error);

/*
 * Set the dir_id of @dir_path to @new_dir_id.
 * @new_commit_id: The new head commit id after the update.
 */
int
seaf_repo_manager_update_dir (SeafRepoManager *mgr,
                              const char *repo_id,
                              const char *dir_path,
                              const char *new_dir_id,
                              const char *user,
                              const char *head_id,
                              char *new_commit_id,
                              GError **error);

/*
 * Permission related functions.
 */

/* Owner functions. */

int
seaf_repo_manager_set_repo_owner (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  const char *email);

char *
seaf_repo_manager_get_repo_owner (SeafRepoManager *mgr,
                                  const char *repo_id);

GList *
seaf_repo_manager_get_orphan_repo_list (SeafRepoManager *mgr);

/* TODO: add start and limit. */
/* Get repos owned by this user.
 */
GList *
seaf_repo_manager_get_repos_by_owner (SeafRepoManager *mgr,
                                      const char *email);

GList *
seaf_repo_manager_get_repo_ids_by_owner (SeafRepoManager *mgr,
                                         const char *email);

/* Group repos. */

int
seaf_repo_manager_add_group_repo (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  int group_id,
                                  const char *owner,
                                  const char *permission,
                                  GError **error);
int
seaf_repo_manager_del_group_repo (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  int group_id,
                                  GError **error);

GList *
seaf_repo_manager_get_groups_by_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      GError **error);

typedef struct GroupPerm {
    int group_id;
    char permission[16];
} GroupPerm;

GList *
seaf_repo_manager_get_group_perm_by_repo (SeafRepoManager *mgr,
                                          const char *repo_id,
                                          GError **error);

int
seaf_repo_manager_set_group_repo_perm (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       int group_id,
                                       const char *permission,
                                       GError **error);

char *
seaf_repo_manager_get_group_repo_owner (SeafRepoManager *mgr,
                                        const char *repo_id,
                                        GError **error);

GList *
seaf_repo_manager_get_group_repoids (SeafRepoManager *mgr,
                                     int group_id,
                                     GError **error);

GList *
seaf_repo_manager_get_group_repos_by_owner (SeafRepoManager *mgr,
                                            const char *owner,
                                            GError **error);

int
seaf_repo_manager_remove_group_repos (SeafRepoManager *mgr,
                                      int group_id,
                                      const char *owner,
                                      GError **error);

/* Inner public repos */

int
seaf_repo_manager_set_inner_pub_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      const char *permission);

int
seaf_repo_manager_unset_inner_pub_repo (SeafRepoManager *mgr,
                                        const char *repo_id);

gboolean
seaf_repo_manager_is_inner_pub_repo (SeafRepoManager *mgr,
                                     const char *repo_id);

GList *
seaf_repo_manager_list_inner_pub_repos (SeafRepoManager *mgr);

gint64
seaf_repo_manager_count_inner_pub_repos (SeafRepoManager *mgr);

GList *
seaf_repo_manager_list_inner_pub_repos_by_owner (SeafRepoManager *mgr,
                                                 const char *user);

char *
seaf_repo_manager_get_inner_pub_repo_perm (SeafRepoManager *mgr,
                                           const char *repo_id);

/*
 * Comprehensive repo permission checker.
 * It checks if @user have permission to access @repo_id.
 */
char *
seaf_repo_manager_check_permission (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *user,
                                    GError **error);

/* Web access permission. */

int
seaf_repo_manager_set_access_property (SeafRepoManager *mgr, const char *repo_id,
                                       const char *ap);

char *
seaf_repo_manager_query_access_property (SeafRepoManager *mgr, const char *repo_id);

/* Decrypted repo token cache. */

void
seaf_repo_manager_add_decrypted_token (SeafRepoManager *mgr,
                                       const char *encrypted_token,
                                       const char *session_key,
                                       const char *decrypted_token);

char *
seaf_repo_manager_get_decrypted_token (SeafRepoManager *mgr,
                                       const char *encrypted_token,
                                       const char *session_key);

/* Virtual repo related. */

char *
seaf_repo_manager_create_virtual_repo (SeafRepoManager *mgr,
                                       const char *origin_repo_id,
                                       const char *path,
                                       const char *repo_name,
                                       const char *repo_desc,
                                       const char *owner,
                                       const char *passwd,
                                       GError **error);

SeafVirtRepo *
seaf_repo_manager_get_virtual_repo_info (SeafRepoManager *mgr,
                                         const char *repo_id);

GList *
seaf_repo_manager_get_virtual_info_by_origin (SeafRepoManager *mgr,
                                              const char *origin_repo);

void
seaf_virtual_repo_info_free (SeafVirtRepo *vinfo);

gboolean
seaf_repo_manager_is_virtual_repo (SeafRepoManager *mgr, const char *repo_id);

char *
seaf_repo_manager_get_virtual_repo_id (SeafRepoManager *mgr,
                                       const char *origin_repo,
                                       const char *path,
                                       const char *owner);

GList *
seaf_repo_manager_get_virtual_repos_by_owner (SeafRepoManager *mgr,
                                              const char *owner,
                                              GError **error);

GList *
seaf_repo_manager_get_virtual_repo_ids_by_origin (SeafRepoManager *mgr,
                                                  const char *origin_repo);

/*
 * if @repo_id is a virtual repo, try to merge with origin;
 * if not, try to merge with its virtual repos.
 */
int
seaf_repo_manager_merge_virtual_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      const char *exclude_repo);

/*
 * Check each virtual repo of @origin_repo_id, if the path corresponds to it
 * doesn't exist, delete the virtual repo.
 */
void
seaf_repo_manager_cleanup_virtual_repos (SeafRepoManager *mgr,
                                         const char *origin_repo_id);

int
seaf_repo_manager_init_merge_scheduler ();

#endif
