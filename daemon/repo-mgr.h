/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_REPO_MGR_H
#define SEAF_REPO_MGR_H

#include "common.h"

#include <pthread.h>

#include "seafile-object.h"
#include "commit-mgr.h"
#include "branch-mgr.h"

#define REPO_AUTO_SYNC        "auto-sync"
#define REPO_RELAY_ID         "relay-id"
#define REPO_REMOTE_HEAD      "remote-head"
#define REPO_LOCAL_HEAD       "local-head"
#define REPO_PROP_EMAIL       "email"
#define REPO_PROP_TOKEN       "token"
#define REPO_PROP_RELAY_ADDR  "relay-address"
#define REPO_PROP_RELAY_PORT  "relay-port"
#define REPO_PROP_DOWNLOAD_HEAD "download-head"
#define REPO_PROP_IS_READONLY "is-readonly"
#define REPO_PROP_SERVER_URL  "server-url"
#define REPO_PROP_SYNC_INTERVAL "sync-interval"
#define REPO_SYNC_WORKTREE_NAME "sync-worktree-name"

struct _SeafRepoManager;
typedef struct _SeafRepo SeafRepo;

struct _ChangeSet;

/* The caller can use the properties directly. But the caller should
 * always write on repos via the API. 
 */
struct _SeafRepo {
    struct _SeafRepoManager *manager;

    gchar       id[37];
    gchar      *name;
    gchar      *desc;
    gchar      *category;       /* not used yet */
    gboolean    encrypted;
    int         enc_version;
    gchar       salt[65];
    gchar       magic[65];       /* hash(repo_id + passwd), key stretched. */
    gchar       random_key[97];  /* key length is 48 after encryption */
    gboolean    no_local_history;
    gint64 last_modify;

    SeafBranch *head;
    gchar root_id[41];

    gboolean    is_corrupted;
    gboolean    delete_pending;

    gchar      *relay_id;
    gchar      *worktree;
    gboolean    wt_changed;
    int         wt_check_time;
    int         last_sync_time;

    /* Last time check locked files. */
    int         last_check_locked_time;
    gboolean    checking_locked_files;

    unsigned char enc_key[32];   /* 256-bit encryption key */
    unsigned char enc_iv[16];

    gchar      *email;          /* email of the user on the relay */
    gchar      *token;          /* token for access this repo on server */

    pthread_mutex_t lock;

    gboolean      worktree_invalid; /* true if worktree moved or deleted */
    gboolean      index_corrupted;
    gboolean      is_readonly;

    unsigned int  auto_sync : 1;
    unsigned int  quota_full_notified : 1;
    unsigned int  access_denied_notified : 1;

    int version;

    gboolean create_partial_commit;

    /* Used for http sync. */
    char *server_url;
    /* Can be server_url or server_url:8082, depends on which one works. */
    char *effective_host;
    gboolean use_fileserver_port;

    /* Detected file change set during indexing.
     * Added to here to avoid passing additional arguments. */
    struct _ChangeSet *changeset;

    /* Non-zero if periodic sync is set for this repo. */
    int sync_interval;
};


gboolean is_repo_id_valid (const char *id);

SeafRepo* 
seaf_repo_new (const char *id, const char *name, const char *desc);

void
seaf_repo_free (SeafRepo *repo);

int
seaf_repo_set_head (SeafRepo *repo, SeafBranch *branch);

SeafCommit *
seaf_repo_get_head_commit (const char *repo_id);

void
seaf_repo_set_readonly (SeafRepo *repo);

void
seaf_repo_unset_readonly (SeafRepo *repo);

int
seaf_repo_checkdir (SeafRepo *repo);

/* Update repo name, desc, magic etc from commit.
 */
void
seaf_repo_from_commit (SeafRepo *repo, SeafCommit *commit);

/* Update repo-related fields to commit. 
 */
void
seaf_repo_to_commit (SeafRepo *repo, SeafCommit *commit);

void
seaf_repo_set_name (SeafRepo *repo, const char *new_name);

/*
 * Returns a list of all commits belongs to the repo.
 * The commits in the repos are all unique.
 */
GList *
seaf_repo_get_commits (SeafRepo *repo);

char *
seaf_repo_index_commit (SeafRepo *repo,
                        gboolean is_force_commit,
                        gboolean is_initial_commit,
                        GError **error);

GList *
seaf_repo_diff (SeafRepo *repo, const char *old, const char *new, int fold_dir_diff, char **error);

typedef struct _SeafRepoManager SeafRepoManager;
typedef struct _SeafRepoManagerPriv SeafRepoManagerPriv;

struct _SeafRepoManager {
    struct _SeafileSession *seaf;

    char *index_dir;

    SeafRepoManagerPriv *priv;
};

SeafRepoManager* 
seaf_repo_manager_new (struct _SeafileSession *seaf);

int
seaf_repo_manager_init (SeafRepoManager *mgr);

int
seaf_repo_manager_start (SeafRepoManager *mgr);

int
seaf_repo_manager_add_repo (SeafRepoManager *mgr, SeafRepo *repo);

int
seaf_repo_manager_mark_repo_deleted (SeafRepoManager *mgr, SeafRepo *repo);

int
seaf_repo_manager_del_repo (SeafRepoManager *mgr, SeafRepo *repo);

void
seaf_repo_manager_move_repo_store (SeafRepoManager *mgr,
                                   const char *type,
                                   const char *repo_id);

void
seaf_repo_manager_remove_repo_ondisk (SeafRepoManager *mgr, const char *repo_id,
                                      gboolean add_deleted_record);

SeafRepo* 
seaf_repo_manager_create_new_repo (SeafRepoManager *mgr,
                                   const char *name,
                                   const char *desc);

SeafRepo* 
seaf_repo_manager_get_repo (SeafRepoManager *manager, const gchar *id);

gboolean
seaf_repo_manager_repo_exists (SeafRepoManager *manager, const gchar *id);

GList* 
seaf_repo_manager_get_repo_list (SeafRepoManager *mgr, int start, int limit);

GList *
seaf_repo_manager_get_repo_id_list_by_server (SeafRepoManager *mgr, const char *server_url);

GList *
seaf_repo_manager_list_garbage_repos (SeafRepoManager *mgr);

void
seaf_repo_manager_remove_garbage_repo (SeafRepoManager *mgr, const char *repo_id);

#define MAX_REPO_TOKEN 64
#define DEFAULT_REPO_TOKEN "default"


int
seaf_repo_manager_set_repo_token (SeafRepoManager *manager, 
                                  SeafRepo *repo,
                                  const char *token);

int
seaf_repo_manager_remove_repo_token (SeafRepoManager *manager,
                                     SeafRepo *repo);

int
seaf_repo_manager_set_repo_email (SeafRepoManager *manager, 
                                  SeafRepo *repo,
                                  const char *email);

int
seaf_repo_manager_set_repo_relay_info (SeafRepoManager *manager, 
                                       const char *repo_id,
                                       const char *relay_addr,
                                       const char *relay_port);
void
seaf_repo_manager_get_repo_relay_info (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       char **relay_addr,
                                       char **relay_port);

int
seaf_repo_manager_branch_repo_unmap (SeafRepoManager *manager, SeafBranch *branch);

int
seaf_repo_manager_set_repo_property (SeafRepoManager *manager,
                                     const char *repo_id,
                                     const char *key,
                                     const char *value);

char *
seaf_repo_manager_get_repo_property (SeafRepoManager *manager,
                                     const char *repo_id,
                                     const char *key);

void
seaf_repo_mamager_del_repo_property (SeafRepoManager *manager, SeafRepo *repo);

int
seaf_repo_check_worktree (SeafRepo *repo);

int
seaf_repo_manager_set_repo_worktree (SeafRepoManager *mgr,
                                     SeafRepo *repo,
                                     const char *worktree);

void
seaf_repo_manager_invalidate_repo_worktree (SeafRepoManager *mgr,
                                            SeafRepo *repo);

void
seaf_repo_manager_validate_repo_worktree (SeafRepoManager *mgr,
                                          SeafRepo *repo);

int
seaf_repo_manager_set_repo_passwd (SeafRepoManager *manager,
                                   SeafRepo *repo,
                                   const char *passwd);

int
seaf_repo_manager_update_repos_server_host (SeafRepoManager *mgr,
                                            const char *old_server_url,
                                            const char *new_server_url);

#define SERVER_PROP_IS_PRO "is_pro"

char *
seaf_repo_manager_get_server_property (SeafRepoManager *mgr,
                                       const char *server_url,
                                       const char *key);

int
seaf_repo_manager_set_server_property (SeafRepoManager *mgr,
                                       const char *server_url,
                                       const char *key,
                                       const char *value);

gboolean
seaf_repo_manager_server_is_pro (SeafRepoManager *mgr,
                                 const char *server_url);

GList *
seaf_repo_load_ignore_files (const char *worktree);

gboolean
seaf_repo_check_ignore_file (GList *ignore_list, const char *fullpath);

void
seaf_repo_free_ignore_files (GList *ignore_list);

enum {
    FETCH_CHECKOUT_SUCCESS = 0,
    FETCH_CHECKOUT_CANCELED,
    FETCH_CHECKOUT_FAILED,
    FETCH_CHECKOUT_TRANSFER_ERROR,
    FETCH_CHECKOUT_LOCKED,
};

struct _TransferTask;
struct _HttpTxTask;

int
seaf_repo_fetch_and_checkout (struct _HttpTxTask *http_task,
                              const char *remote_head_id);

gboolean
seaf_repo_manager_is_ignored_hidden_file (const char *filename);

/* Locked files. */

#define LOCKED_OP_UPDATE "update"
#define LOCKED_OP_DELETE "delete"

typedef struct _LockedFile {
    char *operation;
    gint64 old_mtime;
    char file_id[41];
} LockedFile;

typedef struct _LockedFileSet {
    SeafRepoManager *mgr;
    char repo_id[37];
    GHashTable *locked_files;
} LockedFileSet;

LockedFileSet *
seaf_repo_manager_get_locked_file_set (SeafRepoManager *mgr, const char *repo_id);

void
locked_file_set_free (LockedFileSet *fset);

int
locked_file_set_add_update (LockedFileSet *fset,
                            const char *path,
                            const char *operation,
                            gint64 old_mtime,
                            const char *file_id);

int
locked_file_set_remove (LockedFileSet *fset, const char *path, gboolean db_only);

LockedFile *
locked_file_set_lookup (LockedFileSet *fset, const char *path);

/* Folder Permissions. */

typedef enum FolderPermType {
    FOLDER_PERM_TYPE_USER = 0,
    FOLDER_PERM_TYPE_GROUP,
} FolderPermType;

typedef struct _FolderPerm {
    char *path;
    char *permission;
} FolderPerm;

void
folder_perm_free (FolderPerm *perm);

int
seaf_repo_manager_update_folder_perms (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       FolderPermType type,
                                       GList *folder_perms);

int
seaf_repo_manager_update_folder_perm_timestamp (SeafRepoManager *mgr,
                                                const char *repo_id,
                                                gint64 timestamp);

gint64
seaf_repo_manager_get_folder_perm_timestamp (SeafRepoManager *mgr,
                                             const char *repo_id);

gboolean
seaf_repo_manager_is_path_writable (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *path);

/* Sync error related. */

int
seaf_repo_manager_record_sync_error (const char *repo_id,
                                     const char *repo_name,
                                     const char *path,
                                     int error_id);

GList *
seaf_repo_manager_get_file_sync_errors (SeafRepoManager *mgr, int offset, int limit);

int
seaf_repo_manager_del_file_sync_error_by_id (SeafRepoManager *mgr, int id);

/* Record sync error and send notification. */
void
send_file_sync_error_notification (const char *repo_id,
                                   const char *repo_name,
                                   const char *path,
                                   int err_id);

#endif
