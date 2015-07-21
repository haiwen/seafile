/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_REPO_MGR_H
#define SEAF_REPO_MGR_H

#include "common.h"

#include <pthread.h>

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
#define REPO_LOCAL_HEAD       "local-head"
#define REPO_PROP_EMAIL       "email"
#define REPO_PROP_TOKEN       "token"
#define REPO_PROP_RELAY_ADDR  "relay-address"
#define REPO_PROP_RELAY_PORT  "relay-port"
#define REPO_ENCRYPTED 0x1
#define REPO_PROP_DOWNLOAD_HEAD "download-head"
#define REPO_PROP_IS_READONLY "is-readonly"
#define REPO_PROP_SERVER_URL  "server-url"

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
    unsigned int  net_browsable : 1;
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

/*
 * Returns a list of all commits belongs to the repo.
 * The commits in the repos are all unique.
 */
GList *
seaf_repo_get_commits (SeafRepo *repo);

int
seaf_repo_index_add (SeafRepo *repo, const char *path);

int
seaf_repo_index_worktree_files (const char *repo_id,
                                int version,
                                const char *modifier,
                                const char *worktree,
                                const char *passwd,
                                int enc_version,
                                const char *random_key,
                                char *root_id);

int
seaf_repo_index_rm (SeafRepo *repo, const char *path);

char *
seaf_repo_status (SeafRepo *repo);

gboolean
seaf_repo_is_worktree_changed (SeafRepo *repo);

gboolean
seaf_repo_is_index_unmerged (SeafRepo *repo);

char *
seaf_repo_index_commit (SeafRepo *repo, const char *desc, gboolean is_initial_commit,
                        GError **error);

int
seaf_repo_checkout (SeafRepo *repo, const char *worktree_parent, char **error);

int
seaf_repo_reset (SeafRepo *repo, const char *commit_id, char **error);

int
seaf_repo_revert (SeafRepo *repo, const char *commit_id, char **error);

int
seaf_repo_checkout_commit (SeafRepo *repo, SeafCommit *commit, gboolean recover_merge,
                           char **error);

enum {
    MERGE_STATUS_UNKNOWN = 0,
    MERGE_STATUS_UPTODATE,
    MERGE_STATUS_FAST_FORWARD,
    MERGE_STATUS_REAL_MERGE,
};

int
seaf_repo_merge (SeafRepo *repo, const char *branch, char **error,
                 int *merge_status);

GList *
seaf_repo_diff (SeafRepo *repo, const char *arg1, const char *arg2, char **error);

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

char *
seaf_repo_manager_get_repo_lantoken (SeafRepoManager *manager,
                                     const char *repo_id);
int
seaf_repo_manager_set_repo_lantoken (SeafRepoManager *manager,
                                     const char *repo_id,
                                     const char *token);
int
seaf_repo_manager_verify_repo_lantoken (SeafRepoManager *manager,
                                        const char *repo_id,
                                        const char *token);

char *
seaf_repo_manager_generate_tmp_token (SeafRepoManager *manager,
                                      const char *repo_id,
                                      const char *peer_id);

int
seaf_repo_manager_verify_tmp_token (SeafRepoManager *manager,
                                    const char *repo_id,
                                    const char *peer_id,
                                    const char *token);

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
seaf_repo_manager_set_repo_relay_id (SeafRepoManager *mgr,
                                     SeafRepo *repo,
                                     const char *relay_id);

int
seaf_repo_manager_set_merge (SeafRepoManager *manager,
                             const char *repo_id,
                             const char *remote_head);

int
seaf_repo_manager_clear_merge (SeafRepoManager *manager,
                               const char *repo_id);

typedef struct {
    gboolean in_merge;
    char remote_head[41];
} SeafRepoMergeInfo;

int
seaf_repo_manager_get_merge_info (SeafRepoManager *manager,
                                  const char *repo_id,
                                  SeafRepoMergeInfo *info);

int
seaf_repo_manager_get_common_ancestor (SeafRepoManager *manager,
                                       const char *repo_id,
                                       char *common_ancestor,
                                       char *head_id);

int
seaf_repo_manager_set_common_ancestor (SeafRepoManager *manager,
                                       const char *repo_id,
                                       const char *common_ancestor,
                                       const char *head_id);

typedef struct {
    char repo_id[41];
    char worktree[SEAF_PATH_MAX];
    int total_files;
    int finished_files;
    gboolean success;
} CheckoutTask;

typedef void (*CheckoutDoneCallback) (CheckoutTask *, SeafRepo *, void *);

int
seaf_repo_manager_add_checkout_task (SeafRepoManager *mgr,
                                     SeafRepo *repo,
                                     const char *worktree,
                                     CheckoutDoneCallback done_cb,
                                     void *cb_data);

/* Remove all the files in the worktree and then checkout again.
 * Can be used to re-checkout if wrong password was given.
 */
int
seaf_repo_manager_add_recheckout_task (SeafRepoManager *mgr,
                                       SeafRepo *repo,
                                       CheckoutDoneCallback done_cb,
                                       void *cb_data);

CheckoutTask *
seaf_repo_manager_get_checkout_task (SeafRepoManager *mgr,
                                     const char *repo_id);
int
seaf_repo_manager_update_repo_relay_info (SeafRepoManager *mgr,
                                          SeafRepo *repo,
                                          const char *new_addr,
                                          const char *new_port);

int
seaf_repo_manager_update_repos_server_host (SeafRepoManager *mgr,
                                            const char *old_host,
                                            const char *new_host,
                                            const char *new_server_url);

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
seaf_repo_fetch_and_checkout (struct _TransferTask *task,
                              struct _HttpTxTask *http_task,
                              gboolean is_http,
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

#endif
