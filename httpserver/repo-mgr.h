/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_REPO_MGR_H
#define SEAF_REPO_MGR_H

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
#define REPO_ENCRYPTED 0x1

struct _SeafRepoManager;
typedef struct _SeafRepo SeafRepo;

struct _SeafRepo {
    struct _SeafRepoManager *manager;

    gchar       id[37];
    gchar      *name;
    gchar      *desc;
    gchar      *category;       /* not used yet */
    gboolean    encrypted;
    int         enc_version;
    gchar       magic[33];       /* hash(repo_id + passwd), key stretched. */
    gboolean    no_local_history;

    SeafBranch *head;

    gboolean    is_corrupted;
    gboolean    delete_pending;
    int         ref_cnt;
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

int
seaf_repo_manager_add_repo (SeafRepoManager *mgr, SeafRepo *repo);

int
seaf_repo_manager_del_repo (SeafRepoManager *mgr, SeafRepo *repo);

SeafRepo* 
seaf_repo_manager_get_repo (SeafRepoManager *manager, const gchar *id);

SeafRepo* 
seaf_repo_manager_get_repo_prefix (SeafRepoManager *manager, const gchar *id);

gboolean
seaf_repo_manager_repo_exists (SeafRepoManager *manager, const gchar *id);

gboolean
seaf_repo_manager_repo_exists_prefix (SeafRepoManager *manager, const gchar *id);

GList* 
seaf_repo_manager_get_repo_list (SeafRepoManager *mgr, int start, int limit);

int
seaf_repo_manager_set_repo_owner (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  const char *email);

char *
seaf_repo_manager_get_repo_owner (SeafRepoManager *mgr,
                                  const char *repo_id);

/* TODO: add start and limit. */
/* Get repos owned by this user.
 */
GList *
seaf_repo_manager_get_repos_by_owner (SeafRepoManager *mgr,
                                      const char *email);

GList *
seaf_repo_manager_get_repo_id_list (SeafRepoManager *mgr);

gint64
seaf_repo_manager_get_repo_size (SeafRepoManager *mgr, const char *repo_id);

int
seaf_repo_manager_set_access_property (SeafRepoManager *mgr, const char *repo_id,
                                       const char *ap);

char *
seaf_repo_manager_query_access_property (SeafRepoManager *mgr, const char *repo_id);

int
seaf_repo_manager_share_repo (SeafRepoManager *mgr,
                              const char *repo_id,
                              int group_id,
                              const char *user_name,
                              const char *permission,
                              GError **error);
int
seaf_repo_manager_unshare_repo (SeafRepoManager *mgr,
                                const char *repo_id,
                                int group_id,
                                const char *user_name,
                                GError **error);

GList *
seaf_repo_manager_get_group_repoids (SeafRepoManager *mgr,
                                     int group_id,
                                     GError **error);

GList *
seaf_repo_manager_get_group_my_share_repos (SeafRepoManager *mgr,
                                            const char *username,
                                            GError **error);

char *
seaf_repo_manager_get_repo_share_from (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       GError **error);

int
seaf_repo_manager_remove_repo_group (SeafRepoManager *mgr,
                                     int group_id,
                                     const char *user_name,
                                     GError **error);

#endif
