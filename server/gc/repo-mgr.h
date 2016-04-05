/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_REPO_MGR_H
#define SEAF_REPO_MGR_H

#include <pthread.h>

#include "seafile-object.h"
#include "commit-mgr.h"
#include "branch-mgr.h"

struct _SeafRepoManager;
typedef struct _SeafRepo SeafRepo;

typedef struct SeafVirtRepo {
    char        origin_repo_id[37];
    char        *path;
    char        base_commit[41];
} SeafVirtRepo;

struct _SeafRepo {
    struct _SeafRepoManager *manager;

    gchar       id[37];
    gchar      *name;
    gchar      *desc;
    gchar      *category;       /* not used yet */
    gboolean    encrypted;
    int         enc_version;
    gchar       magic[65];       /* hash(repo_id + passwd), key stretched. */
    gchar       random_key[97];
    gboolean    no_local_history;

    SeafBranch *head;

    gboolean    is_corrupted;
    gboolean    repaired;
    gboolean    delete_pending;
    int         ref_cnt;

    int version;
    /* Used to access fs and block sotre.
     * This id is different from repo_id when this repo is virtual.
     * Virtual repos share fs and block store with its origin repo.
     * However, commit store for each repo is always independent.
     * So always use repo_id to access commit store.
     */
    gchar       store_id[37];
    gboolean    is_virtual;
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

void
seaf_repo_to_commit (SeafRepo *repo, SeafCommit *commit);

void
seaf_repo_from_commit (SeafRepo *repo, SeafCommit *commit);

void
seaf_virtual_repo_info_free (SeafVirtRepo *vinfo);

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
seaf_repo_manager_get_repo_ex (SeafRepoManager *manager, const gchar *id);

gboolean
seaf_repo_manager_repo_exists (SeafRepoManager *manager, const gchar *id);

GList* 
seaf_repo_manager_get_repo_list (SeafRepoManager *mgr,
                                 int start, int limit,
                                 gboolean *error);

GList *
seaf_repo_manager_get_repo_id_list (SeafRepoManager *mgr);

int
seaf_repo_manager_set_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id,
                                          int days);

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

SeafVirtRepo *
seaf_repo_manager_get_virtual_repo_info (SeafRepoManager *mgr,
                                         const char *repo_id);

void
seaf_virtual_repo_info_free (SeafVirtRepo *vinfo);

GList *
seaf_repo_manager_get_virtual_repo_ids_by_origin (SeafRepoManager *mgr,
                                                  const char *origin_repo);

GList *
seaf_repo_manager_list_garbage_repos (SeafRepoManager *mgr);

void
seaf_repo_manager_remove_garbage_repo (SeafRepoManager *mgr, const char *repo_id);

#endif
