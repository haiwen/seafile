/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_COMMIT_MGR_H
#define SEAF_COMMIT_MGR_H

struct _SeafCommitManager;
typedef struct _SeafCommit SeafCommit;

#include <glib/gstdio.h>
#include "db.h"

#include "obj-store.h"

struct _SeafCommit {
    struct _SeafCommitManager *manager;

    int         ref;

    char        commit_id[41];
    char        repo_id[37];
    char        root_id[41];    /* the fs root */
    char       *desc;
    char       *creator_name;
    char        creator_id[41];
    guint64     ctime;          /* creation time */
    char       *parent_id;
    char       *second_parent_id;
    char       *repo_name;
    char       *repo_desc;
    char       *repo_category;
    char       *device_name;
    char       *client_version;

    gboolean    encrypted;         
    int         enc_version;
    char       *magic;
    char       *random_key;
    char       *salt;
    gboolean    no_local_history;

    int         version;
    gboolean    new_merge;
    gboolean    conflict;
    gboolean    repaired;
};


/**
 * @commit_id: if this is NULL, will create a new id.
 * @ctime: if this is 0, will use current time.
 * 
 * Any new commit should be added to commit manager before used.
 */
SeafCommit *
seaf_commit_new (const char *commit_id,
                 const char *repo_id,
                 const char *root_id,
                 const char *author_name,
                 const char *creator_id,
                 const char *desc,
                 guint64 ctime);

char *
seaf_commit_to_data (SeafCommit *commit, gsize *len);

SeafCommit *
seaf_commit_from_data (const char *id, char *data, gsize len);

void
seaf_commit_ref (SeafCommit *commit);

void
seaf_commit_unref (SeafCommit *commit);

/* Set stop to TRUE if you want to stop traversing a branch in the history graph. 
   Note, if currently there are multi branches, this function will be called again. 
   So, set stop to TRUE not always stop traversing the history graph.
*/
typedef gboolean (*CommitTraverseFunc) (SeafCommit *commit, void *data, gboolean *stop);

struct _SeafileSession;

typedef struct _SeafCommitManager SeafCommitManager;
typedef struct _SeafCommitManagerPriv SeafCommitManagerPriv;

struct _SeafCommitManager {
    struct _SeafileSession *seaf;

    sqlite3    *db;
    struct SeafObjStore *obj_store;

    SeafCommitManagerPriv *priv;
};

SeafCommitManager *
seaf_commit_manager_new (struct _SeafileSession *seaf);

int
seaf_commit_manager_init (SeafCommitManager *mgr);

/**
 * Add a commit to commit manager and persist it to disk.
 * Any new commit should be added to commit manager before used.
 * This function increments ref count of the commit object.
 * Not MT safe.
 */
int
seaf_commit_manager_add_commit (SeafCommitManager *mgr, SeafCommit *commit);

/**
 * Delete a commit from commit manager and permanently remove it from disk.
 * A commit object to be deleted should have ref cournt <= 1.
 * Not MT safe.
 */
void
seaf_commit_manager_del_commit (SeafCommitManager *mgr,
                                const char *repo_id,
                                int version,
                                const char *id);

/**
 * Find a commit object.
 * This function increments ref count of returned object.
 * Not MT safe.
 */
SeafCommit* 
seaf_commit_manager_get_commit (SeafCommitManager *mgr,
                                const char *repo_id,
                                int version,
                                const char *id);

/**
 * Get a commit object, with compatibility between version 0 and version 1.
 * It will first try to get commit with version 1 layout; if fails, will
 * try version 0 layout for compatibility.
 * This is useful for loading a repo. In that case, we don't know the version
 * of the repo before loading its head commit.
 */
SeafCommit *
seaf_commit_manager_get_commit_compatible (SeafCommitManager *mgr,
                                           const char *repo_id,
                                           const char *id);

/**
 * Traverse the commits DAG start from head in topological order.
 * The ordering is based on commit time.
 * return FALSE if some commits is missing, TRUE otherwise.
 */
gboolean
seaf_commit_manager_traverse_commit_tree (SeafCommitManager *mgr,
                                          const char *repo_id,
                                          int version,
                                          const char *head,
                                          CommitTraverseFunc func,
                                          void *data,
                                          gboolean skip_errors);

/*
 * The same as the above function, but stops traverse down if parent commit
 * doesn't exists, instead of returning error.
 */
gboolean
seaf_commit_manager_traverse_commit_tree_truncated (SeafCommitManager *mgr,
                                                    const char *repo_id,
                                                    int version,
                                                    const char *head,
                                                    CommitTraverseFunc func,
                                                    void *data,
                                                    gboolean skip_errors);

/**
 * Works the same as seaf_commit_manager_traverse_commit_tree, but stops
 * traversing when a total number of _limit_ commits is reached. If
 * limit <= 0, there is no limit
 */
gboolean
seaf_commit_manager_traverse_commit_tree_with_limit (SeafCommitManager *mgr,
                                                     const char *repo_id,
                                                     int version,
                                                     const char *head,
                                                     CommitTraverseFunc func,
                                                     int limit,
                                                     void *data,
                                                     gboolean skip_errors);

gboolean
seaf_commit_manager_commit_exists (SeafCommitManager *mgr,
                                   const char *repo_id,
                                   int version,
                                   const char *id);

int
seaf_commit_manager_remove_store (SeafCommitManager *mgr,
                                  const char *store_id);

#endif
