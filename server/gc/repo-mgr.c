/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <glib/gstdio.h>

#include <ccnet.h>
#include "utils.h"
#include "avl/avl.h"
#include "log.h"

#include "seafile-session.h"
#include "seafile-config.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "fs-mgr.h"
#include "seafile-error.h"

#include "seaf-db.h"

#define INDEX_DIR "index"

struct _SeafRepoManagerPriv {
    avl_tree_t *repo_tree;
    pthread_rwlock_t lock;
};

static SeafRepo *
load_repo (SeafRepoManager *manager, const char *repo_id);

gboolean
is_repo_id_valid (const char *id)
{
    if (!id)
        return FALSE;

    return is_uuid_valid (id);
}

SeafRepo*
seaf_repo_new (const char *id, const char *name, const char *desc)
{
    SeafRepo* repo;

    /* valid check */
  
    
    repo = g_new0 (SeafRepo, 1);
    memcpy (repo->id, id, 36);
    repo->id[36] = '\0';

    repo->name = g_strdup(name);
    repo->desc = g_strdup(desc);

    repo->ref_cnt = 1;

    return repo;
}

void
seaf_repo_free (SeafRepo *repo)
{
    if (repo->name) g_free (repo->name);
    if (repo->desc) g_free (repo->desc);
    if (repo->category) g_free (repo->category);
    if (repo->head) seaf_branch_unref (repo->head);
    g_free (repo);
}

void
seaf_repo_ref (SeafRepo *repo)
{
    g_atomic_int_inc (&repo->ref_cnt);
}

void
seaf_repo_unref (SeafRepo *repo)
{
    if (!repo)
        return;

    if (g_atomic_int_dec_and_test (&repo->ref_cnt))
        seaf_repo_free (repo);
}

static void
set_head_common (SeafRepo *repo, SeafBranch *branch)
{
    if (repo->head)
        seaf_branch_unref (repo->head);
    repo->head = branch;
    seaf_branch_ref(branch);
}

void
seaf_repo_from_commit (SeafRepo *repo, SeafCommit *commit)
{
    repo->name = g_strdup (commit->repo_name);
    repo->desc = g_strdup (commit->repo_desc);
    repo->encrypted = commit->encrypted;
    if (repo->encrypted) {
        repo->enc_version = commit->enc_version;
        if (repo->enc_version >= 1)
            memcpy (repo->magic, commit->magic, 33);
    }
    repo->no_local_history = commit->no_local_history;
}

void
seaf_repo_to_commit (SeafRepo *repo, SeafCommit *commit)
{
    commit->repo_name = g_strdup (repo->name);
    commit->repo_desc = g_strdup (repo->desc);
    commit->encrypted = repo->encrypted;
    if (commit->encrypted) {
        commit->enc_version = repo->enc_version;
        if (commit->enc_version >= 1)
            commit->magic = g_strdup (repo->magic);
    }
    commit->no_local_history = repo->no_local_history;
}

static gboolean
collect_commit (SeafCommit *commit, void *vlist, gboolean *stop)
{
    GList **commits = vlist;

    /* The traverse function will unref the commit, so we need to ref it.
     */
    seaf_commit_ref (commit);
    *commits = g_list_prepend (*commits, commit);
    return TRUE;
}

GList *
seaf_repo_get_commits (SeafRepo *repo)
{
    GList *branches;
    GList *ptr;
    SeafBranch *branch;
    GList *commits = NULL;

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        g_warning ("Failed to get branch list of repo %s.\n", repo->id);
        return NULL;
    }

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 branch->commit_id,
                                                                 collect_commit,
                                                                 &commits);
        if (!res) {
            for (ptr = commits; ptr != NULL; ptr = ptr->next)
                seaf_commit_unref ((SeafCommit *)(ptr->data));
            g_list_free (commits);
            goto out;
        }
    }

    commits = g_list_reverse (commits);

out:
    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        seaf_branch_unref ((SeafBranch *)ptr->data);
    }
    return commits;
}

static int 
compare_repo (const SeafRepo *srepo, const SeafRepo *trepo)
{
    return g_strcmp0 (srepo->id, trepo->id);
}

SeafRepoManager*
seaf_repo_manager_new (SeafileSession *seaf)
{
    SeafRepoManager *mgr = g_new0 (SeafRepoManager, 1);

    mgr->priv = g_new0 (SeafRepoManagerPriv, 1);
    mgr->seaf = seaf;

    mgr->priv->repo_tree = avl_alloc_tree ((avl_compare_t)compare_repo,
                                           NULL);

    pthread_rwlock_init (&mgr->priv->lock, NULL);

    return mgr;
}

int
seaf_repo_manager_init (SeafRepoManager *mgr)
{
    return 0;
}

int
seaf_repo_manager_start (SeafRepoManager *mgr)
{
    return 0;
}

static gboolean
repo_exists_in_db (SeafDB *db, const char *id)
{
    char sql[256];
    gboolean db_err = FALSE;

    snprintf (sql, sizeof(sql), "SELECT repo_id FROM Repo WHERE repo_id = '%s'",
              id);
    return seaf_db_check_for_existence (db, sql, &db_err);
}

SeafRepo*
seaf_repo_manager_get_repo (SeafRepoManager *manager, const gchar *id)
{
    SeafRepo repo;
    int len = strlen(id);

    if (len >= 37)
        return NULL;

    memcpy (repo.id, id, len + 1);
#if 0
    if (pthread_rwlock_rdlock (&manager->priv->lock) < 0) {
        g_warning ("[repo mgr] failed to lock repo cache.\n");
        return NULL;
    }

    avl_node_t *res = avl_search (manager->priv->repo_tree, &repo);

    pthread_rwlock_unlock (&manager->priv->lock);

    if (res) {
        seaf_repo_ref ((SeafRepo *)(res->item));
        return res->item;
    }
#endif

    if (repo_exists_in_db (manager->seaf->db, id)) {
        SeafRepo *ret = load_repo (manager, id);
        if (!ret)
            return NULL;
        /* seaf_repo_ref (ret); */
        return ret;
    }

    return NULL;
}

SeafRepo*
seaf_repo_manager_get_repo_prefix (SeafRepoManager *manager, const gchar *id)
{
    avl_node_t *node;
    SeafRepo repo, *result;
    int len = strlen(id);

    if (len >= 37)
        return NULL;

    memcpy (repo.id, id, len + 1);

    avl_search_closest (manager->priv->repo_tree, &repo, &node);
    if (node != NULL) {
        result = node->item;
        if (strncmp (id, result->id, len) == 0)
            return node->item;
    }
    return NULL;
}

gboolean
seaf_repo_manager_repo_exists (SeafRepoManager *manager, const gchar *id)
{
    SeafRepo repo;
    memcpy (repo.id, id, 37);

#if 0
    if (pthread_rwlock_rdlock (&manager->priv->lock) < 0) {
        g_warning ("[repo mgr] failed to lock repo cache.\n");
        return FALSE;
    }

    avl_node_t *res = avl_search (manager->priv->repo_tree, &repo);

    pthread_rwlock_unlock (&manager->priv->lock);

    if (res)
        return TRUE;
#endif

    return repo_exists_in_db (manager->seaf->db, id);
}

gboolean
seaf_repo_manager_repo_exists_prefix (SeafRepoManager *manager, const gchar *id)
{
    avl_node_t *node;
    SeafRepo repo;

    memcpy (repo.id, id, 37);

    avl_search_closest (manager->priv->repo_tree, &repo, &node);
    if (node != NULL)
        return TRUE;
    return FALSE;
}

static void
load_repo_commit (SeafRepoManager *manager,
                  SeafRepo *repo,
                  SeafBranch *branch)
{
    SeafCommit *commit;

    commit = seaf_commit_manager_get_commit (manager->seaf->commit_mgr,
                                             branch->commit_id);
    if (!commit) {
        g_warning ("Commit %s is missing\n", branch->commit_id);
        repo->is_corrupted = TRUE;
        return;
    }

    set_head_common (repo, branch);
    seaf_repo_from_commit (repo, commit);

    seaf_commit_unref (commit);
}

static gboolean
load_branch_cb (SeafDBRow *row, void *vrepo)
{
    SeafRepo *repo = vrepo;
    SeafRepoManager *manager = repo->manager;

    const char *branch_name = seaf_db_row_get_column_text (row, 0);
    SeafBranch *branch =
        seaf_branch_manager_get_branch (manager->seaf->branch_mgr,
                                        repo->id, branch_name);
    if (branch == NULL) {
        g_warning ("Broken branch name for repo %s\n", repo->id); 
        repo->is_corrupted = TRUE;
        return FALSE;
    }
    load_repo_commit (manager, repo, branch);
    seaf_branch_unref (branch);

    /* Only one result. */
    return FALSE;
}

static SeafRepo *
load_repo (SeafRepoManager *manager, const char *repo_id)
{
    char sql[256];
    int n;

    SeafRepo *repo = seaf_repo_new(repo_id, NULL, NULL);
    if (!repo) {
        g_warning ("[repo mgr] failed to alloc repo.\n");
        return NULL;
    }

    repo->manager = manager;

    snprintf(sql, 256, "SELECT branch_name FROM RepoHead WHERE repo_id='%s'",
             repo->id);
    n = seaf_db_foreach_selected_row (seaf->db, sql, load_branch_cb, repo);
    if (n < 0) {
        g_warning ("Error read branch for repo %s.\n", repo->id);
        seaf_repo_free (repo);
        return NULL;
    } else if (n == 0) {
        g_warning ("Repo %.8s is corrupted.\n", repo->id);
        seaf_repo_free (repo);
        return NULL;
    }

    if (repo->is_corrupted) {
        g_warning ("Repo %.8s is corrupted.\n", repo->id);
        seaf_repo_free (repo);
        return NULL;
    }

#if 0
    if (pthread_rwlock_wrlock (&manager->priv->lock) < 0) {
        g_warning ("[repo mgr] failed to lock repo cache.\n");
        seaf_repo_free (repo);
        return NULL;
    }
    avl_insert (manager->priv->repo_tree, repo);
    /* Don't need to increase ref count, since the ref count of
     * a new repo object is already 1.
     */
    pthread_rwlock_unlock (&manager->priv->lock);
#endif

    return repo;
}

static gboolean
collect_repo_id (SeafDBRow *row, void *data)
{
    GList **p_ids = data;
    const char *repo_id;

    repo_id = seaf_db_row_get_column_text (row, 0);
    *p_ids = g_list_prepend (*p_ids, g_strdup(repo_id));

    return TRUE;
}

GList *
seaf_repo_manager_get_repo_id_list (SeafRepoManager *mgr)
{
    GList *ret = NULL;
    char sql[256];

    snprintf (sql, 256, "SELECT repo_id FROM Repo");

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_repo_id, &ret) < 0)
        return NULL;

    return ret;
}

typedef struct {
    GList *repos;
    gboolean error;
} CollectReposData;

static gboolean
collect_repos (SeafDBRow *row, void *vdata)
{
    CollectReposData *data = vdata;
    const char *repo_id;
    SeafRepo *repo;

    repo_id = seaf_db_row_get_column_text (row, 0);
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        /* In GC, we should be more conservative.
         * No matter a repo is really corrupted or it's a temp error,
         * we return error here.
         */
        g_warning ("Failed to get repo %.8s.\n", repo_id);
        data->error = TRUE;
        return FALSE;
    }
    data->repos = g_list_prepend (data->repos, repo);

    return TRUE;
}

GList *
seaf_repo_manager_get_repo_list (SeafRepoManager *mgr,
                                 int start, int limit)
{
    CollectReposData data;
    char sql[256];
    GList *ptr;
    SeafRepo *repo;

    if (start == -1 && limit == -1)
        snprintf (sql, 256, "SELECT repo_id FROM Repo");
    else
        snprintf (sql, 256, "SELECT repo_id FROM Repo LIMIT %d, %d", start, limit);

    memset (&data, 0, sizeof(data));

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_repos, &data) < 0)
        goto error;

    if (data.error)
        goto error;

    return g_list_reverse (data.repos);

error:
    for (ptr = data.repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        seaf_repo_unref (repo);
    }
    g_list_free (data.repos);
    return NULL;
}

int
seaf_repo_manager_set_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id,
                                          int days)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "REPLACE INTO RepoHistoryLimit VALUES ('%s', %d)",
              repo_id, days);
    if (seaf_db_query (mgr->seaf->db, sql) < 0)
        return -1;

    return 0;
}

static gboolean
get_limit (SeafDBRow *row, void *vdays)
{
    int *days = vdays;

    *days = seaf_db_row_get_column_int (row, 0);

    return FALSE;
}

int
seaf_repo_manager_get_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id)
{
    char sql[256];
    int per_repo_days = -1;

    snprintf (sql, sizeof(sql),
              "SELECT days FROM RepoHistoryLimit WHERE repo_id='%s'",
              repo_id);
    /* We don't use seaf_db_get_int() because we need to differ DB error
     * from not exist.
     * We can't just return global config value if DB error occured,
     * since the global value may be smaller than per repo one.
     * This can lead to data lose in GC.
     */
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      get_limit, &per_repo_days) < 0) {
        seaf_warning ("DB error.\n");
        return -1;
    }

    /* If per repo value is not set, return the global one. */
    if (per_repo_days < 0)
        return mgr->seaf->keep_history_days;

    return per_repo_days;
}

int
seaf_repo_manager_set_repo_valid_since (SeafRepoManager *mgr,
                                        const char *repo_id,
                                        gint64 timestamp)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "REPLACE INTO RepoValidSince VALUES ('%s', %"G_GINT64_FORMAT")",
              repo_id, timestamp);
    if (seaf_db_query (mgr->seaf->db, sql) < 0)
        return -1;

    return 0;
}

gint64
seaf_repo_manager_get_repo_valid_since (SeafRepoManager *mgr,
                                        const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "SELECT timestamp FROM RepoValidSince WHERE repo_id='%s'",
              repo_id);
    /* Also return -1 if DB error. */
    return seaf_db_get_int64 (mgr->seaf->db, sql);
}

gint64
seaf_repo_manager_get_repo_truncate_time (SeafRepoManager *mgr,
                                          const char *repo_id)
{
    int days;
    gint64 timestamp;

    days = seaf_repo_manager_get_repo_history_limit (mgr, repo_id);
    timestamp = seaf_repo_manager_get_repo_valid_since (mgr, repo_id);

    gint64 now = (gint64)time(NULL);
    if (days > 0)
        return MAX (now - days * 24 * 3600, timestamp);
    else if (days < 0)
        return timestamp;
    else
        return 0;
}
