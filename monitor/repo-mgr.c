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
#include "gc.h"
#include "seafile-crypt.h"
#include "index/index.h"
#include "index/cache-tree.h"
#include "unpack-trees.h"
#include "diff-simple.h"

#include "seaf-db.h"

#define INDEX_DIR "index"

struct _SeafRepoManagerPriv {
    avl_tree_t *repo_tree;
    pthread_rwlock_t lock;
};

static SeafRepo *
load_repo (SeafRepoManager *manager, const char *repo_id);

static int create_db_tables_if_not_exist (SeafRepoManager *mgr);

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
    if (g_atomic_int_dec_and_test (&repo->ref_cnt))
        seaf_repo_free (repo);
}

static void
set_head_common (SeafRepo *repo, SeafBranch *branch, SeafCommit *commit)
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
    /* On the server, we load repos into memory on-demand, because
     * there are too many repos.
     */
    if (create_db_tables_if_not_exist (mgr) < 0) {
        g_warning ("[repo mgr] failed to create tables.\n");
        return -1;
    }

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

    snprintf (sql, sizeof(sql), "SELECT repo_id FROM Repo WHERE repo_id = '%s'",
              id);
    return seaf_db_check_for_existence (db, sql);
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

    set_head_common (repo, branch, commit);
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

    SeafRepo *repo = seaf_repo_new(repo_id, NULL, NULL);
    if (!repo) {
        g_warning ("[repo mgr] failed to alloc repo.\n");
        return NULL;
    }

    repo->manager = manager;

    snprintf(sql, 256, "SELECT branch_name FROM RepoHead WHERE repo_id='%s'",
             repo->id);
    if (seaf_db_foreach_selected_row (seaf->db, sql, load_branch_cb, repo) < 0) {
        g_warning ("Error read branch for repo %s.\n", repo->id);
        seaf_repo_unref (repo);
        return NULL;
    }

    if (repo->is_corrupted) {
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

static int 
create_db_tables_if_not_exist (SeafRepoManager *mgr)
{
    SeafDB *db = mgr->seaf->db;

    char *sql = "CREATE TABLE IF NOT EXISTS Repo (repo_id CHAR(37) PRIMARY KEY)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    int db_type = seaf_db_type (db);
    if (db_type == SEAF_DB_TYPE_MYSQL) {
        sql = "CREATE TABLE IF NOT EXISTS RepoOwner ("
            "repo_id CHAR(37) PRIMARY KEY, "
            "owner_id VARCHAR(255),"
            "INDEX (owner_id))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE RepoGroup (repo_id CHAR(37), group_id INTEGER, "
            "user_name VARCHAR(255), permission CHAR(15), "
            "UNIQUE INDEX (group_id, repo_id))";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    } else if (db_type == SEAF_DB_TYPE_SQLITE) {
        sql = "CREATE TABLE IF NOT EXISTS RepoOwner ("
            "repo_id CHAR(37) PRIMARY KEY, "
            "owner_id TEXT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
        sql = "CREATE INDEX IF NOT EXISTS OwnerIndex ON RepoOwner (owner_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS RepoGroup (repo_id CHAR(37), "
            "group_id INTEGER, user_name TEXT, permission CHAR(15))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS groupid_repoid_indx on "
            "RepoGroup (group_id, repo_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    sql = "CREATE TABLE IF NOT EXISTS RepoHead ("
        "repo_id CHAR(37) PRIMARY KEY, branch_name VARCHAR(10))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoToken ("
        "repo_id CHAR(37) PRIMARY KEY, token VARCHAR(65))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS PublicRepo (repo_id CHAR(37) PRIMARY KEY)";
    if (seaf_db_query (db, sql) < 0)
        return -1;
    
    sql = "CREATE TABLE IF NOT EXISTS WebAP (repo_id CHAR(37) PRIMARY KEY, "
        "access_property CHAR(10))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    return 0;
}

int
seaf_repo_manager_set_repo_owner (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  const char *email)
{
    char sql[256];

    snprintf (sql, sizeof(sql), "REPLACE INTO RepoOwner VALUES ('%s', '%s')",
              repo_id, email);
    if (seaf_db_query (mgr->seaf->db, sql) < 0)
        return -1;

    return 0;
}

static gboolean
get_owner (SeafDBRow *row, void *data)
{
    char **owner_id = data;

    *owner_id = g_strdup(seaf_db_row_get_column_text (row, 0));
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_repo_owner (SeafRepoManager *mgr,
                                  const char *repo_id)
{
    char sql[256];
    char *ret = NULL;

    snprintf (sql, sizeof(sql), 
              "SELECT owner_id FROM RepoOwner WHERE repo_id='%s'",
              repo_id);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      get_owner, &ret) < 0) {
        g_warning ("Failed to get owner id for repo %s.\n", repo_id);
        return NULL;
    }

    return ret;
}

static gboolean
collect_repos (SeafDBRow *row, void *data)
{
    GList **p_repos = data;
    const char *repo_id;
    SeafRepo *repo;

    repo_id = seaf_db_row_get_column_text (row, 0);
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        /* Continue to collect the remaining repos. */
        return TRUE;
    }
    *p_repos = g_list_prepend (*p_repos, repo);

    return TRUE;
}

GList *
seaf_repo_manager_get_repos_by_owner (SeafRepoManager *mgr,
                                      const char *email)
{
    GList *ret = NULL;
    char sql[256];

    snprintf (sql, 256, "SELECT repo_id FROM RepoOwner WHERE owner_id='%s'",
              email);

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_repos, &ret) < 0)
        return NULL;

    return g_list_reverse (ret);
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

GList *
seaf_repo_manager_get_repo_list (SeafRepoManager *mgr, int start, int limit)
{
    GList *ret = NULL;
    char sql[256];

    if (start == -1 && limit == -1)
        snprintf (sql, 256, "SELECT repo_id FROM Repo");
    else
        snprintf (sql, 256, "SELECT repo_id FROM Repo LIMIT %d, %d", start, limit);

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_repos, &ret) < 0)
        return NULL;

    return g_list_reverse (ret);
}

static gboolean
get_repo_size (SeafDBRow *row, void *vsize)
{
    gint64 *psize = vsize;

    *psize = seaf_db_row_get_column_int64 (row, 0);

    return FALSE;
}

gint64
seaf_repo_manager_get_repo_size (SeafRepoManager *mgr, const char *repo_id)
{
    gint64 size = 0;
    char sql[256];

    snprintf (sql, sizeof(sql), "SELECT size FROM RepoSize WHERE repo_id='%s'",
              repo_id);

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      get_repo_size, &size) < 0)
        return -1;

    return size;
}

int
seaf_repo_manager_set_access_property (SeafRepoManager *mgr, const char *repo_id,
                                       const char *ap)
{
    char sql[256];

    if (seaf_repo_manager_query_access_property (mgr, repo_id) == NULL) {
        snprintf (sql, sizeof(sql), "INSERT INTO WebAP VALUES ('%s', '%s')",
                  repo_id, ap);
    } else {
        snprintf (sql, sizeof(sql), "UPDATE WebAP SET access_property='%s' "
                  "WHERE repo_id='%s'", ap, repo_id);
    }

    if (seaf_db_query (mgr->seaf->db, sql) < 0) {
        g_warning ("DB error when set access property for repo %s, %s.\n", repo_id, ap);
        return -1;
    }
    
    return 0;
}

static gboolean
get_ap (SeafDBRow *row, void *data)
{
    char **ap = data;

    *ap = g_strdup (seaf_db_row_get_column_text (row, 0));

    return FALSE;
}

char *
seaf_repo_manager_query_access_property (SeafRepoManager *mgr, const char *repo_id)
{
    char sql[256];
    char *ret = NULL;

    snprintf (sql, sizeof(sql), "SELECT access_property FROM WebAP WHERE repo_id='%s'",
              repo_id);
 
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, get_ap, &ret) < 0) {
        g_warning ("DB error when get access property for repo %s.\n", repo_id);
        return NULL;
    }

    return ret;
}

int
seaf_repo_manager_share_repo (SeafRepoManager *mgr,
                              const char *repo_id,
                              int group_id,
                              const char *user_name,
                              const char *permission,
                              GError **error)
{
    char sql[512];
    
    snprintf (sql, sizeof(sql), "INSERT INTO RepoGroup VALUES ('%s', %d, '%s', '%s')",
              repo_id, group_id, user_name, permission);
    
    if (seaf_db_query (mgr->seaf->db, sql) < 0)
        return -1;

    return 0;
}

int
seaf_repo_manager_unshare_repo (SeafRepoManager *mgr,
                                const char *repo_id,
                                int group_id,
                                const char *user_name,
                                GError **error)
{
    char sql[512];
    
    snprintf (sql, sizeof(sql), "DELETE FROM RepoGroup WHERE repo_id='%s' "
              "AND group_id=%d", repo_id, group_id);

    return seaf_db_query (mgr->seaf->db, sql);
}

static gboolean
get_group_repoids_cb (SeafDBRow *row, void *data)
{
    GList **p_list = data;

    char *repo_id = g_strdup ((const char *)seaf_db_row_get_column_text (row, 0));

    *p_list = g_list_prepend (*p_list, repo_id);

    return TRUE;
}

GList *
seaf_repo_manager_get_group_repoids (SeafRepoManager *mgr,
                                     int group_id,
                                     GError **error)
{
    char sql[512];
    GList *repo_ids = NULL;

    snprintf (sql, sizeof(sql), "SELECT repo_id FROM RepoGroup "
              "WHERE group_id = %d", group_id);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, get_group_repoids_cb,
                                      &repo_ids) < 0)
        return NULL;

    return g_list_reverse (repo_ids);
}

static gboolean
get_group_repos_cb (SeafDBRow *row, void *data)
{
    GList **p_list = data;
    SeafileRepoGroup *repo_group = NULL;
    
    char *repo_id = g_strdup ((const char *)seaf_db_row_get_column_text (row, 0));
    int group_id = seaf_db_row_get_column_int (row, 1);
    char *user_name = g_strdup ((const char *)seaf_db_row_get_column_text (row, 2));
    repo_group = g_object_new (SEAFILE_TYPE_REPO_GROUP,
                               "repo_id", repo_id,
                               "group_id", group_id,
                               "user_name", user_name,
                               NULL);
    if (repo_group != NULL) {
        /* g_object_ref (repo_group); */
        *p_list = g_list_prepend (*p_list, repo_group);        
    }

    return TRUE;
}

GList *
seaf_repo_manager_get_group_my_share_repos (SeafRepoManager *mgr,
                                            const char *username,
                                            GError **error)
{
    char sql[512];
    GList *repos = NULL;

    snprintf (sql, sizeof(sql), "SELECT repo_id, group_id, user_name "
              "FROM RepoGroup WHERE user_name = '%s'", username);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, get_group_repos_cb,
                                      &repos) < 0)
        return NULL;

    return g_list_reverse (repos);
}

static gboolean
get_repo_share_from (SeafDBRow *row, void *data)
{
    char **share_from = data;

    *share_from = g_strdup (seaf_db_row_get_column_text (row, 0));
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_repo_share_from (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       GError **error)
{
    char sql[512];
    char *ret = NULL;

    snprintf (sql, sizeof(sql), "SELECT user_name FROM RepoGroup "
              "WHERE repo_id = '%s'", repo_id);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      get_repo_share_from, &ret) < 0) {
        g_warning ("DB error when get repo share from for repo %s.\n",
                   repo_id);
        return NULL;
    }

    return ret;
}

int
seaf_repo_manager_remove_repo_group (SeafRepoManager *mgr,
                                     int group_id,
                                     const char *user_name,
                                     GError **error)
{
    char sql[512];

    if (!user_name) {
        snprintf (sql, sizeof(sql), "DELETE FROM RepoGroup WHERE group_id=%d",
                  group_id);
    } else {
        snprintf (sql, sizeof(sql), "DELETE FROM RepoGroup WHERE group_id=%d AND "
                  "user_name = '%s'", group_id, user_name);
    }

    return seaf_db_query (mgr->seaf->db, sql);
}
