/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include "log.h"

#include <glib/gstdio.h>

#include <json-glib/json-glib.h>
#include <openssl/sha.h>

#include <ccnet.h>
#include <ccnet/ccnet-object.h>
#include "utils.h"
#include "avl/avl.h"
#include "log.h"
#include "seafile.h"

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
#include "merge-new.h"
#include "monitor-rpc-wrappers.h"

#include "seaf-db.h"

#define INDEX_DIR "index"

struct _SeafRepoManagerPriv {
    avl_tree_t *repo_tree;
    pthread_rwlock_t lock;
};

static const char *ignore_table[] = {
    "*~",
    "*#",
    /* -------------
     * windows tmp files
     * -------------
     */
    "*.tmp",
    "*.TMP",
    /* ms office tmp files */
    "~$*.doc",
    "~$*.docx",
    "~$*.xls",
    "~$*.xlsx",
    "~$*.ppt",
    "~$*.pptx",
    /* windows image cache */
    "Thumbs.db",
    NULL,
};

static GPatternSpec** ignore_patterns;

static SeafRepo *
load_repo (SeafRepoManager *manager, const char *repo_id);

static int create_db_tables_if_not_exist (SeafRepoManager *mgr);

static int save_branch_repo_map (SeafRepoManager *manager, SeafBranch *branch);

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
set_head_common (SeafRepo *repo, SeafBranch *branch, SeafCommit *commit)
{
    if (repo->head)
        seaf_branch_unref (repo->head);
    repo->head = branch;
    seaf_branch_ref(branch);
}

int
seaf_repo_set_head (SeafRepo *repo, SeafBranch *branch, SeafCommit *commit)
{
    if (save_branch_repo_map (repo->manager, branch) < 0)
        return -1;
    set_head_common (repo, branch, commit);
    return 0;
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
        seaf_warning ("Failed to get branch list of repo %s.\n", repo->id);
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

int
seaf_repo_verify_passwd (SeafRepo *repo, const char *passwd)
{
    GString *buf = g_string_new (NULL);
    unsigned char key[16], iv[16];
    char hex[33];

    /* Recompute the magic and compare it with the one comes with the repo. */
    g_string_append_printf (buf, "%s%s", repo->id, passwd);

    seafile_generate_enc_key (buf->str, buf->len, repo->enc_version, key, iv);

    g_string_free (buf, TRUE);
    rawdata_to_hex (key, hex, 16);

    if (strcmp (hex, repo->magic) == 0)
        return 0;
    else
        return -1;
}

static gboolean
should_ignore(const char *filename, void *data)
{
    GPatternSpec **spec = ignore_patterns;

    while (*spec) {
        if (g_pattern_match_string(*spec, filename))
            return TRUE;
        spec++;
    }
    
    /*
     *  Illegal charaters in filenames under windows: (In Linux, only '/' is
     *  disallowed)
     *  
     *  - / \ : * ? " < > | \b \t  
     *  - \1 - \31
     * 
     *  Refer to http://msdn.microsoft.com/en-us/library/aa365247%28VS.85%29.aspx
     */
    static char illegals[] = {'\\', '/', ':', '*', '?', '"', '<', '>', '|', '\b', '\t'};

    int i;
    char c;
    
    for (i = 0; i < G_N_ELEMENTS(illegals); i++) {
        if (strchr (filename, illegals[i])) {
            return TRUE;
        }
    }

    for (c = 1; c <= 31; c++) {
        if (strchr (filename, c)) {
            return TRUE;
        }
    }
        
    return FALSE;
}

static SeafCommit *
get_commit(SeafRepo *repo, const char *branch_or_commit)
{
    SeafBranch *b;
    SeafCommit *c;

    b = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id,
                                        branch_or_commit);
    if (!b) {
        if (strcmp(branch_or_commit, "HEAD") == 0)
            c = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                repo->head->commit_id);
        else
            c = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                branch_or_commit);
    } else {
        c = seaf_commit_manager_get_commit (seaf->commit_mgr, b->commit_id);
    }

    if (b)
        seaf_branch_unref (b);
    
    return c;
}

GList *
seaf_repo_diff (SeafRepo *repo, const char *old, const char *new, char **error)
{
    SeafCommit *c1 = NULL, *c2 = NULL;
    int ret = 0;
    GList *diff_entries = NULL;

    g_return_val_if_fail (*error == NULL, NULL);

    c2 = get_commit (repo, new);
    if (!c2) {
        *error = g_strdup("Can't find new commit");
        return NULL;
    }
    
    if (old == NULL || old[0] == '\0') {
        if (c2->parent_id && c2->second_parent_id) {
            ret = diff_merge (c2, &diff_entries);
            if (ret < 0) {
                *error = g_strdup("Failed to do diff");
                seaf_commit_unref (c2);
                return NULL;
            }
            seaf_commit_unref (c2);
            return diff_entries;
        }

        if (!c2->parent_id) {
            seaf_commit_unref (c2);
            return NULL;
        }
        c1 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             c2->parent_id);
    } else {
        c1 = get_commit (repo, old);
    }

    if (!c1) {
        *error = g_strdup("Can't find old commit");
        seaf_commit_unref (c2);
        return NULL;
    }

    /* do diff */
    ret = diff_commits (c1, c2, &diff_entries);
    if (ret < 0)
        *error = g_strdup("Failed to do diff");

    seaf_commit_unref (c1);
    seaf_commit_unref (c2);

    return diff_entries;
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

    ignore_patterns = g_new0 (GPatternSpec*, G_N_ELEMENTS(ignore_table));
    int i;
    for (i = 0; ignore_table[i] != NULL; i++) {
        ignore_patterns[i] = g_pattern_spec_new (ignore_table[i]);
    }

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
        seaf_warning ("[repo mgr] failed to create tables.\n");
        return -1;
    }

    return 0;
}

int
seaf_repo_manager_start (SeafRepoManager *mgr)
{
    return 0;
}

int
seaf_repo_manager_add_repo (SeafRepoManager *manager,
                            SeafRepo *repo)
{
    char sql[256];
    SeafDB *db = manager->seaf->db;

    snprintf (sql, sizeof(sql), "INSERT INTO Repo VALUES ('%s')", repo->id);
    if (seaf_db_query (db, sql) < 0)
        return -1;

    repo->manager = manager;

#if 0
    if (pthread_rwlock_wrlock (&manager->priv->lock) < 0) {
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
        return -1;
    }

    avl_insert (manager->priv->repo_tree, repo);
    /* Don't need to increse ref count since ref count of a new repo
     * is already 1.
     */

    pthread_rwlock_unlock (&manager->priv->lock);
#endif

    return 0;
}

static int
remove_repo_ondisk (SeafRepoManager *mgr, const char *repo_id)
{
    char sql[256];
    SeafDB *db = mgr->seaf->db;

    /* Remove record in repo table first.
     * Once this is commited, we can gc the other tables later even if
     * we're interrupted.
     */
    snprintf (sql, sizeof(sql), "DELETE FROM Repo WHERE repo_id = '%s'", repo_id);
    if (seaf_db_query (db, sql) < 0)
        return -1;

    /* remove branch */
    GList *p;
    GList *branch_list = 
        seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo_id);
    for (p = branch_list; p; p = p->next) {
        SeafBranch *b = (SeafBranch *)p->data;
        seaf_repo_manager_branch_repo_unmap (mgr, b);
        seaf_branch_manager_del_branch (seaf->branch_mgr, repo_id, b->name);
    }
    seaf_branch_list_free (branch_list);

    snprintf (sql, sizeof(sql), "DELETE FROM RepoOwner WHERE repo_id = '%s'", 
              repo_id);
    seaf_db_query (db, sql);

    snprintf (sql, sizeof(sql), "DELETE FROM RepoGroup WHERE repo_id = '%s'", 
              repo_id);
    seaf_db_query (db, sql);

    if (!seaf->cloud_mode) {
        snprintf (sql, sizeof(sql), "DELETE FROM InnerPubRepo WHERE repo_id = '%s'", 
                  repo_id);
        seaf_db_query (db, sql);
    }

    if (seaf->cloud_mode) {
        snprintf (sql, sizeof(sql),
                  "DELETE FROM OrgRepo WHERE repo_id = '%s'", 
                  repo_id);
        seaf_db_query (db, sql);

        snprintf (sql, sizeof(sql),
                  "DELETE FROM OrgGroupRepo WHERE repo_id = '%s'", 
                  repo_id);
        seaf_db_query (db, sql);

        snprintf (sql, sizeof(sql),
                  "DELETE FROM OrgInnerPubRepo WHERE repo_id = '%s'", 
                  repo_id);
        seaf_db_query (db, sql);
    }

    snprintf (sql, sizeof(sql), "DELETE FROM RepoUserToken WHERE repo_id = '%s'", 
              repo_id);
    seaf_db_query (db, sql);

    return 0;
}

int
seaf_repo_manager_del_repo (SeafRepoManager *mgr,
                            SeafRepo *repo)
{
    if (remove_repo_ondisk (mgr, repo->id) < 0)
        return -1;

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
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
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
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
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

static int
save_branch_repo_map (SeafRepoManager *manager, SeafBranch *branch)
{
    char sql[256];

    snprintf (sql, sizeof(sql), "REPLACE INTO RepoHead VALUES ('%s', '%s')",
              branch->repo_id, branch->name);
    return seaf_db_query (seaf->db, sql);
}

int
seaf_repo_manager_branch_repo_unmap (SeafRepoManager *manager, SeafBranch *branch)
{
    char sql[256];

    snprintf (sql, sizeof(sql), "DELETE FROM RepoHead WHERE branch_name = '%s'"
              " AND repo_id = '%s'",
              branch->name, branch->repo_id);
    return seaf_db_query (seaf->db, sql);
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
        seaf_warning ("Commit %s is missing\n", branch->commit_id);
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
        seaf_warning ("Broken branch name for repo %s\n", repo->id); 
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
        seaf_warning ("[repo mgr] failed to alloc repo.\n");
        return NULL;
    }

    repo->manager = manager;

    snprintf(sql, 256, "SELECT branch_name FROM RepoHead WHERE repo_id='%s'",
             repo->id);
    /* Note that it's also an error if repo head is not set.
     * This means the repo is corrupted.
     */
    n = seaf_db_foreach_selected_row (seaf->db, sql, load_branch_cb, repo);
    if (n < 0) {
        seaf_warning ("Error read branch for repo %s.\n", repo->id);
        seaf_repo_free (repo);
        return NULL;
    } else if (n == 0) {
        seaf_repo_free (repo);
        remove_repo_ondisk (manager, repo_id);
        return NULL;
    }

    if (repo->is_corrupted) {
        seaf_repo_free (repo);
        remove_repo_ondisk (manager, repo_id);
        return NULL;
    }

#if 0
    if (pthread_rwlock_wrlock (&manager->priv->lock) < 0) {
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
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

        sql = "CREATE TABLE IF NOT EXISTS RepoGroup (repo_id CHAR(37), "
            "group_id INTEGER, user_name VARCHAR(255), permission CHAR(15), "
            "UNIQUE INDEX (group_id, repo_id), "
            "INDEX (repo_id), INDEX (user_name))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        if (!mgr->seaf->cloud_mode) {
            sql = "CREATE TABLE IF NOT EXISTS InnerPubRepo ("
                "repo_id CHAR(37) PRIMARY KEY,"
                "permission CHAR(15))";
            if (seaf_db_query (db, sql) < 0)
                return -1;
        }

        if (mgr->seaf->cloud_mode) {
            sql = "CREATE TABLE IF NOT EXISTS OrgRepo (org_id INTEGER, "
                "repo_id CHAR(37), "
                "user VARCHAR(255), "
                "INDEX (org_id, repo_id), UNIQUE INDEX (repo_id), "
                "INDEX (org_id, user))";
            if (seaf_db_query (db, sql) < 0)
                return -1;

            sql = "CREATE TABLE IF NOT EXISTS OrgGroupRepo ("
                "org_id INTEGER, repo_id CHAR(37), "
                "group_id INTEGER, owner VARCHAR(255), permission CHAR(15), "
                "UNIQUE INDEX (org_id, group_id, repo_id), "
                "INDEX (repo_id), INDEX (owner))";
            if (seaf_db_query (db, sql) < 0)
                return -1;

            sql = "CREATE TABLE IF NOT EXISTS OrgInnerPubRepo ("
                "org_id INTEGER, repo_id CHAR(37),"
                "PRIMARY KEY (org_id, repo_id), "
                "permission CHAR(15))";
            if (seaf_db_query (db, sql) < 0)
                return -1;
        }

        sql = "CREATE TABLE IF NOT EXISTS RepoUserToken ("
            "repo_id CHAR(37), "
            "email VARCHAR(255), "
            "token CHAR(41), "
            "UNIQUE INDEX (repo_id, token))";

        if (seaf_db_query (db, sql) < 0)
            return -1;
        
    } else if (db_type == SEAF_DB_TYPE_SQLITE) {
        /* Owner */

        sql = "CREATE TABLE IF NOT EXISTS RepoOwner ("
            "repo_id CHAR(37) PRIMARY KEY, "
            "owner_id TEXT)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
        sql = "CREATE INDEX IF NOT EXISTS OwnerIndex ON RepoOwner (owner_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        /* Group repo */

        sql = "CREATE TABLE IF NOT EXISTS RepoGroup (repo_id CHAR(37), "
            "group_id INTEGER, user_name TEXT, permission CHAR(15))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS groupid_repoid_indx on "
            "RepoGroup (group_id, repo_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE INDEX IF NOT EXISTS repogroup_repoid_index on "
            "RepoGroup (repo_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE INDEX IF NOT EXISTS repogroup_username_indx on "
            "RepoGroup (user_name)";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        /* Public repo */

        if (!mgr->seaf->cloud_mode) {
            sql = "CREATE TABLE IF NOT EXISTS InnerPubRepo ("
                "repo_id CHAR(37) PRIMARY KEY,"
                "permission CHAR(15))";
            if (seaf_db_query (db, sql) < 0)
                return -1;
        }

        if (mgr->seaf->cloud_mode) {
            /* Org repo */

            sql = "CREATE TABLE IF NOT EXISTS OrgRepo (org_id INTEGER, "
                "repo_id CHAR(37), user VARCHAR(255))";
            if (seaf_db_query (db, sql) < 0)
                return -1;

            sql = "CREATE UNIQUE INDEX IF NOT EXISTS repoid_indx on "
                "OrgRepo (repo_id)";
            if (seaf_db_query (db, sql) < 0)
                return -1;

            sql = "CREATE INDEX IF NOT EXISTS orgid_repoid_indx on "
                "OrgRepo (org_id, repo_id)";
            if (seaf_db_query (db, sql) < 0)
                return -1;

            sql = "CREATE INDEX IF NOT EXISTS orgrepo_orgid_user_indx on "
                "OrgRepo (org_id, user)";
            if (seaf_db_query (db, sql) < 0)
                return -1;
            
            /* Org group repo */

            sql = "CREATE TABLE IF NOT EXISTS OrgGroupRepo ("
                "org_id INTEGER, repo_id CHAR(37), "
                "group_id INTEGER, owner VARCHAR(255), permission CHAR(15))";
            if (seaf_db_query (db, sql) < 0)
                return -1;

            sql = "CREATE UNIQUE INDEX IF NOT EXISTS orgid_groupid_repoid_indx on "
                "OrgGroupRepo (org_id, group_id, repo_id)";
            if (seaf_db_query (db, sql) < 0)
                return -1;

            sql = "CREATE INDEX IF NOT EXISTS org_repoid_index on "
                "OrgGroupRepo (repo_id)";
            if (seaf_db_query (db, sql) < 0)
                return -1;

            sql = "CREATE INDEX IF NOT EXISTS org_owner_indx on "
                "OrgGroupRepo (owner)";
            if (seaf_db_query (db, sql) < 0)
                return -1;

            /* Org public repo */

            sql = "CREATE TABLE IF NOT EXISTS OrgInnerPubRepo ("
                "org_id INTEGER, repo_id CHAR(37),"
                "permission CHAR(15),"
                "PRIMARY KEY (org_id, repo_id))";
            if (seaf_db_query (db, sql) < 0)
                return -1;
        }

        sql = "CREATE TABLE IF NOT EXISTS RepoUserToken ("
            "repo_id CHAR(37), "
            "email VARCHAR(255), "
            "token CHAR(41))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE UNIQUE INDEX IF NOT EXISTS repo_token_indx on "
            "RepoUserToken (repo_id, token)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    sql = "CREATE TABLE IF NOT EXISTS RepoHead ("
        "repo_id CHAR(37) PRIMARY KEY, branch_name VARCHAR(10))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS WebAP (repo_id CHAR(37) PRIMARY KEY, "
        "access_property CHAR(10))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    return 0;
}

/*
 * Repo properties functions.
 */

static inline char *
generate_repo_token ()
{
    char *uuid = gen_uuid ();
    unsigned char sha1[20];
    char token[41];
    SHA_CTX s;

    SHA1_Init (&s);
    SHA1_Update (&s, uuid, strlen(uuid));
    SHA1_Final (sha1, &s);

    rawdata_to_hex (sha1, token, 20);

    g_free (uuid);

    return g_strdup (token);
}

int
seaf_repo_manager_set_repo_token (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  const char *email,
                                  const char *token)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "REPLACE INTO RepoUserToken VALUES ('%s', '%s', '%s')",
              repo_id, email, token);

    if (seaf_db_query (mgr->seaf->db, sql) < 0) {
        seaf_warning ("failed to set repo token. repo = %s, email = %s\n",
                      repo_id, email);
        return -1;
    }

    return 0;
}

static gboolean
get_token (SeafDBRow *row, void *data)
{
    char **token = data;

    *token = g_strdup(seaf_db_row_get_column_text (row, 0));
    /* There should be only one result. */
    return FALSE;
}


char *
seaf_repo_manager_get_repo_token_nonnull (SeafRepoManager *mgr,
                                          const char *repo_id,
                                          const char *email)
{
    char sql[256];
    char *token = NULL;

    if (!repo_exists_in_db (mgr->seaf->db, repo_id))
        return NULL;
    
    snprintf (sql, sizeof(sql), 
              "SELECT token FROM RepoUserToken WHERE repo_id='%s' and email='%s'",
              repo_id, email);

    int n_row = seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                              get_token, &token);
    if (n_row < 0) {
        seaf_warning ("DB error when get token for repo %s, email %s.\n",
                      repo_id, email);
        return NULL;

    } else if (n_row == 0) {
        /* token for this (repo, user) does not exist yet */
        token = generate_repo_token ();
        if (seaf_repo_manager_set_repo_token(mgr, repo_id, email, token) < 0) {
            g_free (token);
            return NULL;
        }
    }

    return token;
}

char *
seaf_repo_manager_get_repo_token (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  const char *email)
{
    char sql[256];
    char *token = NULL;

    if (!repo_exists_in_db (mgr->seaf->db, repo_id))
        return NULL;

    snprintf (sql, sizeof(sql), 
              "SELECT token FROM RepoUserToken WHERE repo_id='%s' and email='%s'",
              repo_id, email);

    int n_row = seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                              get_token, &token);
    if (n_row < 0) {
        seaf_warning ("DB error when get token for repo %s, email %s.\n",
                      repo_id, email);
    }

    return token;
}

static gboolean
get_email_by_token_cb (SeafDBRow *row, void *data)
{
    char **email_ptr = data;

    *email_ptr = g_strdup(seaf_db_row_get_column_text (row, 0));
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_email_by_token (SeafRepoManager *manager,
                                      const char *repo_id,
                                      const char *token)
{
    if (!repo_id || !token)
        return NULL;
    
    char *email = NULL;
    GString *buf = g_string_new(NULL);

    g_string_append_printf (
        buf, "SELECT email FROM RepoUserToken "
        "WHERE repo_id = '%s' AND token = '%s'",
        repo_id, token);

    seaf_db_foreach_selected_row (seaf->db, buf->str,
                                  get_email_by_token_cb, &email);

    g_string_free (buf, TRUE);
    
    return email;
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

/*
 * Permission related functions.
 */

/* Owner functions. */

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
        seaf_warning ("Failed to get owner id for repo %s.\n", repo_id);
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

/* Web access permission. */

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
        seaf_warning ("DB error when set access property for repo %s, %s.\n", repo_id, ap);
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
        seaf_warning ("DB error when get access property for repo %s.\n", repo_id);
        return NULL;
    }

    return ret;
}

/* Group repos. */

int
seaf_repo_manager_add_group_repo (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  int group_id,
                                  const char *owner,
                                  const char *permission,
                                  GError **error)
{
    char sql[512];
    
    snprintf (sql, sizeof(sql), "INSERT INTO RepoGroup VALUES ('%s', %d, '%s', '%s')",
              repo_id, group_id, owner, permission);
    
    if (seaf_db_query (mgr->seaf->db, sql) < 0)
        return -1;

    return 0;
}

int
seaf_repo_manager_del_group_repo (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  int group_id,
                                  GError **error)
{
    char sql[512];
    
    snprintf (sql, sizeof(sql), "DELETE FROM RepoGroup WHERE group_id=%d "
              "AND repo_id='%s'", group_id, repo_id);

    return seaf_db_query (mgr->seaf->db, sql);
}

static gboolean
get_group_ids_cb (SeafDBRow *row, void *data)
{
    GList **plist = data;

    int group_id = seaf_db_row_get_column_int (row, 0);

    *plist = g_list_prepend (*plist, (gpointer)(long)group_id);

    return TRUE;
}

GList *
seaf_repo_manager_get_groups_by_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      GError **error)
{
    char sql[512];
    GList *group_ids = NULL;
    
    snprintf (sql, sizeof(sql), "SELECT group_id FROM RepoGroup "
              "WHERE repo_id = '%s'", repo_id);
    
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, get_group_ids_cb,
                                       &group_ids) < 0) {
        g_list_free (group_ids);
        return NULL;
    }

    return g_list_reverse (group_ids);
}

static gboolean
get_group_perms_cb (SeafDBRow *row, void *data)
{
    GList **plist = data;
    GroupPerm *perm = g_new0 (GroupPerm, 1);

    perm->group_id = seaf_db_row_get_column_int (row, 0);
    const char *permission = seaf_db_row_get_column_text(row, 1);
    g_strlcpy (perm->permission, permission, sizeof(perm->permission));

    *plist = g_list_prepend (*plist, perm);

    return TRUE;
}

GList *
seaf_repo_manager_get_group_perm_by_repo (SeafRepoManager *mgr,
                                          const char *repo_id,
                                          GError **error)
{
    char sql[512];
    GList *group_perms = NULL, *p;
    
    snprintf (sql, sizeof(sql), "SELECT group_id, permission FROM RepoGroup "
              "WHERE repo_id = '%s'", repo_id);
    
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, get_group_perms_cb,
                                      &group_perms) < 0) {
        for (p = group_perms; p != NULL; p = p->next)
            g_free (p->data);
        g_list_free (group_perms);
        return NULL;
    }

    return g_list_reverse (group_perms);
}

int
seaf_repo_manager_set_group_repo_perm (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       int group_id,
                                       const char *permission,
                                       GError **error)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "UPDATE RepoGroup SET permission='%s' WHERE "
              "repo_id='%s' AND group_id=%d",
              permission, repo_id, group_id);
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
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;
    SeafileSharedRepo *srepo = NULL;
    
    const char *repo_id = seaf_db_row_get_column_text (row, 0);
    int group_id = seaf_db_row_get_column_int (row, 1);
    const char *user_name = seaf_db_row_get_column_text (row, 2);
    const char *permission = seaf_db_row_get_column_text (row, 3);

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo)
        goto out;

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->head->commit_id);
    if (!commit)
        goto out;

    srepo = g_object_new (SEAFILE_TYPE_SHARED_REPO,
                          "share_type", "group",
                          "repo_id", repo_id,
                          "repo_name", repo->name,
                          "repo_desc", repo->desc,
                          "group_id", group_id,
                          "user", user_name,
                          "permission", permission,
                          "last_modified", commit->ctime,
                          NULL);
    if (srepo != NULL) {
        *p_list = g_list_prepend (*p_list, srepo);
    }

out:
    seaf_repo_unref (repo);
    seaf_commit_unref (commit);
    return TRUE;
}

GList *
seaf_repo_manager_get_group_repos_by_owner (SeafRepoManager *mgr,
                                            const char *owner,
                                            GError **error)
{
    char sql[512];
    GList *repos = NULL;

    snprintf (sql, sizeof(sql), "SELECT repo_id, group_id, user_name, permission "
              "FROM RepoGroup WHERE user_name = '%s'", owner);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, get_group_repos_cb,
                                      &repos) < 0)
        return NULL;

    return g_list_reverse (repos);
}

static gboolean
get_group_repo_owner (SeafDBRow *row, void *data)
{
    char **share_from = data;

    *share_from = g_strdup (seaf_db_row_get_column_text (row, 0));
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_group_repo_owner (SeafRepoManager *mgr,
                                        const char *repo_id,
                                        GError **error)
{
    char sql[512];
    char *ret = NULL;

    snprintf (sql, sizeof(sql), "SELECT user_name FROM RepoGroup "
              "WHERE repo_id = '%s'", repo_id);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      get_group_repo_owner, &ret) < 0) {
        seaf_warning ("DB error when get repo share from for repo %s.\n",
                   repo_id);
        return NULL;
    }

    return ret;
}

int
seaf_repo_manager_remove_group_repos (SeafRepoManager *mgr,
                                      int group_id,
                                      const char *owner,
                                      GError **error)
{
    char sql[512];

    if (!owner) {
        snprintf (sql, sizeof(sql), "DELETE FROM RepoGroup WHERE group_id=%d",
                  group_id);
    } else {
        snprintf (sql, sizeof(sql), "DELETE FROM RepoGroup WHERE group_id=%d AND "
                  "user_name = '%s'", group_id, owner);
    }

    return seaf_db_query (mgr->seaf->db, sql);
}

/* Inner public repos */

int
seaf_repo_manager_set_inner_pub_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      const char *permission)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "REPLACE INTO InnerPubRepo VALUES ('%s', '%s')",
              repo_id, permission);
    return seaf_db_query (mgr->seaf->db, sql);
}

int
seaf_repo_manager_unset_inner_pub_repo (SeafRepoManager *mgr,
                                        const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "DELETE FROM InnerPubRepo WHERE repo_id = '%s'",
              repo_id);
    return seaf_db_query (mgr->seaf->db, sql);
}

gboolean
seaf_repo_manager_is_inner_pub_repo (SeafRepoManager *mgr,
                                     const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "SELECT repo_id FROM InnerPubRepo WHERE repo_id='%s'",
              repo_id);
    return seaf_db_check_for_existence (mgr->seaf->db, sql);
}

static gboolean
collect_public_repos (SeafDBRow *row, void *data)
{
    GList **ret = (GList **)data;
    SeafileSharedRepo *srepo;
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;
    const char *repo_id, *owner, *permission;

    repo_id = seaf_db_row_get_column_text (row, 0);
    owner = seaf_db_row_get_column_text (row, 1);
    permission = seaf_db_row_get_column_text (row, 2);

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo)
        goto out;

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->head->commit_id);
    if (!commit)
        goto out;

    srepo = g_object_new (SEAFILE_TYPE_SHARED_REPO,
                          "share_type", "public",
                          "repo_id", repo_id,
                          "repo_name", repo->name,
                          "repo_desc", repo->desc,
                          "encrypted", repo->encrypted,
                          "permission", permission,
                          "user", owner,
                          "last_modified", commit->ctime,
                          NULL);
    *ret = g_list_prepend (*ret, srepo);

out:
    seaf_repo_unref (repo);
    seaf_commit_unref (commit);
    return TRUE;
}

GList *
seaf_repo_manager_list_inner_pub_repos (SeafRepoManager *mgr)
{
    GList *ret = NULL, *p;
    char sql[256];

    snprintf (sql, 256,
              "SELECT InnerPubRepo.repo_id, owner_id, permission "
              "FROM InnerPubRepo, RepoOwner "
              "WHERE InnerPubRepo.repo_id=RepoOwner.repo_id");

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      collect_public_repos, &ret) < 0) {
        for (p = ret; p != NULL; p = p->next)
            g_object_unref (p->data);
        g_list_free (ret);
        return NULL;
    }

    return g_list_reverse (ret);    
}

GList *
seaf_repo_manager_list_inner_pub_repos_by_owner (SeafRepoManager *mgr,
                                                 const char *user)
{
    GList *ret = NULL, *p;
    char sql[256];

    snprintf (sql, 256,
              "SELECT InnerPubRepo.repo_id, owner_id, permission "
              "FROM InnerPubRepo, RepoOwner "
              "WHERE InnerPubRepo.repo_id=RepoOwner.repo_id AND owner_id='%s'",
              user);

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      collect_public_repos, &ret) < 0) {
        for (p = ret; p != NULL; p = p->next)
            g_object_unref (p->data);
        g_list_free (ret);
        return NULL;
    }

    return g_list_reverse (ret);    
}

char *
seaf_repo_manager_get_inner_pub_repo_perm (SeafRepoManager *mgr,
                                           const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "SELECT permission FROM InnerPubRepo WHERE repo_id='%s'",
              repo_id);
    return seaf_db_get_string(mgr->seaf->db, sql);
}

/* Org repos. */

int
seaf_repo_manager_get_repo_org (SeafRepoManager *mgr,
                                const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "SELECT org_id FROM OrgRepo WHERE repo_id = '%s'",
              repo_id);
    return seaf_db_get_int (mgr->seaf->db, sql);
}

char *
seaf_repo_manager_get_org_repo_owner (SeafRepoManager *mgr,
                                      const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "SELECT user FROM OrgRepo WHERE repo_id = '%s'",
              repo_id);
    return seaf_db_get_string (mgr->seaf->db, sql);
}

int
seaf_repo_manager_set_org_repo (SeafRepoManager *mgr,
                                int org_id,
                                const char *repo_id,
                                const char *user)
{
    char sql[256];

    snprintf (sql, sizeof(sql), "INSERT INTO OrgRepo VALUES (%d, '%s', '%s')",
              org_id, repo_id, user);
    if (seaf_db_query (mgr->seaf->db, sql) < 0)
        return -1;

    return 0;
}

GList *
seaf_repo_manager_get_org_repo_list (SeafRepoManager *mgr,
                                     int org_id,
                                     int start,
                                     int limit)
{
    char sql[512];
    GList *ret = NULL;
    
    snprintf (sql, sizeof(sql), "SELECT repo_id FROM OrgRepo "
              "WHERE org_id = %d LIMIT %d, %d", org_id, start, limit);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      collect_repos, &ret) < 0) {
        return NULL;
    }

    return g_list_reverse (ret);
}

int
seaf_repo_manager_remove_org_repo_by_org_id (SeafRepoManager *mgr,
                                             int org_id)
{
    char sql[512];

    snprintf (sql, sizeof(sql), "DELETE FROM OrgRepo WHERE org_id = %d",
              org_id);

    return seaf_db_query (mgr->seaf->db, sql);
}

GList *
seaf_repo_manager_get_org_repos_by_owner (SeafRepoManager *mgr,
                                          int org_id,
                                          const char *user)
{
    GList *ret = NULL;
    char sql[512];

    snprintf (sql, sizeof(sql), "SELECT repo_id FROM OrgRepo "
              "WHERE org_id=%d AND user='%s'", org_id, user);

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_repos, &ret) < 0)
        return NULL;

    return g_list_reverse (ret);
}

int
seaf_repo_manager_get_org_id_by_repo_id (SeafRepoManager *mgr,
                                         const char *repo_id,
                                         GError **error)
{
    char sql[256];

    snprintf (sql, sizeof(sql), "SELECT org_id FROM OrgRepo "
              "WHERE repo_id = '%s'", repo_id);

    return seaf_db_get_int (mgr->seaf->db, sql);
}


/* Org group repos. */

int
seaf_repo_manager_add_org_group_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      int org_id,
                                      int group_id,
                                      const char *owner,
                                      const char *permission,
                                      GError **error)
{
    char sql[512];
    
    snprintf (sql, sizeof(sql),
              "INSERT INTO OrgGroupRepo VALUES (%d, '%s', %d, '%s', '%s')",
              org_id, repo_id, group_id, owner, permission);
    
    if (seaf_db_query (mgr->seaf->db, sql) < 0)
        return -1;

    return 0;
}

int
seaf_repo_manager_del_org_group_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      int org_id,
                                      int group_id,
                                      GError **error)
{
    char sql[512];
    
    snprintf (sql, sizeof(sql),
              "DELETE FROM OrgGroupRepo WHERE "
              "org_id=%d AND group_id=%d AND repo_id='%s'",
              org_id, group_id, repo_id);

    return seaf_db_query (mgr->seaf->db, sql);
}

GList *
seaf_repo_manager_get_org_group_repoids (SeafRepoManager *mgr,
                                         int org_id,
                                         int group_id,
                                         GError **error)
{
    char sql[512];
    GList *repo_ids = NULL;

    snprintf (sql, sizeof(sql), "SELECT repo_id FROM OrgGroupRepo "
              "WHERE org_id = %d AND group_id = %d",
              org_id, group_id);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, get_group_repoids_cb,
                                      &repo_ids) < 0)
        return NULL;

    return g_list_reverse (repo_ids);
}

GList *
seaf_repo_manager_get_org_groups_by_repo (SeafRepoManager *mgr,
                                          int org_id,
                                          const char *repo_id,
                                          GError **error)
{
    char sql[512];
    GList *group_ids = NULL;
    
    snprintf (sql, sizeof(sql), "SELECT group_id FROM OrgGroupRepo "
              "WHERE org_id = %d AND repo_id = '%s'",
              org_id, repo_id);
    
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, get_group_ids_cb,
                                       &group_ids) < 0) {
        g_list_free (group_ids);
        return NULL;
    }

    return g_list_reverse (group_ids);
}

GList *
seaf_repo_manager_get_org_group_perm_by_repo (SeafRepoManager *mgr,
                                              int org_id,
                                              const char *repo_id,
                                              GError **error)
{
    char sql[512];
    GList *group_perms = NULL, *p;
    
    snprintf (sql, sizeof(sql), "SELECT group_id, permission FROM OrgGroupRepo "
              "WHERE org_id = %d AND repo_id = '%s'",
              org_id, repo_id);
    
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, get_group_perms_cb,
                                      &group_perms) < 0) {
        for (p = group_perms; p != NULL; p = p->next)
            g_free (p->data);
        g_list_free (group_perms);
        return NULL;
    }

    return g_list_reverse (group_perms);
}

int
seaf_repo_manager_set_org_group_repo_perm (SeafRepoManager *mgr,
                                           const char *repo_id,
                                           int org_id,
                                           int group_id,
                                           const char *permission,
                                           GError **error)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "UPDATE OrgGroupRepo SET permission='%s' WHERE "
              "repo_id='%s' AND org_id=%d AND group_id=%d",
              permission, repo_id, org_id, group_id);
    return seaf_db_query (mgr->seaf->db, sql);
}

char *
seaf_repo_manager_get_org_group_repo_owner (SeafRepoManager *mgr,
                                            int org_id,
                                            int group_id,
                                            const char *repo_id,
                                            GError **error)
{
    char sql[512];
    char *ret = NULL;

    snprintf (sql, sizeof(sql), "SELECT owner FROM OrgGroupRepo WHERE "
              "org_id =%d AND group_id = %d AND repo_id = '%s'",
              org_id, group_id, repo_id);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      get_group_repo_owner, &ret) < 0) {
        seaf_warning ("DB error when get repo owner from for org repo %s.\n",
                   repo_id);
        return NULL;
    }

    return ret;
}

GList *
seaf_repo_manager_get_org_group_repos_by_owner (SeafRepoManager *mgr,
                                                int org_id,
                                                const char *owner,
                                                GError **error)
{
    char sql[512];
    GList *repos = NULL;

    snprintf (sql, sizeof(sql), "SELECT repo_id, group_id, owner, permission "
              "FROM OrgGroupRepo WHERE owner = '%s'", owner);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, get_group_repos_cb,
                                      &repos) < 0)
        return NULL;

    return g_list_reverse (repos);
}

/* Org inner public repos */

int
seaf_repo_manager_set_org_inner_pub_repo (SeafRepoManager *mgr,
                                          int org_id,
                                          const char *repo_id,
                                          const char *permission)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "REPLACE INTO OrgInnerPubRepo VALUES (%d, '%s', '%s')",
              org_id, repo_id, permission);
    return seaf_db_query (mgr->seaf->db, sql);
}

int
seaf_repo_manager_unset_org_inner_pub_repo (SeafRepoManager *mgr,
                                            int org_id,
                                            const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "DELETE FROM OrgInnerPubRepo WHERE org_id = %d AND repo_id = '%s'",
              org_id, repo_id);
    return seaf_db_query (mgr->seaf->db, sql);
}

gboolean
seaf_repo_manager_is_org_inner_pub_repo (SeafRepoManager *mgr,
                                         int org_id,
                                         const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "SELECT repo_id FROM OrgInnerPubRepo WHERE "
              "org_id = %d AND repo_id='%s'",
              org_id, repo_id);
    return seaf_db_check_for_existence (mgr->seaf->db, sql);
}

GList *
seaf_repo_manager_list_org_inner_pub_repos (SeafRepoManager *mgr,
                                            int org_id)
{
    GList *ret = NULL;
    char sql[256];

    snprintf (sql, 256,
              "SELECT OrgInnerPubRepo.repo_id, user, permission "
              "FROM OrgInnerPubRepo, OrgRepo "
              "WHERE OrgInnerPubRepo.org_id=%d AND "
              "OrgInnerPubRepo.repo_id=OrgRepo.repo_id AND "
              "OrgInnerPubRepo.org_id=OrgRepo.org_id",
              org_id);

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      collect_public_repos, &ret) < 0)
        return NULL;

    return g_list_reverse (ret);    
}

GList *
seaf_repo_manager_list_org_inner_pub_repos_by_owner (SeafRepoManager *mgr,
                                                     int org_id,
                                                     const char *user)
{
    GList *ret = NULL, *p;
    char sql[256];

    snprintf (sql, 256,
              "SELECT OrgInnerPubRepo.repo_id, user, permission "
              "FROM OrgInnerPubRepo, OrgRepo "
              "WHERE OrgInnerPubRepo.org_id=%d AND user='%s' AND "
              "OrgInnerPubRepo.repo_id=OrgRepo.repo_id AND "
              "OrgInnerPubRepo.org_id=OrgRepo.org_id",
              org_id, user);

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      collect_public_repos, &ret) < 0) {
        for (p = ret; p != NULL; p = p->next)
            g_object_unref (p->data);
        g_list_free (ret);
        return NULL;
    }

    return g_list_reverse (ret);    
}

char *
seaf_repo_manager_get_org_inner_pub_repo_perm (SeafRepoManager *mgr,
                                               int org_id,
                                               const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql),
              "SELECT permission FROM OrgInnerPubRepo WHERE "
              "org_id=%d AND repo_id='%s'",
              org_id, repo_id);
    return seaf_db_get_string(mgr->seaf->db, sql);
}

/*
 * Permission priority: owner --> personal share --> group share --> public.
 * Permission with higher priority overwrites those with lower priority.
 */
static char *
check_repo_share_permission (SeafRepoManager *mgr,
                             const char *repo_id,
                             const char *user_name)
{
    SearpcClient *rpc_client;
    GList *groups, *p1;
    GList *group_perms, *p2;
    CcnetGroup *group;
    GroupPerm *perm;
    int group_id;
    char *permission;

    permission = seaf_share_manager_check_permission (seaf->share_mgr,
                                                      repo_id,
                                                      user_name);
    if (permission != NULL)
        return permission;
    g_free (permission);

    rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                 NULL,
                                                 "ccnet-threaded-rpcserver");
    if (!rpc_client)
        return NULL;

    /* Get the groups this user belongs to. */
    groups = ccnet_get_groups_by_user (rpc_client, user_name);

    ccnet_rpc_client_free (rpc_client);

    /* Get the groups this repo shared to. */
    group_perms = seaf_repo_manager_get_group_perm_by_repo (mgr, repo_id, NULL);

    permission = NULL;
    /* Check if any one group overlaps. */
    for (p1 = groups; p1 != NULL; p1 = p1->next) {
        group = p1->data;
        g_object_get (group, "id", &group_id, NULL);

        for (p2 = group_perms; p2 != NULL; p2 = p2->next) {
            perm = p2->data;
            if (group_id == perm->group_id) {
                /* If the repo is shared to more than 1 groups,
                 * and user is in more than 1 of these groups,
                 * "rw" permission will overwrite "ro" permission.
                 */
                if (g_strcmp0(perm->permission, "rw") == 0) {
                    permission = perm->permission;
                    goto group_out;
                } else if (g_strcmp0(perm->permission, "r") == 0 &&
                           !permission) {
                    permission = perm->permission;
                }
            }
        }
    }

group_out:
    if (permission != NULL)
        permission = g_strdup(permission);

    for (p1 = groups; p1 != NULL; p1 = p1->next)
        g_object_unref ((GObject *)p1->data);
    g_list_free (groups);
    for (p2 = group_perms; p2 != NULL; p2 = p2->next)
        g_free (p2->data);
    g_list_free (group_perms);

    if (permission != NULL)
        return permission;

    if (!mgr->seaf->cloud_mode)
        return seaf_repo_manager_get_inner_pub_repo_perm (mgr, repo_id);

    return NULL;
}

static char *
check_org_repo_share_permission (SeafRepoManager *mgr,
                                 int org_id,
                                 const char *repo_id,
                                 const char *user_name)
{
    SearpcClient *rpc_client;
    GList *groups, *p1;
    GList *group_perms, *p2;
    CcnetGroup *group;
    GroupPerm *perm;
    int group_id;
    char *permission;

    rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                 NULL,
                                                 "ccnet-threaded-rpcserver");
    if (!rpc_client)
        return NULL;

    if (!ccnet_org_user_exists (rpc_client, org_id, user_name)) {
        ccnet_rpc_client_free (rpc_client);
        return NULL;
    }

    permission = seaf_share_manager_check_permission (seaf->share_mgr,
                                                      repo_id,
                                                      user_name);
    if (permission != NULL) {
        ccnet_rpc_client_free (rpc_client);
        return permission;
    }
    g_free (permission);

    /* Get the groups this user belongs to. */
    groups = ccnet_get_groups_by_user (rpc_client, user_name);

    ccnet_rpc_client_free (rpc_client);

    /* Get the groups this repo shared to. */
    group_perms = seaf_repo_manager_get_org_group_perm_by_repo (mgr,
                                                                org_id,
                                                                repo_id,
                                                                NULL);

    permission = NULL;
    /* Check if any one group overlaps. */
    for (p1 = groups; p1 != NULL; p1 = p1->next) {
        group = p1->data;
        g_object_get (group, "id", &group_id, NULL);

        for (p2 = group_perms; p2 != NULL; p2 = p2->next) {
            perm = p2->data;
            if (group_id == perm->group_id) {
                /* If the repo is shared to more than 1 groups,
                 * and user is in more than 1 of these groups,
                 * "rw" permission will overwrite "ro" permission.
                 */
                if (g_strcmp0(perm->permission, "rw") == 0) {
                    permission = perm->permission;
                    goto group_out;
                } else if (g_strcmp0(perm->permission, "r") == 0 &&
                           !permission) {
                    permission = perm->permission;
                }
            }
        }
    }

group_out:
    if (permission != NULL)
        permission = g_strdup(permission);

    for (p1 = groups; p1 != NULL; p1 = p1->next)
        g_object_unref ((GObject *)p1->data);
    g_list_free (groups);
    for (p2 = group_perms; p2 != NULL; p2 = p2->next)
        g_free (p2->data);
    g_list_free (group_perms);

    if (permission != NULL)
        return permission;

    return seaf_repo_manager_get_org_inner_pub_repo_perm (mgr, org_id, repo_id);
}

/*
 * Comprehensive repo access permission checker.
 *
 * Returns read/write permission.
 */
char *
seaf_repo_manager_check_permission (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *user,
                                    GError **error)
{
    char *owner = NULL;
    int org_id;
    char *permission = NULL;

    owner = seaf_repo_manager_get_repo_owner (mgr, repo_id);
    if (owner != NULL) {
        if (strcmp (owner, user) == 0)
            permission = g_strdup("rw");
        else
            permission = check_repo_share_permission (mgr, repo_id, user);
    } else if (mgr->seaf->cloud_mode) {
        /* Org repo. */
        owner = seaf_repo_manager_get_org_repo_owner (mgr, repo_id);
        if (!owner) {
            seaf_warning ("Failed to get owner of org repo %.10s.\n", repo_id);
            goto out;
        }

        org_id = seaf_repo_manager_get_repo_org (mgr, repo_id);
        if (org_id < 0) {
            seaf_warning ("Failed to get org of repo %.10s.\n", repo_id);
            goto out;
        }

        if (strcmp (owner, user) == 0)
            permission = g_strdup("rw");
        else
            permission = check_org_repo_share_permission (mgr, org_id,
                                                          repo_id, user);
    }

out:
    g_free (owner);
    return permission;
}

/*
 * Repo operations.
 */

static gint
compare_dirents (gconstpointer a, gconstpointer b)
{
    const SeafDirent *ent_a = a, *ent_b = b;

    return strcmp (ent_b->name, ent_a->name);
}

static inline SeafDirent *
dup_seaf_dirent (const SeafDirent *dent)
{
    return seaf_dirent_new (dent->id, dent->mode, dent->name);
}

static inline GList *
dup_seafdir_entries (const GList *entries)
{
    const GList *p;
    GList *newentries = NULL;
    SeafDirent *dent;
    
    for (p = entries; p; p = p->next) {
        dent = p->data;
        newentries = g_list_prepend (newentries, dup_seaf_dirent(dent));
    }

    return g_list_reverse(newentries);
}

/* We need to call this function recursively because every dirs in canon_path
 * need to be updated.
 */
static char *
post_file_recursive (const char *dir_id,
                     const char *to_path,
                     SeafDirent *newdent)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    char *slash;
    char *to_path_dup = NULL;
    char *remain = NULL;
    char *id = NULL;

    olddir = seaf_fs_manager_get_seafdir_sorted(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir.  new dir entry is added */
    if (*to_path == '\0') {
        GList *newentries;

        newentries = dup_seafdir_entries (olddir->entries);

        newentries = g_list_insert_sorted (newentries,
                                           dup_seaf_dirent(newdent),
                                           compare_dirents);

        newdir = seaf_dir_new (NULL, newentries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        id = g_strndup (newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free (newdir);

        goto out;
    }

    to_path_dup = g_strdup (to_path);
    slash = strchr (to_path_dup, '/');

    if (!slash) {
        remain = to_path_dup + strlen(to_path_dup);
    } else {
        *slash = '\0';
        remain = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strcmp(dent->name, to_path_dup) != 0)
            continue;

        id = post_file_recursive (dent->id, remain, newdent);
        if (id != NULL) {
            memcpy(dent->id, id, 40);
            dent->id[40] = '\0';
        }
        break;
    }
    
    if (id != NULL) {
        /* Create a new SeafDir. */
        GList *new_entries;
        
        new_entries = dup_seafdir_entries (olddir->entries);
        newdir = seaf_dir_new (NULL, new_entries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        
        g_free(id);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        
        seaf_dir_free (newdir);
    }

out:
    g_free (to_path_dup);
    seaf_dir_free(olddir);
    return id;
}

static char *
do_post_file (const char *root_id,
              const char *parent_dir,
              SeafDirent *dent)
{
    /* if parent_dir is a absolutely path, we will remove the first '/' */
    if (*parent_dir == '/')
        parent_dir = parent_dir + 1;

    return post_file_recursive(root_id, parent_dir, dent);
}

static char *
get_canonical_path (const char *path)
{
    char *ret = g_strdup (path);
    char *p;

    for (p = ret; *p != 0; ++p) {
        if (*p == '\\')
            *p = '/';
    }

    return ret;
}

/* Return TRUE if @filename already existing in @parent_dir. If exists, and
   @mode is not NULL, set its value to the mode of the dirent.
*/
static gboolean
check_file_exists (const char *root_id,
                   const char *parent_dir,
                   const char *filename,
                   int  *mode)
{
    SeafDir *dir;
    GList *p;
    SeafDirent *dent;
    int ret = FALSE;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr, root_id,
                                               parent_dir, NULL);
    if (!dir) {
        seaf_warning ("parent_dir %s doesn't exist.\n", parent_dir);
        return FALSE;
    }

    for (p = dir->entries; p != NULL; p = p->next) {
        dent = p->data;
        int r = strcmp (dent->name, filename);
        if (r == 0) {
            ret = TRUE;
            if (mode) {
                *mode = dent->mode;
            }
            break;
        }
    }

    seaf_dir_free (dir);

    return ret;
}

/**
  Various online file/directory operations:

  Put a file:
  1. find parent seafdir
  2. add a new dirent to parent seafdir
  2. recursively update all seafdir in the path, in a bottom-up manner
  3. commit it

  Del a file/dir:
  basically the same as put a file

  copy a file/dir:
  1. get src dirent from src repo
  2. duplicate src dirent with the new file name
  3. put the new dirent to dst repo and commit it.

  Move a file/dir:
  basically the same as a copy operation. Just one more step:
  4. remove src dirent from src repo and commit it

  Rename a file/dir:
  1. find parent seafdir
  2. update this seafdir with the old dirent replaced by a new dirent.
  3. recursively update all seafdir in the path
  
  NOTE:
  
  All operations which add a new dirent would check if a dirent with the same
  name already exists. If found, they would raise errors.

  All operations which remove a dirent would check if the dirent to be removed
  already exists. If not, they would do nothing and just return OK.

*/

#define GET_REPO_OR_FAIL(repo_var,repo_id)                              \
    do {                                                                \
        repo_var = seaf_repo_manager_get_repo (seaf->repo_mgr, (repo_id)); \
        if (!(repo_var)) {                                              \
            seaf_warning ("Repo %s doesn't exist.\n", (repo_id));       \
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo"); \
            ret = -1;                                                   \
            goto out;                                                   \
        }                                                               \
    } while (0);

#define GET_COMMIT_OR_FAIL(commit_var,commit_id)                        \
    do {                                                                \
        commit_var = seaf_commit_manager_get_commit(seaf->commit_mgr, (commit_id)); \
        if (!(commit_var)) {                                            \
            seaf_warning ("commit %s doesn't exist.\n", (commit_id));   \
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid commit"); \
            ret = -1;                                                   \
            goto out;                                                   \
        }                                                               \
    } while (0);

#define FAIL_IF_FILE_EXISTS(root_id,parent_dir,filename,mode)           \
    do {                                                                \
        if (check_file_exists ((root_id), (parent_dir), (filename), (mode))) { \
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,      \
                         "file already exists");                        \
            ret = -1;                                                   \
            goto out;                                                   \
        }                                                               \
    } while (0);

#define FAIL_IF_FILE_NOT_EXISTS(root_id,parent_dir,filename,mode)       \
    do {                                                                \
        if (!check_file_exists ((root_id), (parent_dir), (filename), (mode))) { \
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,      \
                         "file does not exist");                        \
            ret = -1;                                                   \
            goto out;                                                   \
        }                                                               \
    } while (0);

static int
gen_new_commit (const char *repo_id,
                SeafCommit *base,
                const char *new_root,
                const char *user,
                const char *desc,
                GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *new_commit = NULL, *current_head = NULL;
    int ret = 0;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Repo %s doesn't exist.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Invalid repo");
        ret = -1;
        goto out;
    }

    /* Create a new commit pointing to new_root. */
    new_commit = seaf_commit_new(NULL, repo->id, new_root,
                                 user, EMPTY_SHA1,
                                 desc, 0);
    new_commit->parent_id = g_strdup (base->commit_id);
    seaf_repo_to_commit (repo, new_commit);

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, new_commit) < 0) {
        seaf_warning ("Failed to add commit.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add commit");
        ret = -1;
        goto out;
    }

retry:
    current_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                   repo->head->commit_id);
    if (!current_head) {
        seaf_warning ("Failed to find head commit of %s.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Invalid repo");
        ret = -1;
        goto out;
    }

    /* Merge if base and head are not the same. */
    if (strcmp (base->commit_id, current_head->commit_id) != 0) {
        MergeOptions opt;
        const char *roots[3];
        SeafCommit *merged_commit;

        memset (&opt, 0, sizeof(opt));
        opt.n_ways = 3;
        memcpy (opt.remote_head, new_commit->commit_id, 40);
        opt.do_merge = TRUE;

        roots[0] = base->root_id; /* base */
        roots[1] = current_head->root_id; /* head */
        roots[2] = new_root;      /* remote */

        if (seaf_merge_trees (3, roots, &opt) < 0) {
            seaf_warning ("Failed to merge.\n");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Internal error");
            ret = -1;
            goto out;
        }

        merged_commit = seaf_commit_new(NULL, repo->id, opt.merged_tree_root,
                                        user, EMPTY_SHA1,
                                        "Auto merge by seafile system",
                                        0);

        merged_commit->parent_id = g_strdup (current_head->commit_id);
        merged_commit->second_parent_id = g_strdup (new_commit->commit_id);
        seaf_repo_to_commit (repo, merged_commit);

        if (seaf_commit_manager_add_commit (seaf->commit_mgr, merged_commit) < 0) {
            seaf_warning ("Failed to add commit.\n");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Failed to add commit");
            seaf_commit_unref (new_commit);
            return -1;
        }

        /* replace new_commit with merged_commit. */
        seaf_commit_unref (new_commit);
        new_commit = merged_commit;
    }

    seaf_branch_set_commit(repo->head, new_commit->commit_id);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   current_head->commit_id) < 0)
    {
        seaf_message ("Concurrent branch update, retry.\n");

        seaf_repo_unref (repo);
        repo = NULL;
        seaf_commit_unref (current_head);
        current_head = NULL;

        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!repo) {
            seaf_warning ("Repo %s doesn't exist.\n", repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Invalid repo");
            ret = -1;
            goto out;
        }

        goto retry;
    }

out:
    seaf_commit_unref (new_commit);
    seaf_commit_unref (current_head);
    seaf_repo_unref (repo);
    return ret;
}

static void
update_repo_size(const char *repo_id)
{
    if (seaf->monitor_id == NULL)
        return;

    SearpcClient *ccnet_rpc_client = NULL, *monitor_rpc_client = NULL;
    GError *error = NULL;

    if (strcmp(seaf->monitor_id, seaf->session->base.id) != 0) {
        ccnet_rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                           NULL,
                                                           "ccnet-rpcserver");
        if (!ccnet_rpc_client) {
            seaf_warning ("failed to create ccnet rpc client\n");
            goto out;
        }

        if (!ccnet_peer_is_ready (ccnet_rpc_client, seaf->monitor_id)) {
            goto out;
        }
    }

    monitor_rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                         NULL,
                                                         "monitor-rpcserver");
    if (!monitor_rpc_client) {
        seaf_warning ("failed to create monitor rpc client\n");
        goto out;
    }

    searpc_client_call__int (monitor_rpc_client, "compute_repo_size",
                             &error, 1, "string", repo_id);

    if (error) {
        seaf_warning ("error when compute_repo_size: %s", error->message);
        g_error_free (error);
    }

out:
    if (ccnet_rpc_client)
        ccnet_rpc_client_free (ccnet_rpc_client);
    if (monitor_rpc_client)
        ccnet_rpc_client_free (monitor_rpc_client);
}

int
seaf_repo_manager_post_file (SeafRepoManager *mgr,
                             const char *repo_id,
                             const char *temp_file_path,
                             const char *parent_dir,
                             const char *file_name,
                             const char *user,
                             GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    unsigned char sha1[20];
    char buf[PATH_MAX];
    char *root_id = NULL;
    SeafileCrypt *crypt = NULL;
    SeafDirent *new_dent = NULL;
    char hex[41];
    int ret = 0;

    if (access (temp_file_path, R_OK) != 0) {
        seaf_warning ("[post file] File %s doesn't exist or not readable.\n",
                      temp_file_path);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid input file");
        return -1;
    }

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit,repo->head->commit_id);

    if (!canon_path)
        canon_path = get_canonical_path (parent_dir);

    if (should_ignore (file_name, NULL)) {
        seaf_warning ("[post file] Invalid filename %s.\n", file_name);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid filename");
        ret = -1;
        goto out;
    }

    if (strstr (parent_dir, "//") != NULL) {
        seaf_warning ("[post file] parent_dir cantains // sequence.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid parent dir");
        ret = -1;
        goto out;
    }
    
    FAIL_IF_FILE_EXISTS(head_commit->root_id, canon_path, file_name, NULL);

    /* Write blocks. */
    if (repo->encrypted) {
        unsigned char key[16], iv[16];
        if (seaf_passwd_manager_get_decrypt_key_raw (seaf->passwd_mgr,
                                                     repo_id, user,
                                                     key, iv) < 0) {
            seaf_warning ("Passwd for repo %s is not set.\n", repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Passwd is not set");
            ret = -1;
            goto out;
        }
        crypt = seafile_crypt_new (repo->enc_version, key, iv);
    }

    if (seaf_fs_manager_index_blocks (seaf->fs_mgr, temp_file_path,
                                      sha1, crypt) < 0) {
        seaf_warning ("failed to index blocks");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to index blocks");
        ret = -1;
        goto out;
    }
        
    rawdata_to_hex(sha1, hex, 20);
    new_dent = seaf_dirent_new (hex, S_IFREG, file_name);

    root_id = do_post_file (head_commit->root_id, canon_path, new_dent);
    if (!root_id) {
        seaf_warning ("[post file] Failed to put file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to put file");
        ret = -1;
        goto out;
    }

    snprintf(buf, PATH_MAX, "Added \"%s\"", file_name);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_dent)
        g_free (new_dent);
    g_free (root_id);
    g_free (canon_path);
    g_free (crypt);

    if (ret == 0)
        update_repo_size(repo_id);

    return ret;
}

static gboolean
filename_exists (GList *entries, const char *filename)
{
    GList *ptr;
    SeafDirent *dent;

    for (ptr = entries; ptr != NULL; ptr = ptr->next) {
        dent = ptr->data;
        if (strcmp (dent->name, filename) == 0)
            return TRUE;
    }

    return FALSE;
}

static void
split_filename (const char *filename, char **name, char **ext)
{
    char *dot;

    dot = strrchr (filename, '.');
    if (dot) {
        *ext = g_strdup (dot + 1);
        *name = g_strndup (filename, dot - filename);
    } else {
        *name = g_strdup (filename);
        *ext = NULL;
    }
}

static int
add_new_entries (GList **entries, GList *filenames, GList *id_list)
{
    GList *ptr1, *ptr2;
    char *file, *id;

    for (ptr1 = filenames, ptr2 = id_list;
         ptr1 && ptr2;
         ptr1 = ptr1->next, ptr2 = ptr2->next)
    {
        file = ptr1->data;
        id = ptr2->data;

        int i = 1;
        char *name, *ext, *unique_name;
        SeafDirent *newdent;

        unique_name = g_strdup(file);
        split_filename (unique_name, &name, &ext);
        while (filename_exists (*entries, unique_name) && i <= 16) {
            g_free (unique_name);
            if (ext)
                unique_name = g_strdup_printf ("%s (%d).%s", name, i, ext);
            else
                unique_name = g_strdup_printf ("%s (%d)", name, i);
            i++;
        }

        if (i <= 16) {
            newdent = seaf_dirent_new (id, S_IFREG, unique_name);
            *entries = g_list_insert_sorted (*entries, newdent, compare_dirents);
        }

        g_free (name);
        g_free (ext);
        g_free (unique_name);

        if (i > 16)
            return -1;
    }

    return 0;
}

static char *
post_multi_files_recursive (const char *dir_id,
                            const char *to_path,
                            GList *filenames,
                            GList *id_list)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    char *slash;
    char *to_path_dup = NULL;
    char *remain = NULL;
    char *id = NULL;

    olddir = seaf_fs_manager_get_seafdir_sorted(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir.  new dir entry is added */
    if (*to_path == '\0') {
        GList *newentries;

        newentries = dup_seafdir_entries (olddir->entries);

        if (add_new_entries (&newentries, filenames, id_list) < 0)
            goto out;

        newdir = seaf_dir_new (NULL, newentries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        id = g_strndup (newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free (newdir);

        goto out;
    }

    to_path_dup = g_strdup (to_path);
    slash = strchr (to_path_dup, '/');

    if (!slash) {
        remain = to_path_dup + strlen(to_path_dup);
    } else {
        *slash = '\0';
        remain = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strcmp(dent->name, to_path_dup) != 0)
            continue;

        id = post_multi_files_recursive (dent->id, remain, filenames, id_list);
        if (id != NULL) {
            memcpy(dent->id, id, 40);
            dent->id[40] = '\0';
        }
        break;
    }
    
    if (id != NULL) {
        /* Create a new SeafDir. */
        GList *new_entries;
        
        new_entries = dup_seafdir_entries (olddir->entries);
        newdir = seaf_dir_new (NULL, new_entries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        
        g_free(id);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        
        seaf_dir_free (newdir);
    }

out:
    g_free (to_path_dup);
    seaf_dir_free(olddir);
    return id;
}

static char *
do_post_multi_files (const char *root_id,
                     const char *parent_dir,
                     GList *filenames,
                     GList *id_list)
{
    /* if parent_dir is a absolutely path, we will remove the first '/' */
    if (*parent_dir == '/')
        parent_dir = parent_dir + 1;

    return post_multi_files_recursive(root_id, parent_dir, filenames, id_list);
}

static void
convert_file_list (JsonArray *array, guint index, JsonNode *element, gpointer data)
{
    GList **files = data;

    *files = g_list_prepend (*files, json_node_dup_string (element));
}

static GList *
json_to_file_list (const char *files_json)
{
    JsonParser *parser = json_parser_new ();
    JsonNode *root;
    JsonArray *array;
    GList *files = NULL;
    GError *error = NULL;

    json_parser_load_from_data (parser, files_json, strlen(files_json), &error);
    if (error) {
        seaf_warning ("Failed to load file list from json.\n");
        g_error_free (error);
        return NULL;
    }

    root = json_parser_get_root (parser);
    array = json_node_get_array (root);

    json_array_foreach_element (array, convert_file_list, &files);

    g_object_unref (parser);
    return files;
}

int
seaf_repo_manager_post_multi_files (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *parent_dir,
                                    const char *filenames_json,
                                    const char *paths_json,
                                    const char *user,
                                    GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    GList *filenames = NULL, *paths = NULL, *id_list = NULL, *ptr;
    char *filename, *path;
    unsigned char sha1[20];
    GString *buf = g_string_new (NULL);
    char *root_id = NULL;
    SeafileCrypt *crypt = NULL;
    char hex[41];
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit,repo->head->commit_id);

    canon_path = get_canonical_path (parent_dir);

    /* Decode file name and tmp file paths from json. */
    filenames = json_to_file_list (filenames_json);
    paths = json_to_file_list (paths_json);
    if (!filenames || !paths) {
        seaf_warning ("[post files] Invalid filenames or paths.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid files");
        ret = -1;
        goto out;
    }

    /* Check inputs. */
    for (ptr = filenames; ptr; ptr = ptr->next) {
        filename = ptr->data;
        if (should_ignore (filename, NULL)) {
            seaf_warning ("[post files] Invalid filename %s.\n", filename);
            g_set_error (error, SEAFILE_DOMAIN, POST_FILE_ERR_FILENAME,
                         "%s", filename);
            ret = -1;
            goto out;
        }
    }

    if (strstr (parent_dir, "//") != NULL) {
        seaf_warning ("[post file] parent_dir cantains // sequence.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid parent dir");
        ret = -1;
        goto out;
    }

    /* Index tmp files and get file id list. */
    if (repo->encrypted) {
        unsigned char key[16], iv[16];
        if (seaf_passwd_manager_get_decrypt_key_raw (seaf->passwd_mgr,
                                                     repo_id, user,
                                                     key, iv) < 0) {
            seaf_warning ("Passwd for repo %s is not set.\n", repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Passwd is not set");
            ret = -1;
            goto out;
        }
        crypt = seafile_crypt_new (repo->enc_version, key, iv);
    }

    for (ptr = paths; ptr; ptr = ptr->next) {
        path = ptr->data;
        if (seaf_fs_manager_index_blocks (seaf->fs_mgr, path, sha1, crypt) < 0) {
            seaf_warning ("failed to index blocks");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Failed to index blocks");
            ret = -1;
            goto out;
        }

        rawdata_to_hex(sha1, hex, 20);
        id_list = g_list_prepend (id_list, g_strdup(hex));
    }
    id_list = g_list_reverse (id_list);

    /* Add the files to parent dir and commit. */
    root_id = do_post_multi_files (head_commit->root_id, canon_path,
                                   filenames, id_list);
    if (!root_id) {
        seaf_warning ("[post file] Failed to put file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Failed to put file");
        ret = -1;
        goto out;
    }

    guint len = g_list_length (filenames);
    if (len > 1)
        g_string_printf (buf, "Added \"%s\" and %u more files.",
                         (char *)(filenames->data), len - 1);
    else
        g_string_printf (buf, "Added \"%s\".", (char *)(filenames->data));

    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf->str, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    string_list_free (filenames);
    string_list_free (paths);
    string_list_free (id_list);
    g_string_free (buf, TRUE);
    g_free (root_id);
    g_free (canon_path);
    g_free (crypt);

    if (ret == 0)
        update_repo_size(repo_id);

    return ret;
}

static char *
del_file_recursive(const char *dir_id,
                   const char *to_path,
                   const char *filename)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    char *to_path_dup = NULL;
    char *remain = NULL;
    char *slash;
    char *id = NULL;

    olddir = seaf_fs_manager_get_seafdir_sorted(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir. Remove the given entry from it. */
    if (*to_path == '\0') {
        SeafDirent *old, *new;
        GList *newentries = NULL, *p;

        for (p = olddir->entries; p != NULL; p = p->next) {
            old = p->data;
            if (strcmp(old->name, filename) != 0) {
                new = seaf_dirent_new (old->id, old->mode, old->name);
                newentries = g_list_prepend (newentries, new);
            }
        }

        newentries = g_list_reverse (newentries);

        newdir = seaf_dir_new(NULL, newentries, 0);
        seaf_dir_save(seaf->fs_mgr, newdir);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free(newdir);

        goto out;
    }

    to_path_dup = g_strdup (to_path);
    slash = strchr (to_path_dup, '/');

    if (!slash) {
        remain = to_path_dup + strlen(to_path_dup);
    } else {
        *slash = '\0';
        remain = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strcmp(dent->name, to_path_dup) != 0)
            continue;

        id = del_file_recursive(dent->id, remain, filename);
        if (id != NULL) {
            memcpy(dent->id, id, 40);
            dent->id[40] = '\0';
        }
        break;
    }
    if (id != NULL) {
        /* Create a new SeafDir. */
        GList *new_entries;
        
        new_entries = dup_seafdir_entries (olddir->entries);
        newdir = seaf_dir_new (NULL, new_entries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        
        g_free(id);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        
        seaf_dir_free (newdir);
    }

out:
    g_free (to_path_dup);
    seaf_dir_free(olddir);
    return id;
}

static char *
do_del_file(const char *root_id,
            const char *parent_dir,
            const char *file_name)
{
    /* if parent_dir is a absolutely path, we will remove the first '/' */
    if (*parent_dir == '/')
        parent_dir = parent_dir + 1;

    return del_file_recursive(root_id, parent_dir, file_name);
}

int
seaf_repo_manager_del_file (SeafRepoManager *mgr,
                            const char *repo_id,
                            const char *parent_dir,
                            const char *file_name,
                            const char *user,
                            GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    char buf[PATH_MAX];
    char *root_id = NULL;
    int mode = 0;
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    if (!canon_path)
        canon_path = get_canonical_path (parent_dir);
    
    if (!check_file_exists(head_commit->root_id, canon_path, file_name, &mode)) {
        seaf_warning ("[del file] target file %s/%s does not exist, skip\n",
                      canon_path, file_name);
        goto out;
    }

    root_id = do_del_file (head_commit->root_id, canon_path, file_name);
    if (!root_id) {
        seaf_warning ("[del file] Failed to del file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to del file");
        ret = -1;
        goto out;
    }

    /* Commit. */
    if (S_ISDIR(mode)) {
        snprintf(buf, PATH_MAX, "Removed directory \"%s\"", file_name);
    } else {
        snprintf(buf, PATH_MAX, "Deleted \"%s\"", file_name);
    }

    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    g_free (root_id);
    g_free (canon_path);

    return ret;
}

static SeafDirent *
get_dirent_by_path (SeafRepo *repo,
                    const char *path,
                    const char *file_name,
                    GError **error)
{
    SeafCommit *head_commit = NULL; 
    SeafDirent *dent = NULL;
    SeafDir *dir = NULL;
    
    head_commit = seaf_commit_manager_get_commit(seaf->commit_mgr,
                                                 repo->head->commit_id);
    if (!head_commit) {
        seaf_warning ("commit %s doesn't exist.\n", repo->head->commit_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid commit");
        goto out;
    }

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr, head_commit->root_id,
                                              path, NULL);
    if (!dir) {
        seaf_warning ("dir %s doesn't exist in repo %s.\n", path, repo->id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid dir");
        goto out;
    }

    GList *p;
    for (p = dir->entries; p; p = p->next) {
        SeafDirent *d = p->data;
        int r = strcmp (d->name, file_name);
        if (r == 0) {
            dent = seaf_dirent_new (d->id, d->mode, d->name);
            break;
        }
    }

    if (!dent && error && !(*error)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "failed to get dirent");
    }

out:
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (dir)
        seaf_dir_free (dir);

    return dent;
}

static int
put_dirent_and_commit (const char *repo_id,
                       const char *path,
                       SeafDirent *dent,
                       const char *user,
                       GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *root_id = NULL;
    char buf[PATH_MAX];
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    root_id = do_post_file (head_commit->root_id, path, dent);
    if (!root_id) {
        seaf_warning ("[cp file] Failed to cp file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to cp file");
        ret = -1;
        goto out;
    }

    /* Commit. */
    if (S_ISDIR(dent->mode)) {
        snprintf(buf, sizeof(buf), "Added directory \"%s\"", dent->name);
    } else {
        snprintf(buf, sizeof(buf), "Added \"%s\"", dent->name);
    }

    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (root_id)
        g_free (root_id);
    
    return ret;
}

/**
 * Copy a SeafDirent from a SeafDir to another.
 * 
 * 1. When @src_repo and @dst_repo are not the same repo, neither of them
 *    should be encrypted.
 * 
 * 2. the file being copied must not exist in the dst path of the dst repo.
 */
int
seaf_repo_manager_copy_file (SeafRepoManager *mgr,
                             const char *src_repo_id,
                             const char *src_path,
                             const char *src_filename,
                             const char *dst_repo_id,
                             const char *dst_path,
                             const char *dst_filename,
                             const char *user,
                             GError **error)
{
    SeafRepo *src_repo = NULL, *dst_repo = NULL;
    SeafDirent *src_dent = NULL, *dst_dent = NULL;
    char *src_canon_path = NULL, *dst_canon_path = NULL;
    SeafCommit *dst_head_commit = NULL;
    int ret = 0;

    GET_REPO_OR_FAIL(src_repo, src_repo_id);

    if (strcmp(src_repo_id, dst_repo_id) != 0) {
        GET_REPO_OR_FAIL(dst_repo, dst_repo_id);

        if (src_repo->encrypted || dst_repo->encrypted) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Can't copy files between encrypted repo(s)");
            ret = -1;
            goto out;
        }
        
    } else {
        seaf_repo_ref (src_repo);
        dst_repo = src_repo;
    }
    
    src_canon_path = get_canonical_path (src_path);
    dst_canon_path = get_canonical_path (dst_path);

    /* first check whether a file with file_name already exists in destination dir */
    GET_COMMIT_OR_FAIL(dst_head_commit, dst_repo->head->commit_id);
    
    FAIL_IF_FILE_EXISTS(dst_head_commit->root_id, dst_canon_path, dst_filename, NULL);
    
    /* get src dirent */
    src_dent = get_dirent_by_path (src_repo, src_canon_path, src_filename, error);
    if (!src_dent) {
        ret = -1;
        goto out;
    }

    /* duplicate src dirent with new name */
    dst_dent = seaf_dirent_new (src_dent->id, src_dent->mode, dst_filename);

    if (put_dirent_and_commit (dst_repo_id,
                               dst_canon_path,
                               dst_dent,
                               user,
                               error) < 0) {
        if (!error)
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "failed to put dirent");
            ret = -1;
            goto out;
    }
    
out:
    if (src_repo)
        seaf_repo_unref (src_repo);
    if (dst_repo)
        seaf_repo_unref (dst_repo);
    if (dst_head_commit)
        seaf_commit_unref(dst_head_commit);
    if (src_canon_path)
        g_free (src_canon_path);
    if (dst_canon_path)
        g_free (dst_canon_path);
    if (src_dent)
        g_free(src_dent);
    if (dst_dent)
        g_free(dst_dent);

    if (ret == 0) {
        update_repo_size (dst_repo_id);
    }

    return ret;
}

static int
move_file_same_repo (const char *repo_id,
                     const char *src_path, SeafDirent *src_dent,
                     const char *dst_path, SeafDirent *dst_dent,
                     const char *user,
                     GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *root_id_after_put = NULL, *root_id = NULL;
    char buf[PATH_MAX];
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);
    
    root_id_after_put = do_post_file (head_commit->root_id, dst_path, dst_dent);
    if (!root_id_after_put) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "move file failed");
        ret = -1;
        goto out;
    }

    root_id = do_del_file (root_id_after_put, src_path, src_dent->name);
    if (!root_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "move file failed");
        ret = -1;
        goto out;
    }

    /* Commit. */
    if (S_ISDIR(src_dent->mode)) {
        snprintf(buf, PATH_MAX, "Moved directory \"%s\"", src_dent->name);
    } else {
        snprintf(buf, PATH_MAX, "Moved \"%s\"", src_dent->name);
    }

    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;
    
out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    g_free (root_id_after_put);
    g_free (root_id);
    
    return ret;
}
                     
int
seaf_repo_manager_move_file (SeafRepoManager *mgr,
                             const char *src_repo_id,
                             const char *src_path,
                             const char *src_filename,
                             const char *dst_repo_id,
                             const char *dst_path,
                             const char *dst_filename,
                             const char *user,
                             GError **error)
{
    SeafRepo *src_repo = NULL, *dst_repo = NULL;
    SeafDirent *src_dent = NULL, *dst_dent = NULL;
    char *src_canon_path = NULL, *dst_canon_path = NULL;
    SeafCommit *dst_head_commit = NULL;
    int ret = 0;

    GET_REPO_OR_FAIL(src_repo, src_repo_id);

    if (strcmp(src_repo_id, dst_repo_id) != 0) {
        GET_REPO_OR_FAIL(dst_repo, dst_repo_id);

        if (src_repo->encrypted || dst_repo->encrypted) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Can't copy files between encrypted repo(s)");
            ret = -1;
            goto out;
        }
        
    } else {
        seaf_repo_ref (src_repo);
        dst_repo = src_repo;
    }
    
    src_canon_path = get_canonical_path (src_path);
    dst_canon_path = get_canonical_path (dst_path);
    /* first check whether a file with file_name already exists in destination dir */
    GET_COMMIT_OR_FAIL(dst_head_commit, dst_repo->head->commit_id);
    FAIL_IF_FILE_EXISTS(dst_head_commit->root_id, dst_canon_path, dst_filename, NULL);

    /* get src dirent */
    src_dent = get_dirent_by_path (src_repo, src_canon_path, src_filename, error);
    if (!src_dent) {
        ret = -1;
        goto out;
    }

    /* duplicate src dirent with new name */
    dst_dent = seaf_dirent_new (src_dent->id, src_dent->mode, dst_filename);

    if (src_repo == dst_repo) {
        /* move file within the same repo */
        if (move_file_same_repo (src_repo_id,
                                 src_canon_path, src_dent,
                                 dst_canon_path, dst_dent,
                                 user, error) < 0) {
            ret = -1;
            goto out;
        }
        
    } else {
        /* move between different repos */

        /* add this dirent to dst repo */
        if (put_dirent_and_commit (dst_repo_id,
                                   dst_canon_path,
                                   dst_dent,
                                   user,
                                   error) < 0) {
            if (!error)
                g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                             "failed to put dirent");
            ret = -1;
            goto out;
        }

        if (seaf_repo_manager_del_file (mgr, src_repo_id, src_path,
                                        src_filename, user, error) < 0) {
            ret = -1;
            goto out;
        }
    }

out:
    if (src_repo) seaf_repo_unref (src_repo);
    if (dst_repo) seaf_repo_unref (dst_repo);

    if (dst_head_commit) seaf_commit_unref(dst_head_commit);
    
    if (src_canon_path) g_free (src_canon_path);
    if (dst_canon_path) g_free (dst_canon_path);
    
    if (src_dent) g_free(src_dent);
    if (dst_dent) g_free(dst_dent);

    if (ret == 0) {
        update_repo_size (dst_repo_id);
    }

    return ret;
}

int
seaf_repo_manager_post_dir (SeafRepoManager *mgr,
                            const char *repo_id,
                            const char *parent_dir,
                            const char *new_dir_name,
                            const char *user,
                            GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    char buf[PATH_MAX];
    char *root_id = NULL;
    SeafDirent *new_dent = NULL;
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    canon_path = get_canonical_path (parent_dir);

    FAIL_IF_FILE_EXISTS(head_commit->root_id, canon_path, new_dir_name, NULL);

    if (!new_dent) {
        new_dent = seaf_dirent_new (EMPTY_SHA1, S_IFDIR, new_dir_name);
    }

    root_id = do_post_file (head_commit->root_id, canon_path, new_dent);
    if (!root_id) {
        seaf_warning ("[put dir] Failed to put dir.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to put dir");
        ret = -1;
        goto out;
    }

    /* Commit. */
    snprintf(buf, PATH_MAX, "Added directory \"%s\"", new_dir_name);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_dent)
        g_free (new_dent);
    g_free (root_id);
    g_free (canon_path);

    return ret;
}

int
seaf_repo_manager_post_empty_file (SeafRepoManager *mgr,
                                   const char *repo_id,
                                   const char *parent_dir,
                                   const char *new_file_name,
                                   const char *user,
                                   GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    char buf[PATH_MAX];
    char *root_id = NULL;
    SeafDirent *new_dent = NULL;
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    if (!canon_path)
        /* no need to call get_canonical_path again when retry */
        canon_path = get_canonical_path (parent_dir);

    FAIL_IF_FILE_EXISTS(head_commit->root_id, canon_path, new_file_name, NULL);

    if (!new_dent) {
        new_dent = seaf_dirent_new (EMPTY_SHA1, S_IFREG, new_file_name);
    }

    root_id = do_post_file (head_commit->root_id, canon_path, new_dent);
    if (!root_id) {
        seaf_warning ("[put dir] Failed to create empty file dir.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to put dir");
        ret = -1;
        goto out;
    }

    /* Commit. */
    snprintf(buf, PATH_MAX, "Added \"%s\"", new_file_name);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_dent)
        g_free (new_dent);
    g_free (root_id);
    g_free (canon_path);

    return ret;
}

static char *
rename_file_recursive(const char *dir_id,
                      const char *to_path,
                      const char *oldname,
                      const char *newname)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    char *to_path_dup = NULL;
    char *remain = NULL;
    char *slash;
    char *id = NULL;

    olddir = seaf_fs_manager_get_seafdir_sorted(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir. */
    if (*to_path == '\0') {
        SeafDirent *old, *newdent = NULL;
        GList *newentries = NULL, *p;

        /* When renameing, there is a pitfall: we can't simply rename the
         * dirent, since the dirents are required to be sorted in descending
         * order. We need to copy all old dirents except the target dirent,
         * and then rename the target dirent, and then insert the new
         * dirent, so that we can maintain the descending order of dirents. */
        for (p = olddir->entries; p != NULL; p = p->next) {
            old = p->data;
            if (strcmp(old->name, oldname) != 0) {
                newentries = g_list_prepend (newentries, dup_seaf_dirent(old));
            } else {
                newdent = seaf_dirent_new (old->id, old->mode, newname);
            }
        }

        newentries = g_list_reverse (newentries);

        if (newdent) {
            newentries = g_list_insert_sorted(newentries, newdent, compare_dirents);
        }

        newdir = seaf_dir_new (NULL, newentries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        id = g_strndup (newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free (newdir);

        goto out;
    }

    to_path_dup = g_strdup (to_path);
    slash = strchr (to_path_dup, '/');

    if (!slash) {
        remain = to_path_dup + strlen(to_path_dup);
    } else {
        *slash = '\0';
        remain = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strcmp(dent->name, to_path_dup) != 0)
            continue;

        id = rename_file_recursive (dent->id, remain, oldname, newname);
        if (id != NULL) {
            memcpy(dent->id, id, 40);
            dent->id[40] = '\0';
        }
        break;
    }
    
    if (id != NULL) {
        /* Create a new SeafDir. */
        GList *new_entries;
        
        new_entries = dup_seafdir_entries (olddir->entries);
        newdir = seaf_dir_new (NULL, new_entries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        
        g_free(id);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        
        seaf_dir_free (newdir);
    }

out:
    g_free (to_path_dup);
    seaf_dir_free(olddir);
    return id;
}

static char *
do_rename_file(const char *root_id,
               const char *parent_dir,
               const char *oldname,
               const char *newname)
{
    /* if parent_dir is a absolutely path, we will remove the first '/' */
    if (*parent_dir == '/')
        parent_dir = parent_dir + 1;

    return rename_file_recursive(root_id, parent_dir, oldname, newname);
}


int
seaf_repo_manager_rename_file (SeafRepoManager *mgr,
                               const char *repo_id,
                               const char *parent_dir,
                               const char *oldname,
                               const char *newname,
                               const char *user,
                               GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *root_id = NULL;
    char *canon_path = NULL;
    char buf[PATH_MAX];
    int mode = 0;
    int ret = 0;

    if (strcmp(oldname, newname) == 0)
        return 0;
    
    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);
    
    if (!canon_path)
        canon_path = get_canonical_path (parent_dir);

    FAIL_IF_FILE_NOT_EXISTS(head_commit->root_id, canon_path, oldname, &mode);
    FAIL_IF_FILE_EXISTS(head_commit->root_id, canon_path, newname, NULL);

    root_id = do_rename_file (head_commit->root_id, canon_path,
                              oldname, newname);
    if (!root_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "faile to rename file %s", oldname);
        ret = -1;
        goto out;
    }

    /* Commit. */
    if (S_ISDIR(mode)) {
        snprintf(buf, PATH_MAX, "Renamed directory \"%s\"", oldname);
    } else {
        snprintf(buf, PATH_MAX, "Renamed \"%s\"", oldname);
    }

    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    g_free (canon_path);
    g_free (root_id);

    return ret;
}

int
seaf_repo_manager_is_valid_filename (SeafRepoManager *mgr,
                                     const char *repo_id,
                                     const char *filename,
                                     GError **error)
{
    if (should_ignore(filename, NULL))
        return 0;
    else
        return 1;
}

void
seaf_repo_generate_magic (SeafRepo *repo, const char *passwd)
{
    GString *buf = g_string_new (NULL);
    unsigned char key[16], iv[16];

    /* Compute a "magic" string from repo_id and passwd.
     * This is used to verify the password given by user before decrypting
     * data.
     * We use large iteration times to defense against brute-force attack.
     */
    g_string_append_printf (buf, "%s%s", repo->id, passwd);

    seafile_generate_enc_key (buf->str, buf->len, CURRENT_ENC_VERSION, key, iv);

    g_string_free (buf, TRUE);
    rawdata_to_hex (key, repo->magic, 16);
}

static char *
create_repo_common (SeafRepoManager *mgr,
                    const char *repo_name,
                    const char *repo_desc,
                    const char *user,
                    const char *passwd,
                    GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;
    SeafBranch *master = NULL;
    char *repo_id = NULL;
    char *ret = NULL;

    repo_id = gen_uuid ();
    repo = seaf_repo_new (repo_id, repo_name, repo_desc);
    g_free (repo_id);

    repo->no_local_history = TRUE;
    if (passwd != NULL && passwd[0] != '\0') {
        repo->encrypted = TRUE;
        repo->enc_version = CURRENT_ENC_VERSION;
        seaf_repo_generate_magic (repo, passwd);
    }

    commit = seaf_commit_new (NULL, repo->id,
                              EMPTY_SHA1, /* root id */
                              user, /* creator */
                              EMPTY_SHA1, /* creator id */
                              repo_desc,  /* description */
                              0);         /* ctime */

    seaf_repo_to_commit (repo, commit);
    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0) {
        seaf_warning ("Failed to add commit.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add commit");
        goto out;
    }

    master = seaf_branch_new ("master", repo->id, commit->commit_id);
    if (seaf_branch_manager_add_branch (seaf->branch_mgr, master) < 0) {
        seaf_warning ("Failed to add branch.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add branch");
        goto out;
    }

    if (seaf_repo_set_head (repo, master, commit) < 0) {
        seaf_warning ("Failed to set repo head.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to set repo head.");
        goto out;
    }

    if (seaf_repo_manager_add_repo (mgr, repo) < 0) {
        seaf_warning ("Failed to add repo.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add repo.");
        goto out;
    }

    ret = g_strdup(repo->id);
out:
    if (repo)
        seaf_repo_unref (repo);
    if (commit)
        seaf_commit_unref (commit);
    if (master)
        seaf_branch_unref (master);
    
    return ret;    
}

char *
seaf_repo_manager_create_new_repo (SeafRepoManager *mgr,
                                   const char *repo_name,
                                   const char *repo_desc,
                                   const char *owner_email,
                                   const char *passwd,
                                   GError **error)
{
    char *repo_id = NULL;

    repo_id = create_repo_common (mgr, repo_name, repo_desc, owner_email,
                                  passwd, error);

    if (seaf_repo_manager_set_repo_owner (mgr, repo_id, owner_email) < 0) {
        seaf_warning ("Failed to set repo owner.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to set repo owner.");
        goto out;
    }

    return repo_id;
    
out:
    if (repo_id)
        g_free (repo_id);
    return NULL;
}

char *
seaf_repo_manager_create_org_repo (SeafRepoManager *mgr,
                                   const char *repo_name,
                                   const char *repo_desc,
                                   const char *user,
                                   const char *passwd,
                                   int org_id,
                                   GError **error)
{
    char *repo_id = NULL;

    repo_id = create_repo_common (mgr, repo_name, repo_desc, user, passwd,
                                  error);

    if (seaf_repo_manager_set_org_repo (mgr, org_id, repo_id, user) < 0) {
        seaf_warning ("Failed to set org repo.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to set org repo.");
        goto out;
    }

    return repo_id;

out:
    if (repo_id)
        g_free (repo_id);
    return NULL;
}

static char *
put_file_recursive(const char *dir_id,
                   const char *to_path,
                   SeafDirent *newdent)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    char *to_path_dup = NULL;
    char *remain = NULL;
    char *slash;
    char *id = NULL;

    olddir = seaf_fs_manager_get_seafdir_sorted(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir. Update the target dirent. */
    if (*to_path == '\0') {
        GList *newentries = NULL, *p;
        SeafDirent *dent;

        for (p = olddir->entries; p; p = p->next) {
            dent = p->data;
            if (strcmp(dent->name, newdent->name) == 0) {
                newentries = g_list_prepend (newentries, dup_seaf_dirent(newdent));
            } else {
                newentries = g_list_prepend (newentries, dup_seaf_dirent(dent));
            }
        }

        newentries = g_list_reverse (newentries);
        newdir = seaf_dir_new (NULL, newentries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        id = g_strndup (newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free (newdir);

        goto out;
    }

    to_path_dup = g_strdup (to_path);
    slash = strchr (to_path_dup, '/');

    if (!slash) {
        remain = to_path_dup + strlen(to_path_dup);
    } else {
        *slash = '\0';
        remain = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strcmp(dent->name, to_path_dup) != 0)
            continue;

        id = put_file_recursive (dent->id, remain, newdent);
        if (id != NULL) {
            memcpy(dent->id, id, 40);
            dent->id[40] = '\0';
        }
        break;
    }
    
    if (id != NULL) {
        /* Create a new SeafDir. */
        GList *new_entries;
        
        new_entries = dup_seafdir_entries (olddir->entries);
        newdir = seaf_dir_new (NULL, new_entries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        
        g_free(id);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        
        seaf_dir_free (newdir);
    }

out:
    g_free (to_path_dup);
    seaf_dir_free(olddir);
    return id;
}

static char *
do_put_file (const char *root_id,
             const char *parent_dir,
             SeafDirent *dent)
{
    /* if parent_dir is a absolutely path, we will remove the first '/' */
    if (*parent_dir == '/')
        parent_dir = parent_dir + 1;

    return put_file_recursive(root_id, parent_dir, dent);
}

int
seaf_repo_manager_put_file (SeafRepoManager *mgr,
                            const char *repo_id,
                            const char *temp_file_path,
                            const char *parent_dir,
                            const char *file_name,
                            const char *user,
                            GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    unsigned char sha1[20];
    char buf[PATH_MAX];
    char *root_id = NULL;
    SeafileCrypt *crypt = NULL;
    SeafDirent *new_dent = NULL;
    char hex[41];
    char *old_file_id = NULL, *fullpath = NULL;
    int ret = 0;

    if (access (temp_file_path, R_OK) != 0) {
        seaf_warning ("[put file] File %s doesn't exist or not readable.\n",
                      temp_file_path);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid input file");
        return -1;
    }

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    if (!canon_path)
        canon_path = get_canonical_path (parent_dir);

    if (should_ignore (file_name, NULL)) {
        seaf_warning ("[put file] Invalid filename %s.\n", file_name);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid filename");
        ret = -1;
        goto out;
    }

    if (strstr (parent_dir, "//") != NULL) {
        seaf_warning ("[put file] parent_dir cantains // sequence.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid parent dir");
        ret = -1;
        goto out;
    }
    
    FAIL_IF_FILE_NOT_EXISTS(head_commit->root_id, canon_path, file_name, NULL);

    /* Write blocks. */
    if (repo->encrypted) {
        unsigned char key[16], iv[16];
        if (seaf_passwd_manager_get_decrypt_key_raw (seaf->passwd_mgr,
                                                     repo_id, user,
                                                     key, iv) < 0) {
            seaf_warning ("Passwd for repo %s is not set.\n", repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Passwd is not set");
            ret = -1;
            goto out;
        }
        crypt = seafile_crypt_new (repo->enc_version, key, iv);
    }

    if (seaf_fs_manager_index_blocks (seaf->fs_mgr, temp_file_path,
                                      sha1, crypt) < 0) {
        seaf_warning ("failed to index blocks");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to index blocks");
        ret = -1;
        goto out;
    }
        
    rawdata_to_hex(sha1, hex, 20);
    new_dent = seaf_dirent_new (hex, S_IFREG, file_name);

    if (!fullpath)
        fullpath = g_build_filename(parent_dir, file_name, NULL);

    old_file_id = seaf_fs_manager_path_to_obj_id (seaf->fs_mgr,
                                                   head_commit->root_id,
                                                   fullpath, NULL, NULL);

    if (g_strcmp0(old_file_id, new_dent->id) == 0) {
        ret = 0;
        goto out;
    }

    root_id = do_put_file (head_commit->root_id, canon_path, new_dent);
    if (!root_id) {
        seaf_warning ("[put file] Failed to put file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to put file");
        ret = -1;
        goto out;
    }

    /* Commit. */
    snprintf(buf, PATH_MAX, "Modified \"%s\"", file_name);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_dent)
        g_free (new_dent);
    g_free (root_id);
    g_free (canon_path);
    g_free (crypt);
    g_free (old_file_id);
    g_free (fullpath);

    if (ret == 0) {
        update_repo_size (repo_id);
    }

    return ret;
}

/* split filename into base and extension */
static void
filename_splitext (const char *filename,
                   char **base,
                   char **ext)
{
    char *dot = strrchr(filename, '.');
    if (!dot) {
        *base = g_strdup(filename);
        *ext = NULL;
    } else {
        *dot = '\0';
        *base = g_strdup(filename);
        *dot = '.';

        *ext = g_strdup(dot);
    }
}

static char *
revert_file_to_root (const char *root_id,
                     const char *filename,
                     const char *file_id,
                     gboolean *skipped,
                     GError **error)
{
    SeafDir *dir = NULL;
    SeafDirent *dent = NULL, *newdent = NULL;
    char *basename = NULL, *ext = NULL;
    char new_file_name[PATH_MAX];
    char *new_root_id = NULL;
    int i = 1;
    GList *p;

    *skipped = FALSE;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                               root_id,
                                               "/", error);
    if (*error) {
        return NULL;
    }

    snprintf (new_file_name, sizeof(new_file_name), "%s", filename);

    filename_splitext(filename, &basename, &ext);
    for (;;) {
        for (p = dir->entries; p; p = p->next) {
            dent = p->data;
            if (strcmp(dent->name, new_file_name) != 0)
                continue;

            if (S_ISREG(dent->mode)) {
                /* same named file */
                if (strcmp(dent->id, file_id) == 0) {
                    *skipped = TRUE;
                    goto out;
                } else {
                    /* rename and retry */
                    snprintf (new_file_name, sizeof(new_file_name), "%s (%d)%s",
                              basename, i++, ext);
                    break;
                }
                
            } else if (S_ISDIR(dent->mode)) {
                /* rename and retry */
                snprintf (new_file_name, sizeof(new_file_name), "%s (%d)%s",
                          basename, i++, ext);
                break;
            }
        }

        if (p == NULL)
            break;
    }

    newdent = seaf_dirent_new (file_id, S_IFREG, new_file_name);
    new_root_id = do_post_file (root_id, "/", newdent);

out:
    if (dir)
        seaf_dir_free (dir);

    g_free (basename);
    g_free (ext);
    g_free (newdent);

    return new_root_id;
}

static char *
revert_file_to_parent_dir (const char *root_id,
                           const char *parent_dir,
                           const char *filename,
                           const char *file_id,
                           gboolean *skipped,
                           GError **error)
{
    SeafDir *dir = NULL;
    SeafDirent *dent = NULL, *newdent = NULL;
    char *basename = NULL, *ext = NULL;
    char new_file_name[PATH_MAX];
    char *new_root_id = NULL;
    gboolean is_overwrite = FALSE;
    int i = 1;
    GList *p;
    
    *skipped = FALSE;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                               root_id,
                                               parent_dir, error);
    if (*error) {
        return NULL;
    }

    snprintf (new_file_name, sizeof(new_file_name), "%s", filename);
    filename_splitext(filename, &basename, &ext);
    while(TRUE) {
        for (p = dir->entries; p; p = p->next) {
            dent = p->data;
            if (strcmp(dent->name, new_file_name) != 0)
                continue;

            if (S_ISREG(dent->mode)) {
                /* same named file */
                if (strcmp(dent->id, file_id) == 0) {
                    *skipped = TRUE;
                    goto out;
                } else {
                    /* same name, different id: just overwrite */
                    is_overwrite = TRUE;
                    goto do_revert;
                }
                
            } else if (S_ISDIR(dent->mode)) {
                /* rename and retry */
                snprintf (new_file_name, sizeof(new_file_name), "%s (%d)%s",
                          basename, i++, ext);
                break;
            }
        }

        if (p == NULL)
            break;
    }

do_revert:    
    newdent = seaf_dirent_new (file_id, S_IFREG, new_file_name);
    if (is_overwrite) {
        new_root_id = do_put_file (root_id, parent_dir, newdent);
    } else {
        new_root_id = do_post_file (root_id, parent_dir, newdent);
    }

out:
    if (dir)
        seaf_dir_free (dir);

    g_free (basename);
    g_free (ext);
    g_free (newdent);

    return new_root_id;
}

static gboolean
detect_path_exist (const char *root_id,
                   const char *path,
                   GError **error)
{
    SeafDir *dir;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr, root_id, path, error);
    if (*error) {
        if (g_error_matches(*error, SEAFILE_DOMAIN, SEAF_ERR_PATH_NO_EXIST)) {
            /* path does not exist */
            g_clear_error(error);
            return FALSE;
        } else {
            /* Other error */
            return FALSE;
        }
    }

    seaf_dir_free(dir);
    return TRUE;
}

int
seaf_repo_manager_revert_file (SeafRepoManager *mgr,
                               const char *repo_id,
                               const char *old_commit_id,
                               const char *file_path,
                               const char *user,
                               GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL, *old_commit = NULL;
    char *parent_dir = NULL, *filename = NULL;
    char *revert_to_file_id = NULL;
    char *canon_path = NULL, *root_id = NULL;
    char buf[PATH_MAX];
    char time_str[512];
    gboolean parent_dir_exist = FALSE;
    gboolean revert_to_root = FALSE;
    gboolean skipped = FALSE;
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    /* If old_commit_id is head commit, do nothing. */
    if (strcmp(repo->head->commit_id, old_commit_id) == 0) {
        g_debug ("[revert file] commit is head, do nothing\n");
        goto out;
    }

    if (!old_commit) {
        GET_COMMIT_OR_FAIL(old_commit, old_commit_id);
        if (strcmp(old_commit->repo_id, repo_id) != 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "bad commit id");
            ret = -1;
            goto out;
        }
    }

    if (!canon_path) {
        canon_path = get_canonical_path (file_path);
        if (canon_path[strlen(canon_path) -1 ] == '/') {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "bad target file path");
            ret = -1;
            goto out;
        }

        revert_to_file_id = seaf_fs_manager_get_seafile_id_by_path (
                    seaf->fs_mgr, old_commit->root_id, canon_path, error);
        if (*error) {
            seaf_warning ("[revert file] error: %s\n", (*error)->message);
            g_clear_error (error);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "internal error");
            ret = -1;
            goto out;
        }

        parent_dir  = g_path_get_dirname(canon_path);
        filename = g_path_get_basename(canon_path);
    }

    parent_dir_exist = detect_path_exist (head_commit->root_id,
                                          parent_dir, error);
    if (*error) {
        seaf_warning ("[revert file] error: %s\n", (*error)->message);
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "internal error");
        ret = -1;
        goto out;
    }
    
    if (!parent_dir_exist) {
        /* When parent dir does not exist, revert this file to root dir. */
        revert_to_root = TRUE;
        root_id = revert_file_to_root (head_commit->root_id,
                                       filename,
                                       revert_to_file_id,
                                       &skipped, error);
    } else {
        revert_to_root = FALSE;
        root_id = revert_file_to_parent_dir (head_commit->root_id, parent_dir,
                                             filename, revert_to_file_id,
                                             &skipped, error);
    }

    if (*error) {
        seaf_warning ("[revert file] error: %s\n", (*error)->message);
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "internal error");
        ret = -1;
        goto out;
    }

    if (skipped) {
        goto out;
    }
    
    if (!root_id) {
        seaf_warning ("[revert file] Failed to revert file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to revert file");
        ret = -1;
        goto out;
    }

    /* Commit. */
    strftime (time_str, sizeof(time_str), "%F %T",
              localtime((time_t *)(&old_commit->ctime)));
    snprintf(buf, PATH_MAX, "Reverted file \"%s\" to status at %s", filename, time_str);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (old_commit)
        seaf_commit_unref (old_commit);

    g_free (root_id);
    g_free (parent_dir);
    g_free (filename);

    g_free (canon_path);
    g_free (revert_to_file_id);

#define REVERT_TO_ROOT              0x1
    if (ret == 0) {
        if (revert_to_root)
            ret |= REVERT_TO_ROOT;
    }

    return ret;
}

static char *
revert_dir (const char *root_id,
            const char *parent_dir,
            const char *dirname,
            const char *dir_id,
            gboolean *skipped,
            GError **error)
{
    SeafDir *dir = NULL;
    SeafDirent *dent = NULL, *newdent = NULL;
    char new_dir_name[PATH_MAX];
    char *new_root_id = NULL;
    int i = 1;
    GList *p;

    *skipped = FALSE;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                               root_id,
                                               parent_dir, error);
    if (*error) {
        return NULL;
    }

    snprintf (new_dir_name, sizeof(new_dir_name), "%s", dirname);

    for (;;) {
        for (p = dir->entries; p; p = p->next) {
            dent = p->data;
            if (strcmp(dent->name, new_dir_name) != 0)
                continue;

            /* the same dir */
            if (S_ISDIR(dent->mode) && strcmp(dent->id, dir_id) == 0) {
                *skipped = TRUE;
                goto out;
            } else {
                /* rename and retry */
                snprintf (new_dir_name, sizeof(new_dir_name), "%s (%d)",
                          dirname, i++);
                break;
            }
        }

        if (p == NULL)
            break;
    }

    newdent = seaf_dirent_new (dir_id, S_IFDIR, new_dir_name);
    new_root_id = do_post_file (root_id, parent_dir, newdent);

out:
    if (dir)
        seaf_dir_free (dir);

    g_free (newdent);

    return new_root_id;
}

int
seaf_repo_manager_revert_dir (SeafRepoManager *mgr,
                              const char *repo_id,
                              const char *old_commit_id,
                              const char *dir_path,
                              const char *user,
                              GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL, *old_commit = NULL;
    char *parent_dir = NULL, *dirname = NULL;
    char *revert_to_dir_id = NULL;
    char *canon_path = NULL, *root_id = NULL;
    char buf[PATH_MAX];
    gboolean parent_dir_exist = FALSE;
    gboolean revert_to_root = FALSE;
    gboolean skipped = FALSE;
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    /* If old_commit_id is head commit, do nothing. */
    if (strcmp(repo->head->commit_id, old_commit_id) == 0) {
        g_debug ("[revert dir] commit is head, do nothing\n");
        goto out;
    }

    if (!old_commit) {
        GET_COMMIT_OR_FAIL(old_commit, old_commit_id);
        if (strcmp(old_commit->repo_id, repo_id) != 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "bad commit id");
            ret = -1;
            goto out;
        }
    }

    if (!canon_path) {
        canon_path = get_canonical_path (dir_path);

        revert_to_dir_id = seaf_fs_manager_get_seafdir_id_by_path (
                    seaf->fs_mgr, old_commit->root_id, canon_path, error);
        if (*error) {
            seaf_warning ("[revert dir] error: %s\n", (*error)->message);
            g_clear_error (error);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "internal error");
            ret = -1;
            goto out;
        }

        parent_dir  = g_path_get_dirname(canon_path);
        dirname = g_path_get_basename(canon_path);
    }

    parent_dir_exist = detect_path_exist (head_commit->root_id,
                                          parent_dir, error);
    if (*error) {
        seaf_warning ("[revert dir] error: %s\n", (*error)->message);
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "internal error");
        ret = -1;
        goto out;
    }
    
    if (!parent_dir_exist) {
        /* When parent dir does not exist, revert this file to root dir. */
        revert_to_root = TRUE;
        root_id = revert_dir (head_commit->root_id,
                              "/",
                              dirname,
                              revert_to_dir_id,
                              &skipped, error);
    } else {
        revert_to_root = FALSE;
        root_id = revert_dir (head_commit->root_id,
                              parent_dir,
                              dirname,
                              revert_to_dir_id,
                              &skipped, error);
    }

    if (*error) {
        seaf_warning ("[revert dir] error: %s\n", (*error)->message);
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "internal error");
        ret = -1;
        goto out;
    }

    if (skipped) {
        goto out;
    }
    
    if (!root_id) {
        seaf_warning ("[revert dir] Failed to revert dir.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to revert dir");
        ret = -1;
        goto out;
    }

    /* Commit. */
    snprintf(buf, PATH_MAX, "Recovered deleted directory \"%s\"", dirname);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (old_commit)
        seaf_commit_unref (old_commit);

    g_free (root_id);
    g_free (parent_dir);
    g_free (dirname);

    g_free (canon_path);
    g_free (revert_to_dir_id);

#define REVERT_TO_ROOT              0x1
    if (ret == 0) {
        if (revert_to_root)
            ret |= REVERT_TO_ROOT;
    }

    return ret;
}

typedef struct CollectRevisionParam CollectRevisionParam;

struct CollectRevisionParam {
    const char *path;
    GHashTable *wanted_commits;
    GHashTable *file_id_cache;
    GError **error;
};

static char *
get_commit_file_id_with_cache (SeafCommit *commit,
                               const char *path,
                               GHashTable *file_id_cache,
                               GError **error)
{
    char *file_id = NULL;
    guint32 mode;

    file_id = g_hash_table_lookup (file_id_cache, commit->commit_id);
    if (file_id) {
        return g_strdup(file_id);
    }

    file_id = seaf_fs_manager_path_to_obj_id (seaf->fs_mgr,
                    commit->root_id, path, &mode, error);

    if (file_id != NULL) {
        if (S_ISDIR(mode)) {
            g_free (file_id);
            return NULL;

        } else {
            g_hash_table_insert (file_id_cache,
                                 g_strdup(commit->commit_id),
                                 g_strdup(file_id));
            return file_id;
        }
    }

    return NULL;
}

static gboolean
collect_file_revisions (SeafCommit *commit, void *vdata, gboolean *stop)
{
    CollectRevisionParam *data = vdata;
    const char *path = data->path;
    GError **error = data->error;
    GHashTable *wanted_commits = data->wanted_commits;
    GHashTable *file_id_cache = data->file_id_cache;

    SeafCommit *parent = NULL;
    SeafCommit *parent2 = NULL;
    char *file_id = NULL;
    char *parent_file_id = NULL;
    char *parent_file_id2 = NULL;

    gboolean ret = TRUE;

    file_id = get_commit_file_id_with_cache (commit, path,
                                             file_id_cache, error);
    if (*error) {
        ret = FALSE;
        goto out;
    }

    if (!file_id) {
        /* Target file is not present in this commit. */
        goto out;
    }

    if (!commit->parent_id) {
        /* Initial commit */
        seaf_commit_ref (commit);
        g_hash_table_insert (wanted_commits, commit->commit_id, commit);
        goto out;
    }

    parent = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             commit->parent_id);
    if (!parent) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Faild to get commit %s", commit->parent_id);
        ret = FALSE;
        goto out;
    }

    parent_file_id = get_commit_file_id_with_cache (parent,
                                                    path, file_id_cache, error);
    if (*error) {
        ret = FALSE;
        goto out;
    }

    if (g_strcmp0 (parent_file_id, file_id) == 0) {
        /* This commit does not modify the target file */
        goto out;
    }

    /* In case of a merge, the second parent also need compare */
    if (commit->second_parent_id) {
        parent2 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 commit->second_parent_id);
        if (!parent2) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Faild to get commit %s", commit->second_parent_id);
            ret = FALSE;
            goto out;
        }

        parent_file_id2 = get_commit_file_id_with_cache (parent2,
                                        path, file_id_cache, error);
        if (*error) {
            ret = FALSE;
            goto out;
        }

        if (g_strcmp0 (parent_file_id2, file_id) == 0) {
            /* This commit does not modify the target file */
            goto out;
        }
    }

    seaf_commit_ref (commit);
    g_hash_table_insert (wanted_commits, commit->commit_id, commit);

out:
    g_free (file_id);
    g_free (parent_file_id);
    g_free (parent_file_id2);

    if (parent) seaf_commit_unref (parent);
    if (parent2) seaf_commit_unref (parent2);

    return ret;
}

static int
compare_commit_by_time (const SeafCommit *a, const SeafCommit *b)
{
    /* Latest commit comes first in the list. */
    return (b->ctime - a->ctime);
}

GList *
seaf_repo_manager_list_file_revisions (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *path,
                                       int limit,
                                       GError **error)
{
    SeafRepo *repo = NULL;
    GList *commit_list = NULL;
    CollectRevisionParam data = {0};

    repo = seaf_repo_manager_get_repo (mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "No such repo %s", repo_id);
        goto out;
    }

    data.path = path;
    data.error = error;

    /* A (commit id, commit) hash table. We specify a value destroy
     * function, so that even if we fail in half way of traversing, we can
     * free all commits in the hashtbl.*/
    data.wanted_commits = g_hash_table_new_full (g_str_hash, g_str_equal,
                            NULL, (GDestroyNotify)seaf_commit_unref);

    /* A hash table to cache caculated file id of <path> in <commit> */
    data.file_id_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, g_free);

    if (!seaf_commit_manager_traverse_commit_tree_with_limit (seaf->commit_mgr,
                                                        repo->head->commit_id,
                                                        (CommitTraverseFunc)collect_file_revisions,
                                                              limit, &data)) {
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "failed to traverse commit of repo %s", repo_id);
        goto out;
    }

    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, data.wanted_commits);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        SeafCommit *commit = value;
        seaf_commit_ref (commit);
        commit_list = g_list_insert_sorted (commit_list, commit,
                                            (GCompareFunc)compare_commit_by_time);
    }
        
out:
    if (repo)
        seaf_repo_unref (repo);
    if (data.wanted_commits)
        g_hash_table_destroy (data.wanted_commits);
    if (data.file_id_cache)
        g_hash_table_destroy (data.file_id_cache);

    return commit_list;
}

int
seaf_repo_manager_revert_on_server (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *commit_id,
                                    const char *user_name,
                                    GError **error)
{
    SeafRepo *repo;
    SeafCommit *commit, *new_commit;
    char desc[512];
    int ret = 0;

retry:
    repo = seaf_repo_manager_get_repo (mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "No such repo");
        return -1;
    }

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr, commit_id);
    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Commit doesn't exist");
        ret = -1;
        goto out;
    }

    strftime (desc, sizeof(desc), "Reverted repo to status at %F %T.", 
              localtime((time_t *)(&commit->ctime)));

    new_commit = seaf_commit_new (NULL, repo->id, commit->root_id,
                                  user_name, EMPTY_SHA1,
                                  desc, 0);

    new_commit->parent_id = g_strdup (repo->head->commit_id);

    seaf_repo_to_commit (repo, new_commit);

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, new_commit) < 0) {
        ret = -1;
        goto out;
    }

    seaf_branch_set_commit (repo->head, new_commit->commit_id);
    if (seaf_branch_manager_test_and_update_branch (seaf->branch_mgr,
                                                    repo->head,
                                                    new_commit->parent_id) < 0)
    {
        seaf_warning ("[revert] Concurrent branch update, retry.\n");
        seaf_repo_unref (repo);
        seaf_commit_unref (commit);
        seaf_commit_unref (new_commit);
        repo = NULL;
        commit = new_commit = NULL;
        goto retry;
    }

out:
    if (new_commit)
        seaf_commit_unref (new_commit);
    if (commit)
        seaf_commit_unref (commit);
    if (repo)
        seaf_repo_unref (repo);

    return ret;
}

static void
add_deleted_entry (GHashTable *entries,
                   SeafDirent *dent,
                   const char *base,
                   SeafCommit *child,
                   SeafCommit *parent)
{
    char *path = g_strconcat (base, dent->name, NULL);
    SeafileDeletedEntry *entry;
    Seafile *file;

    if (g_hash_table_lookup (entries, path) != NULL) {
        /* g_debug ("found dup deleted entry for %s.\n", path); */
        g_free (path);
        return;
    }

    /* g_debug ("Add deleted entry for %s.\n", path); */

    entry = g_object_new (SEAFILE_TYPE_DELETED_ENTRY,
                          "commit_id", parent->commit_id,
                          "obj_id", dent->id,
                          "obj_name", dent->name,
                          "basedir", base,
                          "mode", dent->mode,
                          "delete_time", child->ctime,
                          NULL);

    if (S_ISREG(dent->mode)) {
        file = seaf_fs_manager_get_seafile (seaf->fs_mgr, dent->id);
        if (!file) {
            g_free (path);
            g_object_unref (entry);
            return;
        }
        g_object_set (entry, "file_size", file->file_size, NULL);
    }

    g_hash_table_insert (entries, path, entry);
}

static int
find_deleted_recursive (const char *root1,
                        const char *root2,
                        const char *base,
                        SeafCommit *child,
                        SeafCommit *parent,
                        GHashTable *entries)
{
    SeafDir *d1, *d2;
    GList *p1, *p2;
    SeafDirent *dent1, *dent2;
    int res, ret = 0;

    d1 = seaf_fs_manager_get_seafdir_sorted (seaf->fs_mgr, root1);
    if (!d1) {
        seaf_warning ("Failed to find dir %s.\n", root1);
        return -1;
    }
    d2 = seaf_fs_manager_get_seafdir_sorted (seaf->fs_mgr, root2);
    if (!d2) {
        seaf_warning ("Failed to find dir %s.\n", root2);
        seaf_dir_free (d1);
        return -1;
    }

    p1 = d1->entries;
    p2 = d2->entries;

    /* Since dirents are sorted in descending order, we can use merge
     * algorithm to find out deleted entries.
     * Deleted entries are those:
     * 1. exists in d2 but absent in d1.
     * 2. exists in both d1 and d2 but with different type.
     */

    while (p1 && p2) {
        dent1 = p1->data;
        dent2 = p2->data;

        res = g_strcmp0 (dent1->name, dent2->name);
        if (res < 0) {
            /* exists in d2 but absent in d1. */
            add_deleted_entry (entries, dent2, base, child, parent);
            p2 = p2->next;
        } else if (res == 0) {
            if ((dent1->mode & S_IFMT) != (dent2->mode & S_IFMT)) {
                /* both exists but with diffent type. */
                add_deleted_entry (entries, dent2, base, child, parent);
            } else if (S_ISDIR(dent1->mode)) {
                char *new_base = g_strconcat (base, dent1->name, "/", NULL);
                ret = find_deleted_recursive (dent1->id, dent2->id, new_base,
                                              child, parent, entries);
                g_free (new_base);
                if (ret < 0)
                    goto out;
            }
            p1 = p1->next;
            p2 = p2->next;
        } else {
            p1 = p1->next;
        }
    }

    for ( ; p2 != NULL; p2 = p2->next) {
        dent2 = p2->data;
        add_deleted_entry (entries, dent2, base, child, parent);
    }

out:
    seaf_dir_free (d1);
    seaf_dir_free (d2);
    return ret;
}

#define MAX_DELETE_TIME (30 * 24 * 3600) /* 30 days */

static gboolean
collect_deleted (SeafCommit *commit, void *data, gboolean *stop)
{
    GHashTable *entries = data;
    guint64 now = time(NULL);
    SeafCommit *p1, *p2;

    if (now - commit->ctime >= MAX_DELETE_TIME) {
        *stop = TRUE;
        return TRUE;
    }

    if (commit->parent_id == NULL)
        return TRUE;

    p1 = seaf_commit_manager_get_commit (commit->manager, commit->parent_id);
    if (!p1) {
        seaf_warning ("Failed to find commit %s.\n", commit->parent_id);
        return FALSE;
    }
    if (find_deleted_recursive (commit->root_id, p1->root_id, "/",
                                commit, p1, entries) < 0) {
        seaf_commit_unref (p1);
        return FALSE;
    }
    seaf_commit_unref (p1);

    if (commit->second_parent_id) {
        p2 = seaf_commit_manager_get_commit (commit->manager,
                                             commit->second_parent_id);
        if (!p2) {
            seaf_warning ("Failed to find commit %s.\n",
                          commit->second_parent_id);
            return FALSE;
        }
        if (find_deleted_recursive (commit->root_id, p2->root_id, "/",
                                    commit, p2, entries) < 0) {
            seaf_commit_unref (p2);
            return FALSE;
        }
        seaf_commit_unref (p2);
    }

    return TRUE;
}

static gboolean
remove_existing (gpointer key, gpointer value, gpointer user_data)
{
    SeafileDeletedEntry *e = value;
    SeafCommit *head = user_data;
    guint32 mode = seafile_deleted_entry_get_mode(e), mode_out = 0;
    char *path = key;

    char *obj_id = seaf_fs_manager_path_to_obj_id (seaf->fs_mgr, head->root_id,
                                                    path, &mode_out, NULL);
    if (obj_id == NULL)
        return FALSE;
    g_free (obj_id);

    /* If path exist in head commit and with the same type,
     * remove it from deleted entries.
     */
    if ((mode & S_IFMT) == (mode_out & S_IFMT)) {
        /* g_debug ("%s exists in head commit.\n", path); */
        return TRUE;
    }

    return FALSE;
}

static int
filter_out_existing_entries (GHashTable *entries, const char *head_id)
{
    SeafCommit *head;

    head = seaf_commit_manager_get_commit (seaf->commit_mgr, head_id);
    if (!head) {
        seaf_warning ("Failed to find head commit %s.\n", head_id);
        return -1;
    }

    g_hash_table_foreach_remove (entries, remove_existing, head);

    seaf_commit_unref (head);
    return 0;
}

static gboolean
hash_to_list (gpointer key, gpointer value, gpointer user_data)
{
    GList **plist = (GList **)user_data;

    g_free (key);
    *plist = g_list_prepend (*plist, value);

    return TRUE;
}

GList *
seaf_repo_manager_get_deleted_entries (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       GError **error)
{
    SeafRepo *repo;
    GHashTable *entries;
    GList *ret = NULL;

    repo = seaf_repo_manager_get_repo (mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Invalid repo id");
        return NULL;
    }

    entries = g_hash_table_new_full (g_str_hash, g_str_equal,
                                     g_free, g_object_unref);
    if (!seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                   repo->head->commit_id,
                                                   collect_deleted,
                                                   entries))
    {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Internal error");
        g_hash_table_destroy (entries);
        seaf_repo_unref (repo);
        return NULL;
    }

    /* Remove entries exist in the current commit.
     * This is necessary because some files may be added back after deletion.
     */
    filter_out_existing_entries (entries, repo->head->commit_id);

    g_hash_table_foreach_steal (entries, hash_to_list, &ret);
    g_hash_table_destroy (entries);

    return ret;
}
