/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <glib/gstdio.h>

#include <openssl/sha.h>

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

int
seaf_repo_manager_del_repo (SeafRepoManager *mgr,
                            SeafRepo *repo)
{
    char sql[256];
    SeafDB *db = mgr->seaf->db;

    /* Remove record in repo table first.
     * Once this is commited, we can gc the other tables later even if
     * we're interrupted.
     */
    snprintf (sql, sizeof(sql), "DELETE FROM Repo WHERE repo_id = '%s'", repo->id);
    if (seaf_db_query (db, sql) < 0)
        return -1;

    /* remove branch */
    GList *p;
    GList *branch_list = 
        seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    for (p = branch_list; p; p = p->next) {
        SeafBranch *b = (SeafBranch *)p->data;
        seaf_repo_manager_branch_repo_unmap (mgr, b);
        seaf_branch_manager_del_branch (seaf->branch_mgr, repo->id, b->name);
    }
    seaf_branch_list_free (branch_list);

    snprintf (sql, sizeof(sql), "DELETE FROM RepoOwner WHERE repo_id = '%s'", 
              repo->id);
    seaf_db_query (db, sql);

    snprintf (sql, sizeof(sql), "DELETE FROM RepoUserToken WHERE repo_id = '%s'", 
              repo->id);
    seaf_db_query (db, sql);

#if 0
    if (pthread_rwlock_wrlock (&mgr->priv->lock) < 0) {
        seaf_warning ("[repo mgr] failed to lock repo cache.\n");
        return -1;
    }

    avl_delete (mgr->priv->repo_tree, repo);
    seaf_repo_unref (repo);

    pthread_rwlock_unlock (&mgr->priv->lock);
#endif

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

    SeafRepo *repo = seaf_repo_new(repo_id, NULL, NULL);
    if (!repo) {
        seaf_warning ("[repo mgr] failed to alloc repo.\n");
        return NULL;
    }

    repo->manager = manager;

    snprintf(sql, 256, "SELECT branch_name FROM RepoHead WHERE repo_id='%s'",
             repo->id);
    if (seaf_db_foreach_selected_row (seaf->db, sql, load_branch_cb, repo) < 0) {
        seaf_warning ("Error read branch for repo %s.\n", repo->id);
        seaf_repo_unref (repo);
        return NULL;
    }

    if (repo->is_corrupted) {
        seaf_repo_free (repo);
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
            "group_id INTEGER, "
            "user_name VARCHAR(255), permission CHAR(15), "
            "UNIQUE INDEX (group_id, repo_id))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS OrgRepo (org_id INTEGER, "
            "repo_id CHAR(37), "
            "user VARCHAR(255), "
            "INDEX (org_id, repo_id), UNIQUE INDEX (repo_id))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS RepoUserToken ("
            "repo_id CHAR(37), "
            "email VARCHAR(255), "
            "token CHAR(41), "
            "UNIQUE INDEX (repo_id, token))";

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

    sql = "CREATE TABLE IF NOT EXISTS PublicRepo (repo_id CHAR(37) PRIMARY KEY)";
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

/* Group related. */

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
        seaf_warning ("DB error when get repo share from for repo %s.\n",
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

/* Org related. */

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
post_file_recursive(const char *dir_id,
                   const char *to_path,
                   SeafDirent *newdent)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    const char *slash;
    char *id = NULL;
    int len;

    olddir = seaf_fs_manager_get_seafdir(seaf->fs_mgr, dir_id);
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

    /* to_path is a relative path */
    slash = strchr(to_path, '/');
    if (!slash) {
        len = strlen (to_path);
        slash = to_path + len;
    } else {
        len = slash - to_path;
        slash = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strncmp(dent->name, to_path, len) != 0)
            continue;

        id = post_file_recursive (dent->id, slash, newdent);
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
        } else if (r < 0) {
            /* entries are in descending order. */
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

#define GEN_NEW_COMMIT(repo,root_id,user,buf)                       \
    do {                                                            \
        new_commit = seaf_commit_new(NULL, repo->id, root_id,       \
                                     user, EMPTY_SHA1,              \
                                     buf, 0);                       \
        new_commit->parent_id = g_strdup (repo->head->commit_id);   \
        seaf_repo_to_commit (repo, new_commit);                     \
                                                                    \
        if (seaf_commit_manager_add_commit (seaf->commit_mgr,       \
                                            new_commit) < 0) {      \
            seaf_warning ("Failed to add commit.\n");               \
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,   \
                         "Failed to add commit");                   \
            ret = -1;                                               \
            goto out;                                               \
        }                                                           \
        seaf_branch_set_commit(repo->head, new_commit->commit_id);  \
    } while (0);


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
    SeafCommit *new_commit = NULL, *head_commit = NULL;
    char *canon_path = NULL;
    unsigned char sha1[20];
    char buf[PATH_MAX];
    char *root_id = NULL;
    SeafileCrypt *crypt = NULL;
    gboolean write_blocks = TRUE;
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

retry:
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

    /* Write blocks. We don't need to write blocks in retry.
     */
    if (write_blocks) {
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
    }

    root_id = do_post_file (head_commit->root_id, canon_path, new_dent);
    if (!root_id) {
        seaf_warning ("[post file] Failed to put file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to put file");
        ret = -1;
        goto out;
    }

    /* Commit. */
    snprintf(buf, PATH_MAX, "Added \"%s\"", file_name);
    GEN_NEW_COMMIT(repo, root_id, user, buf);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   head_commit->commit_id) < 0)
    {
        seaf_warning ("[post file] Concurrent branch update, retry.\n");
        seaf_repo_unref (repo);
        seaf_commit_unref (head_commit);
        seaf_commit_unref (new_commit);
        g_free (root_id);
        g_free (crypt);
        repo = NULL;
        head_commit = new_commit = NULL;
        root_id = NULL;
        crypt = NULL;
        write_blocks = FALSE;
        goto retry;
    }

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_commit)
        seaf_commit_unref(new_commit);
    if (new_dent)
        g_free (new_dent);
    g_free (root_id);
    g_free (canon_path);
    g_free (crypt);

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
    const char *slash;
    char *id = NULL;
    int len;

    olddir = seaf_fs_manager_get_seafdir(seaf->fs_mgr, dir_id);
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

    /* to_path is a relative path */
    slash = strchr(to_path, '/');
    if (!slash) {
        len = strlen (to_path);
        slash = to_path + len;
    } else {
        len = slash - to_path;
        slash = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strncmp(dent->name, to_path, len) != 0)
            continue;

        id = del_file_recursive(dent->id, slash, filename);
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
    SeafCommit *new_commit = NULL, *head_commit = NULL;
    char *canon_path = NULL;
    char buf[PATH_MAX];
    char *root_id = NULL;
    int mode = 0;
    int ret = 0;
    
retry:
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

    GEN_NEW_COMMIT(repo, root_id, user, buf);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   head_commit->commit_id) < 0)
    {
        seaf_warning ("[del file] Concurrent branch update, retry.\n");
        seaf_repo_unref (repo);
        seaf_commit_unref (head_commit);
        seaf_commit_unref (new_commit);
        g_free (root_id);
        repo = NULL;
        head_commit = new_commit = NULL;
        root_id = NULL;
        goto retry;
    }

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_commit)
        seaf_commit_unref(new_commit);
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
        } else if (r < 0) {
            /* entries are in descending order. */
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
    SeafCommit *head_commit = NULL, *new_commit = NULL;
    char *root_id = NULL;
    char buf[PATH_MAX];
    int ret = 0;

retry:
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

    GEN_NEW_COMMIT(repo, root_id, user, buf);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   head_commit->commit_id) < 0)
    {
        seaf_warning ("Concurrent update, retry.\n");
        seaf_repo_unref (repo);
        seaf_commit_unref (head_commit);
        seaf_commit_unref (new_commit);
        g_free (root_id);
        goto retry;
    }
    
out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (new_commit)
        seaf_commit_unref (new_commit);
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
    SeafCommit *head_commit = NULL, *new_commit = NULL;
    char *root_id_after_put = NULL, *root_id = NULL;
    char buf[PATH_MAX];
    int ret = 0;

retry:
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

    GEN_NEW_COMMIT(repo, root_id, user, buf);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   head_commit->commit_id) < 0)
    {
        seaf_warning ("[move file] Concurrent branch update, retry.\n");
        seaf_repo_unref (repo);
        seaf_commit_unref (head_commit);
        seaf_commit_unref (new_commit);
        g_free (root_id_after_put);
        g_free (root_id);
        repo = NULL;
        head_commit = new_commit = NULL;
        root_id_after_put = root_id = NULL;
        goto retry;
    }
    
out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (new_commit)
        seaf_commit_unref (new_commit);
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
    SeafCommit *new_commit = NULL, *head_commit = NULL;
    char *canon_path = NULL;
    char buf[PATH_MAX];
    char *root_id = NULL;
    SeafDirent *new_dent = NULL;
    int ret = 0;

retry:
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
    GEN_NEW_COMMIT(repo, root_id, user, buf);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   head_commit->commit_id) < 0)
    {
        seaf_warning ("[post dir] Concurrent branch update, retry.\n");
        seaf_repo_unref (repo);
        seaf_commit_unref (head_commit);
        seaf_commit_unref (new_commit);
        g_free (root_id);
        g_free (canon_path);
        repo = NULL;
        head_commit = new_commit = NULL;
        root_id = canon_path = NULL;
        goto retry;
    }

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_commit)
        seaf_commit_unref(new_commit);
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
    const char *slash;
    char *id = NULL;
    int len;

    olddir = seaf_fs_manager_get_seafdir(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir. */
    if (*to_path == '\0') {
        SeafDirent *old, *new;
        GList *newentries = NULL, *p;

        for (p = olddir->entries; p != NULL; p = p->next) {
            old = p->data;
            if (strcmp(old->name, oldname) == 0) {
                new = seaf_dirent_new (old->id, old->mode, newname);
            } else {
                new = seaf_dirent_new (old->id, old->mode, old->name);
            }
            newentries = g_list_prepend (newentries, new);
        }

        newentries = g_list_reverse (newentries);

        newdir = seaf_dir_new (NULL, newentries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        id = g_strndup (newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free (newdir);

        goto out;
    }

    /* to_path is a relative path */
    slash = strchr(to_path, '/');
    if (!slash) {
        len = strlen (to_path);
        slash = to_path + len;
    } else {
        len = slash - to_path;
        slash = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strncmp(dent->name, to_path, len) != 0)
            continue;

        id = rename_file_recursive (dent->id, slash, oldname, newname);
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
    SeafCommit *head_commit = NULL, *new_commit = NULL;
    char *root_id = NULL;
    char *canon_path = NULL;
    char buf[PATH_MAX];
    int mode = 0;
    int ret;

    if (strcmp(oldname, newname) == 0)
        return 0;
    
retry:
    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);
    
    if (!canon_path)
        canon_path = get_canonical_path (parent_dir);

    FAIL_IF_FILE_NOT_EXISTS(head_commit->root_id, canon_path, oldname, &mode);

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

    GEN_NEW_COMMIT(repo, root_id, user, buf);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   head_commit->commit_id) < 0)
    {
        seaf_warning ("[rename file] Concurrent branch update, retry.\n");
        seaf_repo_unref (repo);
        seaf_commit_unref (head_commit);
        seaf_commit_unref (new_commit);
        g_free (root_id);
        repo = NULL;
        head_commit = new_commit = NULL;
        root_id = NULL;
        goto retry;
    }

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (new_commit)
        seaf_commit_unref (new_commit);
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

static char *
put_file_recursive(const char *dir_id,
                   const char *to_path,
                   SeafDirent *newdent)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    const char *slash;
    char *id = NULL;
    int len;

    olddir = seaf_fs_manager_get_seafdir(seaf->fs_mgr, dir_id);
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

    /* to_path is a relative path */
    slash = strchr(to_path, '/');
    if (!slash) {
        len = strlen (to_path);
        slash = to_path + len;
    } else {
        len = slash - to_path;
        slash = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strncmp(dent->name, to_path, len) != 0)
            continue;

        id = put_file_recursive (dent->id, slash, newdent);
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
    SeafCommit *new_commit = NULL, *head_commit = NULL;
    char *canon_path = NULL;
    unsigned char sha1[20];
    char buf[PATH_MAX];
    char *root_id = NULL;
    SeafileCrypt *crypt = NULL;
    gboolean write_blocks = TRUE;
    SeafDirent *new_dent = NULL;
    char hex[41];
    int ret = 0;

    if (access (temp_file_path, R_OK) != 0) {
        seaf_warning ("[put file] File %s doesn't exist or not readable.\n",
                      temp_file_path);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid input file");
        return -1;
    }

retry:
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

    /* Write blocks. We don't need to write blocks in retry.
     */
    if (write_blocks) {
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
    GEN_NEW_COMMIT(repo, root_id, user, buf);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   head_commit->commit_id) < 0)
    {
        seaf_warning ("[put file] Concurrent branch update, retry.\n");
        seaf_repo_unref (repo);
        seaf_commit_unref (head_commit);
        seaf_commit_unref (new_commit);
        g_free (root_id);
        g_free (crypt);
        repo = NULL;
        head_commit = new_commit = NULL;
        root_id = NULL;
        crypt = NULL;
        write_blocks = FALSE;
        goto retry;
    }

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_commit)
        seaf_commit_unref(new_commit);
    if (new_dent)
        g_free (new_dent);
    g_free (root_id);
    g_free (canon_path);
    g_free (crypt);

    return ret;
}

int
seaf_repo_manager_revert_file (SeafRepoManager *mgr,
                               const char *repo_id,
                               const char *commit_id,
                               const char *path,
                               const char *user,
                               GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL, *commit = NULL, *new_commit = NULL;
    SeafDirent *revert_to_dent = NULL;
    char *dirname, *filename;
    char *current_file_id = NULL, *revert_to_file_id = NULL;
    char *canon_path = NULL, *root_id = NULL;
    char buf[PATH_MAX];
    char time_str[512];
    int ret = 0;

retry:
    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    /* if commit_id is head commit, do nothing */
    if (strcmp(repo->head->commit_id, commit_id) == 0) {
        seaf_warning ("[revert file] commit is head, do nothing\n");
        goto out;
    }

    if (!commit) {
        GET_COMMIT_OR_FAIL(commit, commit_id);
        if (strcmp(commit->repo_id, repo_id) != 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "bad commit id");
            ret = -1;
            goto out;
        }
    }

    if (!canon_path) {
        canon_path = get_canonical_path(path);
        if (canon_path[strlen(canon_path) -1 ] == '/') {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "bad target file path");
            ret = -1;
            goto out;
        }

        char *slash = strrchr (canon_path, '/');
        if (!slash) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "bad target file path");
            ret = -1;
            goto out;
        }

        filename = slash + 1;
        if (slash == canon_path)
            dirname = "/";
        else {
            *slash = '\0';
            dirname = canon_path;
        }
    }

    if (!current_file_id) {
        current_file_id = seaf_fs_manager_path_to_file_id (seaf->fs_mgr,
                                                head_commit->root_id,
                                                canon_path, NULL);

        if (!current_file_id) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "file does not exist or is deleted");
            ret = -1;
            goto out;
        }

        revert_to_file_id = seaf_fs_manager_path_to_file_id (seaf->fs_mgr,
                                                     commit->root_id,
                                                     canon_path, NULL);
        if (!revert_to_file_id) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "file does not exist in history commit");
            ret = -1;
            goto out;
        }

        if (strcmp(current_file_id, revert_to_file_id) == 0) {
            seaf_warning ("[revert file] target version is "
                          "the same as current version.\n");
            goto out;
        }

        revert_to_dent = seaf_dirent_new (revert_to_file_id,
                                          S_IFREG, filename);
    }

    root_id = do_put_file (head_commit->root_id, dirname, revert_to_dent);

    if (!root_id) {
        seaf_warning ("[revert file] Failed to revert file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to revert file");
        ret = -1;
        goto out;
    }

    /* Commit. */
    strftime (time_str, sizeof(time_str), "%F %T",
              localtime((time_t *)(&commit->ctime)));
    snprintf(buf, PATH_MAX, "Reverted file \"%s\" to status at %s", filename, time_str);
    GEN_NEW_COMMIT(repo, root_id, user, buf);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   head_commit->commit_id) < 0)
    {
        seaf_warning ("[post file] Concurrent branch update, retry.\n");
        seaf_repo_unref (repo);
        seaf_commit_unref (head_commit);
        seaf_commit_unref (new_commit);
        g_free (root_id);
        repo = NULL;
        head_commit = new_commit = NULL;
        root_id = NULL;
        goto retry;
    }

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (commit)
        seaf_commit_unref (commit);
    if (new_commit)
        seaf_commit_unref (new_commit);
    g_free (canon_path);
    g_free (root_id);
    g_free (current_file_id);
    g_free (revert_to_file_id);

    return ret;
}

typedef struct CollectRevisionParam CollectRevisionParam;

struct CollectRevisionParam {
    const char *path;
    GHashTable *commit_hash;
    GError **error;
};

static gboolean
collect_file_revisions (SeafCommit *commit, void *vdata, gboolean *stop)
{
    CollectRevisionParam *data = vdata;
    GError **error = data->error;
    GHashTable *commit_hash = data->commit_hash;
    char *file_id;
    file_id = seaf_fs_manager_path_to_file_id (seaf->fs_mgr,
                                               commit->root_id,
                                               data->path, error);
    if (*error) {
        *stop = TRUE;
        return FALSE;
    } else if (!file_id) {
        return TRUE;
    }

    SeafCommit *commit2 = g_hash_table_lookup (commit_hash, file_id);
    if (!commit2) {
        seaf_commit_ref (commit);
        g_hash_table_insert (commit_hash, file_id, commit);

    } else if (commit->ctime < commit2->ctime) {
        seaf_commit_ref (commit);
        g_hash_table_replace (commit_hash, file_id, commit);
        /* no need to unref commit2 since we alreay specified a value destroy function */
    }

    return TRUE;
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
                                       GError **error)
{
    SeafRepo *repo = NULL;
    GHashTable *commit_hash = NULL;

    GList *commit_list = NULL;

    repo = seaf_repo_manager_get_repo (mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "No such repo %s", repo_id);
        goto out;
    }

    /* A (seafile id, commit id) hash table. We specify a value destroy
     * function, so that even if we fail in half way of traversing, we can
     * free all commits in the hashtbl.*/
    commit_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                    g_free, (GDestroyNotify)seaf_commit_unref);

    CollectRevisionParam data;
    data.path = path;
    data.commit_hash = commit_hash;
    data.error = error;

    if (!seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                repo->head->commit_id,
                                (CommitTraverseFunc)collect_file_revisions,
                                &data)) {
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "failed to traverse commit of repo %s", repo_id);
        goto out;
    }

    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, commit_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        SeafCommit *commit = value;
        seaf_commit_ref (commit);
        commit_list = g_list_insert_sorted (commit_list, commit,
                                            (GCompareFunc)compare_commit_by_time);
    }
        
out:
    if (repo)
        seaf_repo_unref (repo);
    if (commit_hash)
        g_hash_table_destroy (commit_hash);

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
