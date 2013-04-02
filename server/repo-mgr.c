/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <glib/gstdio.h>

#include <json-glib/json-glib.h>
#include <openssl/sha.h>

#include <ccnet.h>
#include <ccnet/ccnet-object.h>
#include "utils.h"
#include "log.h"
#include "seafile.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "fs-mgr.h"
#include "seafile-error.h"
#include "seafile-crypt.h"

#include "monitor-rpc-wrappers.h"

#include "seaf-db.h"

#define REAP_TOKEN_INTERVAL 300 /* 5 mins */
#define DECRYPTED_TOKEN_TTL 3600 /* 1 hour */

typedef struct DecryptedToken {
    char *token;
    gint64 reap_time;
} DecryptedToken;

struct _SeafRepoManagerPriv {
    /* (encrypted_token, session_key) -> decrypted token */
    GHashTable *decrypted_tokens;
    pthread_rwlock_t lock;
    CcnetTimer *reap_token_timer;
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
load_repo (SeafRepoManager *manager, const char *repo_id, gboolean ret_corrupt);

static int create_db_tables_if_not_exist (SeafRepoManager *mgr);

static int save_branch_repo_map (SeafRepoManager *manager, SeafBranch *branch);

static int reap_token (void *data);
static void decrypted_token_free (DecryptedToken *token);

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

int
seaf_repo_set_head (SeafRepo *repo, SeafBranch *branch)
{
    if (save_branch_repo_map (repo->manager, branch) < 0)
        return -1;
    set_head_common (repo, branch);
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

static inline gboolean
has_trailing_space (const char *path)
{
    int len = strlen(path);
    if (path[len - 1] == ' ') {
        return TRUE;
    }

    return FALSE;
}

gboolean
should_ignore_file(const char *filename, void *data)
{
    GPatternSpec **spec = ignore_patterns;

    /* Ignore file/dir if its name is too long. */
    if (strlen(filename) >= SEAF_DIR_NAME_LEN)
        return TRUE;

    if (has_trailing_space (filename)) {
        /* Ignore files/dir whose path has trailing spaces. It would cause
         * problem on windows. */
        /* g_debug ("ignore '%s' which contains trailing space in path\n", path); */
        return TRUE;
    }

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

SeafRepoManager*
seaf_repo_manager_new (SeafileSession *seaf)
{
    SeafRepoManager *mgr = g_new0 (SeafRepoManager, 1);

    mgr->priv = g_new0 (SeafRepoManagerPriv, 1);
    mgr->seaf = seaf;

    mgr->priv->decrypted_tokens = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                         g_free,
                                                         (GDestroyNotify)decrypted_token_free);
    pthread_rwlock_init (&mgr->priv->lock, NULL);
    mgr->priv->reap_token_timer = ccnet_timer_new (reap_token, mgr,
                                                   REAP_TOKEN_INTERVAL * 1000);

    ignore_patterns = g_new0 (GPatternSpec*, G_N_ELEMENTS(ignore_table));
    int i;
    for (i = 0; ignore_table[i] != NULL; i++) {
        ignore_patterns[i] = g_pattern_spec_new (ignore_table[i]);
    }

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
repo_exists_in_db (SeafDB *db, const char *id, gboolean *db_err)
{
    char sql[256];

    snprintf (sql, sizeof(sql), "SELECT repo_id FROM Repo WHERE repo_id = '%s'",
              id);
    return seaf_db_check_for_existence (db, sql, db_err);
}

SeafRepo*
seaf_repo_manager_get_repo (SeafRepoManager *manager, const gchar *id)
{
    int len = strlen(id);
    gboolean db_err = FALSE;

    if (len >= 37)
        return NULL;

    if (repo_exists_in_db (manager->seaf->db, id, &db_err)) {
        SeafRepo *ret = load_repo (manager, id, FALSE);
        if (!ret)
            return NULL;
        /* seaf_repo_ref (ret); */
        return ret;
    }

    return NULL;
}

SeafRepo*
seaf_repo_manager_get_repo_ex (SeafRepoManager *manager, const gchar *id)
{
    int len = strlen(id);
    gboolean db_err = FALSE, exists;
    SeafRepo *ret = NULL;

    if (len >= 37)
        return NULL;

    exists = repo_exists_in_db (manager->seaf->db, id, &db_err);

    if (db_err) {
        ret = seaf_repo_new(id, NULL, NULL);
        ret->is_corrupted = TRUE;
        return ret;
    }

    if (exists) {
        ret = load_repo (manager, id, TRUE);
        return ret;
    }

    return NULL;
}

gboolean
seaf_repo_manager_repo_exists (SeafRepoManager *manager, const gchar *id)
{
    gboolean db_err = FALSE;
    return repo_exists_in_db (manager->seaf->db, id, &db_err);
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
load_repo (SeafRepoManager *manager, const char *repo_id, gboolean ret_corrupt)
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
    if (n <= 0) {
        seaf_warning ("Error read branch for repo %s.\n", repo->id);
        repo->is_corrupted = TRUE;
    }

    if (repo->is_corrupted && !ret_corrupt) {
        seaf_repo_free (repo);
        return NULL;
    }

    return repo;
}

static int
create_tables_mysql (SeafRepoManager *mgr)
{
    SeafDB *db = mgr->seaf->db;
    char *sql;

    sql = "CREATE TABLE IF NOT EXISTS Repo (repo_id CHAR(37) PRIMARY KEY)"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoOwner ("
        "repo_id CHAR(37) PRIMARY KEY, "
        "owner_id VARCHAR(255),"
        "INDEX (owner_id))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoGroup (repo_id CHAR(37), "
        "group_id INTEGER, user_name VARCHAR(255), permission CHAR(15), "
        "UNIQUE INDEX (group_id, repo_id), "
        "INDEX (repo_id), INDEX (user_name))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    if (!mgr->seaf->cloud_mode) {
        sql = "CREATE TABLE IF NOT EXISTS InnerPubRepo ("
            "repo_id CHAR(37) PRIMARY KEY,"
            "permission CHAR(15))"
            "ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    if (mgr->seaf->cloud_mode) {
        sql = "CREATE TABLE IF NOT EXISTS OrgRepo (org_id INTEGER, "
            "repo_id CHAR(37), "
            "user VARCHAR(255), "
            "INDEX (org_id, repo_id), UNIQUE INDEX (repo_id), "
            "INDEX (org_id, user))"
            "ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS OrgGroupRepo ("
            "org_id INTEGER, repo_id CHAR(37), "
            "group_id INTEGER, owner VARCHAR(255), permission CHAR(15), "
            "UNIQUE INDEX (org_id, group_id, repo_id), "
            "INDEX (repo_id), INDEX (owner))"
            "ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        sql = "CREATE TABLE IF NOT EXISTS OrgInnerPubRepo ("
            "org_id INTEGER, repo_id CHAR(37),"
            "PRIMARY KEY (org_id, repo_id), "
            "permission CHAR(15))"
            "ENGINE=INNODB";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    sql = "CREATE TABLE IF NOT EXISTS RepoUserToken ("
        "repo_id CHAR(37), "
        "email VARCHAR(255), "
        "token CHAR(41), "
        "UNIQUE INDEX (repo_id, token))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoHead ("
        "repo_id CHAR(37) PRIMARY KEY, branch_name VARCHAR(10))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoSize ("
        "repo_id CHAR(37) PRIMARY KEY,"
        "size BIGINT UNSIGNED,"
        "head_id CHAR(41))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoHistoryLimit ("
        "repo_id CHAR(37) PRIMARY KEY, days INTEGER)"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoValidSince ("
        "repo_id CHAR(37) PRIMARY KEY, timestamp BIGINT)"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS WebAP (repo_id CHAR(37) PRIMARY KEY, "
        "access_property CHAR(10))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    return 0;
}

static int
create_tables_sqlite (SeafRepoManager *mgr)
{
    SeafDB *db = mgr->seaf->db;
    char *sql;

    sql = "CREATE TABLE IF NOT EXISTS Repo (repo_id CHAR(37) PRIMARY KEY)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

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

    sql = "CREATE TABLE IF NOT EXISTS RepoHead ("
        "repo_id CHAR(37) PRIMARY KEY, branch_name VARCHAR(10))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoSize ("
        "repo_id CHAR(37) PRIMARY KEY,"
        "size BIGINT UNSIGNED,"
        "head_id CHAR(41))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoHistoryLimit ("
        "repo_id CHAR(37) PRIMARY KEY, days INTEGER)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoValidSince ("
        "repo_id CHAR(37) PRIMARY KEY, timestamp BIGINT)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS WebAP (repo_id CHAR(37) PRIMARY KEY, "
        "access_property CHAR(10))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    return 0;
}

static int 
create_db_tables_if_not_exist (SeafRepoManager *mgr)
{
    SeafDB *db = mgr->seaf->db;
    int db_type = seaf_db_type (db);

    if (db_type == SEAF_DB_TYPE_MYSQL)
        return create_tables_mysql (mgr);
    else if (db_type == SEAF_DB_TYPE_SQLITE)
        return create_tables_sqlite (mgr);

    g_assert (0);
    return -1;
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
    gboolean db_err = FALSE;

    if (!repo_exists_in_db (mgr->seaf->db, repo_id, &db_err))
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
    gboolean db_err = FALSE;

    if (!repo_exists_in_db (mgr->seaf->db, repo_id, &db_err))
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

int
seaf_repo_manager_get_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id)
{
    char sql[256];
    int per_repo_days;

    snprintf (sql, sizeof(sql),
              "SELECT days FROM RepoHistoryLimit WHERE repo_id='%s'",
              repo_id);
    per_repo_days = seaf_db_get_int (mgr->seaf->db, sql);

    /* If per repo value is not set or DB error, return the global one. */
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
    /* Also return -1 if doesn't exist. */
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

GList *
seaf_repo_manager_get_repo_ids_by_owner (SeafRepoManager *mgr,
                                         const char *email)
{
    GList *ret = NULL;
    char sql[256];

    snprintf (sql, 256, "SELECT repo_id FROM RepoOwner WHERE owner_id='%s'",
              email);

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_repo_id, &ret) < 0) {
        string_list_free (ret);
        return NULL;
    }

    return ret;
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
    gboolean db_err = FALSE;

    snprintf (sql, sizeof(sql),
              "SELECT repo_id FROM InnerPubRepo WHERE repo_id='%s'",
              repo_id);
    return seaf_db_check_for_existence (mgr->seaf->db, sql, &db_err);
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

gint64
seaf_repo_manager_count_inner_pub_repos (SeafRepoManager *mgr)
{
    char sql[256];

    snprintf (sql, 256, "SELECT COUNT(*) FROM InnerPubRepo");

    return seaf_db_get_int64(mgr->seaf->db, sql);
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
    gboolean db_err = FALSE;

    snprintf (sql, sizeof(sql),
              "SELECT repo_id FROM OrgInnerPubRepo WHERE "
              "org_id = %d AND repo_id='%s'",
              org_id, repo_id);
    return seaf_db_check_for_existence (mgr->seaf->db, sql, &db_err);
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



int
seaf_repo_manager_is_valid_filename (SeafRepoManager *mgr,
                                     const char *repo_id,
                                     const char *filename,
                                     GError **error)
{
    if (should_ignore_file(filename, NULL))
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

    if (seaf_repo_set_head (repo, master) < 0) {
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

static int reap_token (void *data)
{
    SeafRepoManager *mgr = data;
    GHashTableIter iter;
    gpointer key, value;
    DecryptedToken *t;

    pthread_rwlock_wrlock (&mgr->priv->lock);

    gint64 now = (gint64)time(NULL);

    g_hash_table_iter_init (&iter, mgr->priv->decrypted_tokens);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        t = value;
        if (now >= t->reap_time)
            g_hash_table_iter_remove (&iter);
    }

    pthread_rwlock_unlock (&mgr->priv->lock);

    return TRUE;
}

static void decrypted_token_free (DecryptedToken *token)
{
    if (!token)
        return;
    g_free (token->token);
    g_free (token);
}

void
seaf_repo_manager_add_decrypted_token (SeafRepoManager *mgr,
                                       const char *encrypted_token,
                                       const char *session_key,
                                       const char *decrypted_token)
{
    char key[256];
    DecryptedToken *token;

    snprintf (key, sizeof(key), "%s%s", encrypted_token, session_key);
    key[255] = 0;

    pthread_rwlock_wrlock (&mgr->priv->lock);

    token = g_new0 (DecryptedToken, 1);
    token->token = g_strdup(decrypted_token);
    token->reap_time = (gint64)time(NULL) + DECRYPTED_TOKEN_TTL;

    g_hash_table_insert (mgr->priv->decrypted_tokens,
                         g_strdup(key),
                         token);

    pthread_rwlock_unlock (&mgr->priv->lock);
}

char *
seaf_repo_manager_get_decrypted_token (SeafRepoManager *mgr,
                                       const char *encrypted_token,
                                       const char *session_key)
{
    char key[256];
    DecryptedToken *token;

    snprintf (key, sizeof(key), "%s%s", encrypted_token, session_key);
    key[255] = 0;

    pthread_rwlock_rdlock (&mgr->priv->lock);
    token = g_hash_table_lookup (mgr->priv->decrypted_tokens, key);
    pthread_rwlock_unlock (&mgr->priv->lock);

    if (token)
        return g_strdup(token->token);
    return NULL;
}
