/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <glib/gstdio.h>

#include <openssl/sha.h>
#include <openssl/rand.h>

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
#define SCAN_TRASH_DAYS 1 /* one day */
#define TRASH_EXPIRE_DAYS 30 /* one month */

typedef struct DecryptedToken {
    char *token;
    gint64 reap_time;
} DecryptedToken;

struct _SeafRepoManagerPriv {
    /* (encrypted_token, session_key) -> decrypted token */
    GHashTable *decrypted_tokens;
    pthread_rwlock_t lock;
    CcnetTimer *reap_token_timer;

    CcnetTimer *scan_trash_timer;
    gint64 trash_expire_interval;
};

static const char *ignore_table[] = {
    /* tmp files under Linux */
    "*~",
    /* Emacs tmp files */
    "#*#",
    /* ms office tmp files */
    "~$*",
    "~*.tmp", /* for files like ~WRL0001.tmp */
    /* windows image cache */
    "Thumbs.db",
    /* For Mac */
    ".DS_Store",
    NULL,
};

static GPatternSpec** ignore_patterns;

static void
load_repo (SeafRepoManager *manager, SeafRepo *repo);

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
    if (repo->head) seaf_branch_unref (repo->head);
    if (repo->virtual_info)
        seaf_virtual_repo_info_free (repo->virtual_info);
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
    repo->repaired = commit->repaired;
    repo->last_modify = commit->ctime;
    memcpy (repo->root_id, commit->root_id, 40);
    if (repo->encrypted) {
        repo->enc_version = commit->enc_version;
        if (repo->enc_version == 1)
            memcpy (repo->magic, commit->magic, 32);
        else if (repo->enc_version == 2) {
            memcpy (repo->magic, commit->magic, 64);
            memcpy (repo->random_key, commit->random_key, 96);
        }
    }
    repo->no_local_history = commit->no_local_history;
    repo->version = commit->version;
}

void
seaf_repo_to_commit (SeafRepo *repo, SeafCommit *commit)
{
    commit->repo_name = g_strdup (repo->name);
    commit->repo_desc = g_strdup (repo->desc);
    commit->encrypted = repo->encrypted;
    commit->repaired = repo->repaired;
    if (commit->encrypted) {
        commit->enc_version = repo->enc_version;
        if (commit->enc_version == 1)
            commit->magic = g_strdup (repo->magic);
        else if (commit->enc_version == 2) {
            commit->magic = g_strdup (repo->magic);
            commit->random_key = g_strdup (repo->random_key);
        }
    }
    commit->no_local_history = repo->no_local_history;
    commit->version = repo->version;
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
                                                                 repo->id,
                                                                 repo->version,
                                                                 branch->commit_id,
                                                                 collect_commit,
                                                                 &commits,
                                                                 FALSE);
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

gboolean
should_ignore_file(const char *filename, void *data)
{
    /* GPatternSpec **spec = ignore_patterns; */

    if (!g_utf8_validate (filename, -1, NULL)) {
        seaf_warning ("File name %s contains non-UTF8 characters, skip.\n", filename);
        return TRUE;
    }

    /* Ignore file/dir if its name is too long. */
    if (strlen(filename) >= SEAF_DIR_NAME_LEN)
        return TRUE;

    if (strchr (filename, '/'))
        return TRUE;

    return FALSE;
}

static gboolean
collect_repo_id (SeafDBRow *row, void *data);

static int
scan_trash (void *data)
{
    GList *repo_ids = NULL;
    SeafRepoManager *mgr = seaf->repo_mgr;
    gint64 expire_time = time(NULL) - mgr->priv->trash_expire_interval;
    char *sql = "SELECT repo_id FROM RepoTrash WHERE del_time <= ?";

    int ret = seaf_db_statement_foreach_row (seaf->db, sql,
                                             collect_repo_id, &repo_ids,
                                             1, "int64", expire_time);
    if (ret < 0) {
        seaf_warning ("Get expired repo from trash failed.");
        string_list_free (repo_ids);
        return TRUE;
    }

    GList *iter;
    char *repo_id;
    for (iter=repo_ids; iter; iter=iter->next) {
        repo_id = iter->data;
        ret = seaf_repo_manager_del_repo_from_trash (mgr, repo_id, NULL);
        if (ret < 0)
            break;
    }

    string_list_free (repo_ids);

    return TRUE;
}

static void
init_scan_trash_timer (SeafRepoManagerPriv *priv, GKeyFile *config)
{
    int scan_days;
    int expire_days;
    GError *error = NULL;

    scan_days = g_key_file_get_integer (config,
                                        "library_trash", "scan_days",
                                        &error);
    if (error) {
       scan_days = SCAN_TRASH_DAYS;
       g_clear_error (&error);
    }

    expire_days = g_key_file_get_integer (config,
                                          "library_trash", "expire_days",
                                          &error);
    if (error) {
        expire_days = TRASH_EXPIRE_DAYS;
        g_clear_error (&error);
    }

    priv->trash_expire_interval = expire_days * 24 * 3600;
    priv->scan_trash_timer = ccnet_timer_new (scan_trash, NULL,
                                              scan_days * 24 * 3600 * 1000);
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

    init_scan_trash_timer (mgr->priv, seaf->config);

    /* ignore_patterns = g_new0 (GPatternSpec*, G_N_ELEMENTS(ignore_table)); */
    /* int i; */
    /* for (i = 0; ignore_table[i] != NULL; i++) { */
    /*     ignore_patterns[i] = g_pattern_spec_new (ignore_table[i]); */
    /* } */

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

    if (seaf_repo_manager_init_merge_scheduler() < 0) {
        seaf_warning ("Failed to init merge scheduler.\n");
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
    SeafDB *db = manager->seaf->db;

    if (seaf_db_statement_query (db, "INSERT INTO Repo VALUES (?)",
                                 1, "string", repo->id) < 0)
        return -1;

    repo->manager = manager;

    return 0;
}

static int
add_deleted_repo_record (SeafRepoManager *mgr, const char *repo_id)
{
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;

        exists = seaf_db_statement_exists (seaf->db,
                                           "SELECT repo_id FROM GarbageRepos "
                                           "WHERE repo_id=?",
                                           &err, 1, "string", repo_id);
        if (err)
            return -1;

        if (!exists) {
            return seaf_db_statement_query(seaf->db,
                                           "INSERT INTO GarbageRepos VALUES (?)",
                                           1, "string", repo_id);
        }

        return 0;
    } else {
        return seaf_db_statement_query (seaf->db,
                                        "REPLACE INTO GarbageRepos VALUES (?)",
                                        1, "string", repo_id);
    }
}

static int
add_deleted_repo_to_trash (SeafRepoManager *mgr, const char *repo_id,
                           SeafCommit *commit)
{
    char *owner = NULL;
    int ret = -1;

    owner = seaf_repo_manager_get_repo_owner (mgr, repo_id);
    if (!owner) {
        seaf_warning ("Failed to get owner for repo %.8s.\n", repo_id);
        goto out;
    }

    gint64 size = seaf_repo_manager_get_repo_size (mgr, repo_id);
    if (size == -1) {
        seaf_warning ("Failed to get size of repo %.8s.\n", repo_id);
        goto out;
    }

    ret =  seaf_db_statement_query (mgr->seaf->db,
                                    "INSERT INTO RepoTrash (repo_id, repo_name, head_id, "
                                    "owner_id, size, org_id, del_time) "
                                    "values (?, ?, ?, ?, ?, -1, ?)", 6,
                                    "string", repo_id,
                                    "string", commit->repo_name,
                                    "string", commit->commit_id,
                                    "string", owner,
                                    "int64", size,
                                    "int64", time(NULL));
out:
    g_free (owner);

    return ret;
}

static int
remove_virtual_repo_ondisk (SeafRepoManager *mgr,
                            const char *repo_id)
{
    SeafDB *db = mgr->seaf->db;

    /* Remove record in repo table first.
     * Once this is commited, we can gc the other tables later even if
     * we're interrupted.
     */
    if (seaf_db_statement_query (db, "DELETE FROM Repo WHERE repo_id = ?",
                                 1, "string", repo_id) < 0)
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

    seaf_db_statement_query (db, "DELETE FROM RepoOwner WHERE repo_id = ?",
                   1, "string", repo_id);

    seaf_db_statement_query (db, "DELETE FROM SharedRepo WHERE repo_id = ?",
                   1, "string", repo_id);

    seaf_db_statement_query (db, "DELETE FROM RepoGroup WHERE repo_id = ?",
                   1, "string", repo_id);

    if (!seaf->cloud_mode) {
        seaf_db_statement_query (db, "DELETE FROM InnerPubRepo WHERE repo_id = ?",
                                 1, "string", repo_id);
    }

    seaf_db_statement_query (db, "DELETE FROM RepoUserToken WHERE repo_id = ?",
                             1, "string", repo_id);

    return 0;
}

static gboolean
get_branch (SeafDBRow *row, void *vid)
{
    char *ret = vid;
    const char *commit_id;

    commit_id = seaf_db_row_get_column_text (row, 0);
    memcpy (ret, commit_id, 41);

    return FALSE;
}

static SeafCommit*
get_head_commit (SeafRepoManager *mgr, const char *repo_id, gboolean *has_err)
{
    char commit_id[41];
    char *sql;

    commit_id[0] = 0;
    sql = "SELECT commit_id FROM Branch WHERE name=? AND repo_id=?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       get_branch, commit_id,
                                       2, "string", "master", "string", repo_id) < 0) {
        *has_err = TRUE;
        return NULL;
    }

    if (commit_id[0] == 0)
        return NULL;

    SeafCommit *head_commit = seaf_commit_manager_get_commit (seaf->commit_mgr, repo_id,
                                                              1, commit_id);

    return head_commit;
}

int
seaf_repo_manager_del_repo (SeafRepoManager *mgr,
                            const char *repo_id,
                            GError **error)
{
    gboolean has_err = FALSE;

    SeafCommit *head_commit = get_head_commit (mgr, repo_id, &has_err);
    if (has_err) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get head commit from db");
        return -1;
    }
    if (!head_commit) {
        // head commit is missing, del repo directly
        goto del_repo;
    }

    if (add_deleted_repo_to_trash (mgr, repo_id, head_commit) < 0) {
        seaf_commit_unref (head_commit);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to remove repo to trash ");
        return -1;
    }

    seaf_commit_unref (head_commit);

del_repo:
    if (seaf_db_statement_query (mgr->seaf->db, "DELETE FROM Repo WHERE repo_id = ?",
                                 1, "string", repo_id) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to delete repo from db");
        return -1;
    }

    /* Repo branches are not removed at this point. */

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM RepoOwner WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM SharedRepo WHERE repo_id = ?",
                             1, "string", repo_id);

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM RepoGroup WHERE repo_id = ?",
                             1, "string", repo_id);

    if (!seaf->cloud_mode) {
        seaf_db_statement_query (mgr->seaf->db, "DELETE FROM InnerPubRepo WHERE repo_id = ?",
                                 1, "string", repo_id);
    }

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM RepoUserToken WHERE repo_id = ?",
                             1, "string", repo_id);

    /* Remove virtual repos when origin repo is deleted. */
    GList *vrepos, *ptr;
    vrepos = seaf_repo_manager_get_virtual_repo_ids_by_origin (mgr, repo_id);
    for (ptr = vrepos; ptr != NULL; ptr = ptr->next)
        remove_virtual_repo_ondisk (mgr, (char *)ptr->data);
    string_list_free (vrepos);

    seaf_db_statement_query (mgr->seaf->db, "DELETE FROM VirtualRepo "
                             "WHERE repo_id=? OR origin_repo=?",
                             2, "string", repo_id, "string", repo_id);

    return 0;
}

int
seaf_repo_manager_del_virtual_repo (SeafRepoManager *mgr,
                                    const char *repo_id)
{
    return remove_virtual_repo_ondisk (mgr, repo_id);
}

static gboolean
repo_exists_in_db (SeafDB *db, const char *id, gboolean *db_err)
{
    return seaf_db_statement_exists (db,
                                     "SELECT repo_id FROM Repo WHERE repo_id = ?",
                                     db_err, 1, "string", id);
}

gboolean
create_repo_fill_size (SeafDBRow *row, void *data)
{
    SeafRepo **repo = data;

    const char *repo_id = seaf_db_row_get_column_text (row, 0);
    gint64 size = seaf_db_row_get_column_int64 (row, 1);

    *repo = seaf_repo_new (repo_id, NULL, NULL);
    if (!*repo)
        return FALSE;

    (*repo)->size = size;

    return TRUE;
}

static SeafRepo*
get_repo_from_db (SeafRepoManager *mgr, const char *id, gboolean *db_err)
{
    SeafRepo *repo = NULL;
    const char *sql = "SELECT r.repo_id, s.size FROM Repo r left join RepoSize s "
                      "ON r.repo_id = s.repo_id WHERE r.repo_id = ?";

    int ret = seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                             create_repo_fill_size, &repo,
                                             1, "string", id);
    if (ret < 0)
        *db_err = TRUE;

    return repo;
}

SeafRepo*
seaf_repo_manager_get_repo (SeafRepoManager *manager, const gchar *id)
{
    int len = strlen(id);
    gboolean db_err = FALSE;
    SeafRepo *repo = NULL;

    if (len >= 37)
        return NULL;

    repo = get_repo_from_db (manager, id, &db_err);

    if (repo) {
        load_repo (manager, repo);
        if (repo->is_corrupted) {
            seaf_repo_unref (repo);
            return NULL;
        }
    }

    return repo;
}

SeafRepo*
seaf_repo_manager_get_repo_ex (SeafRepoManager *manager, const gchar *id)
{
    int len = strlen(id);
    gboolean db_err = FALSE;
    SeafRepo *ret = NULL;

    if (len >= 37)
        return NULL;

    ret = get_repo_from_db (manager, id, &db_err);
    if (db_err) {
        ret = seaf_repo_new(id, NULL, NULL);
        ret->is_corrupted = TRUE;
        return ret;
    }

    if (ret) {
        load_repo (manager, ret);
    }

    return ret;
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
    if (seaf_db_type(seaf->db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;
        int rc;

        exists = seaf_db_statement_exists (seaf->db,
                                           "SELECT repo_id FROM RepoHead WHERE repo_id=?",
                                           &err, 1, "string", branch->repo_id);
        if (err)
            return -1;

        if (exists)
            rc = seaf_db_statement_query (seaf->db,
                                          "UPDATE RepoHead SET branch_name=? "
                                          "WHERE repo_id=?",
                                          2, "string", branch->name,
                                          "string", branch->repo_id);
        else
            rc = seaf_db_statement_query (seaf->db,
                                          "INSERT INTO RepoHead VALUES (?, ?)",
                                          2, "string", branch->repo_id,
                                          "string", branch->name);
        return rc;
    } else {
        return seaf_db_statement_query (seaf->db,
                                        "REPLACE INTO RepoHead VALUES (?, ?)",
                                        2, "string", branch->repo_id,
                                        "string", branch->name);
    }

    return -1;
}

int
seaf_repo_manager_branch_repo_unmap (SeafRepoManager *manager, SeafBranch *branch)
{
    return seaf_db_statement_query (seaf->db,
                                    "DELETE FROM RepoHead WHERE branch_name = ?"
                                    " AND repo_id = ?",
                                    2, "string", branch->name,
                                    "string", branch->repo_id);
}

static void
load_repo_commit (SeafRepoManager *manager,
                  SeafRepo *repo,
                  SeafBranch *branch)
{
    SeafCommit *commit;

    commit = seaf_commit_manager_get_commit_compatible (manager->seaf->commit_mgr,
                                                        repo->id,
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

static void
load_repo (SeafRepoManager *manager, SeafRepo *repo)
{
    SeafBranch *branch;

    repo->manager = manager;

    branch = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "master");
    if (!branch) {
        g_warning ("Failed to get master branch of repo %.8s.\n", repo->id);
        repo->is_corrupted = TRUE;
    } else {
        load_repo_commit (manager, repo, branch);
        seaf_branch_unref (branch);
    }

    if (repo->is_corrupted) {
        return;
    }

    /* Load virtual repo info if any. */
    repo->virtual_info = seaf_repo_manager_get_virtual_repo_info (manager, repo->id);
    if (repo->virtual_info)
        memcpy (repo->store_id, repo->virtual_info->origin_repo_id, 36);
    else
        memcpy (repo->store_id, repo->id, 36);
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

    sql = "CREATE TABLE IF NOT EXISTS InnerPubRepo ("
        "repo_id CHAR(37) PRIMARY KEY,"
        "permission CHAR(15))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoUserToken ("
        "repo_id CHAR(37), "
        "email VARCHAR(255), "
        "token CHAR(41), "
        "UNIQUE INDEX (repo_id, token), INDEX (email))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoTokenPeerInfo ("
        "token CHAR(41) PRIMARY KEY, "
        "peer_id CHAR(41), "
        "peer_ip VARCHAR(41), "
        "peer_name VARCHAR(255), "
        "sync_time BIGINT)";
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

    sql = "CREATE TABLE IF NOT EXISTS VirtualRepo (repo_id CHAR(36) PRIMARY KEY,"
        "origin_repo CHAR(36), path TEXT, base_commit CHAR(40), INDEX(origin_repo))"
        "ENGINE=INNODB";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS GarbageRepos (repo_id CHAR(36) PRIMARY KEY)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoTrash (repo_id CHAR(36) PRIMARY KEY,"
        "repo_name VARCHAR(255), head_id CHAR(40), owner_id VARCHAR(255),"
        "size BIGINT(20), org_id INTEGER, del_time BIGINT, "
        "INDEX(owner_id), INDEX(org_id))ENGINE=INNODB";
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

    sql = "CREATE TABLE IF NOT EXISTS InnerPubRepo ("
        "repo_id CHAR(37) PRIMARY KEY,"
        "permission CHAR(15))";
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

    sql = "CREATE INDEX IF NOT EXISTS repo_token_email_indx on "
        "RepoUserToken (email)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoTokenPeerInfo ("
        "token CHAR(41) PRIMARY KEY, "
        "peer_id CHAR(41), "
        "peer_ip VARCHAR(41), "
        "peer_name VARCHAR(255), "
        "sync_time BIGINT)";
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

    sql = "CREATE TABLE IF NOT EXISTS VirtualRepo (repo_id CHAR(36) PRIMARY KEY,"
        "origin_repo CHAR(36), path TEXT, base_commit CHAR(40))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS virtualrepo_origin_repo_idx "
        "ON VirtualRepo (origin_repo)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS GarbageRepos (repo_id CHAR(36) PRIMARY KEY)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoTrash (repo_id CHAR(36) PRIMARY KEY,"
        "repo_name VARCHAR(255), head_id CHAR(40), owner_id VARCHAR(255), size BIGINT UNSIGNED,"
        "org_id INTEGER, del_time BIGINT)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS repotrash_owner_id_idx ON RepoTrash(owner_id)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS repotrash_org_id_idx ON RepoTrash(org_id)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    return 0;
}

static int
create_tables_pgsql (SeafRepoManager *mgr)
{
    SeafDB *db = mgr->seaf->db;
    char *sql;

    sql = "CREATE TABLE IF NOT EXISTS Repo (repo_id CHAR(36) PRIMARY KEY)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoOwner ("
        "repo_id CHAR(36) PRIMARY KEY, "
        "owner_id VARCHAR(255))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    if (!pgsql_index_exists (db, "repoowner_owner_idx")) {
        sql = "CREATE INDEX repoowner_owner_idx ON RepoOwner (owner_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    sql = "CREATE TABLE IF NOT EXISTS RepoGroup (repo_id CHAR(36), "
        "group_id INTEGER, user_name VARCHAR(255), permission VARCHAR(15), "
        "UNIQUE (group_id, repo_id))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    if (!pgsql_index_exists (db, "repogroup_repoid_idx")) {
        sql = "CREATE INDEX repogroup_repoid_idx ON RepoGroup (repo_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    if (!pgsql_index_exists (db, "repogroup_username_idx")) {
        sql = "CREATE INDEX repogroup_username_idx ON RepoGroup (user_name)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    sql = "CREATE TABLE IF NOT EXISTS InnerPubRepo ("
        "repo_id CHAR(36) PRIMARY KEY,"
        "permission VARCHAR(15))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoUserToken ("
        "repo_id CHAR(36), "
        "email VARCHAR(255), "
        "token CHAR(40), "
        "UNIQUE (repo_id, token))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    if (!pgsql_index_exists (db, "repousertoken_email_idx")) {
        sql = "CREATE INDEX repousertoken_email_idx ON RepoUserToken (email)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    sql = "CREATE TABLE IF NOT EXISTS RepoTokenPeerInfo ("
        "token CHAR(40) PRIMARY KEY, "
        "peer_id CHAR(40), "
        "peer_ip VARCHAR(40), "
        "peer_name VARCHAR(255), "
        "sync_time BIGINT)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoHead ("
        "repo_id CHAR(36) PRIMARY KEY, branch_name VARCHAR(10))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoSize ("
        "repo_id CHAR(36) PRIMARY KEY,"
        "size BIGINT,"
        "head_id CHAR(40))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoHistoryLimit ("
        "repo_id CHAR(36) PRIMARY KEY, days INTEGER)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoValidSince ("
        "repo_id CHAR(36) PRIMARY KEY, timestamp BIGINT)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS WebAP (repo_id CHAR(36) PRIMARY KEY, "
        "access_property VARCHAR(10))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS VirtualRepo (repo_id CHAR(36) PRIMARY KEY,"
        "origin_repo CHAR(36), path TEXT, base_commit CHAR(40))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    if (!pgsql_index_exists (db, "virtualrepo_origin_repo_idx")) {
        sql = "CREATE INDEX virtualrepo_origin_repo_idx ON VirtualRepo (origin_repo)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    sql = "CREATE TABLE IF NOT EXISTS GarbageRepos (repo_id CHAR(36) PRIMARY KEY)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS RepoTrash (repo_id CHAR(36) PRIMARY KEY,"
        "repo_name VARCHAR(255), head_id CHAR(40), owner_id VARCHAR(255), size bigint,"
        "org_id INTEGER, del_time BIGINT)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    if (!pgsql_index_exists (db, "repotrash_owner_id")) {
        sql = "CREATE INDEX repotrash_owner_id on RepoTrash(owner_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }
    if (!pgsql_index_exists (db, "repotrash_org_id")) {
        sql = "CREATE INDEX repotrash_org_id on RepoTrash(org_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

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
    else if (db_type == SEAF_DB_TYPE_PGSQL)
        return create_tables_pgsql (mgr);

    g_return_val_if_reached (-1);
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

static int
add_repo_token (SeafRepoManager *mgr,
                const char *repo_id,
                const char *email,
                const char *token,
                GError **error)
{
    int rc = seaf_db_statement_query (mgr->seaf->db,
                                      "INSERT INTO RepoUserToken VALUES (?, ?, ?)",
                                      3, "string", repo_id, "string", email,
                                      "string", token);

    if (rc < 0) {
        seaf_warning ("failed to add repo token. repo = %s, email = %s\n",
                      repo_id, email);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
        return -1;
    }

    return 0;
}

char *
seaf_repo_manager_generate_repo_token (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *email,
                                       GError **error)
{
    char *token = generate_repo_token ();
    if (add_repo_token (mgr, repo_id, email, token, error) < 0) {
        g_free (token);        
        return NULL;
    }

    return token;
}

int
seaf_repo_manager_add_token_peer_info (SeafRepoManager *mgr,
                                       const char *token,
                                       const char *peer_id,
                                       const char *peer_ip,
                                       const char *peer_name,
                                       gint64 sync_time)
{
    int ret = 0;

    if (seaf_db_statement_query (mgr->seaf->db,
                                 "INSERT INTO RepoTokenPeerInfo VALUES ("
                                 "?, ?, ?, ?, ?)",
                                 5, "string", token,
                                 "string", peer_id,
                                 "string", peer_ip,
                                 "string", peer_name,
                                 "int64", sync_time) < 0)
        ret = -1;

    return ret;
}

int
seaf_repo_manager_update_token_peer_info (SeafRepoManager *mgr,
                                          const char *token,
                                          const char *peer_ip,
                                          gint64 sync_time)
{
    int ret = 0;

    if (seaf_db_statement_query (mgr->seaf->db,
                                 "UPDATE RepoTokenPeerInfo SET "
                                 "peer_ip=?, sync_time=? WHERE token=?",
                                 3, "string", peer_ip,
                                 "int64", sync_time,
                                 "string", token) < 0)
        ret = -1;

    return ret;
}

gboolean
seaf_repo_manager_token_peer_info_exists (SeafRepoManager *mgr,
                                          const char *token)
{
    gboolean db_error = FALSE;

    return seaf_db_statement_exists (mgr->seaf->db,
                                     "SELECT token FROM RepoTokenPeerInfo WHERE token=?",
                                     &db_error, 1, "string", token);
}

int
seaf_repo_manager_delete_token (SeafRepoManager *mgr,
                                const char *repo_id,
                                const char *token,
                                const char *user,
                                GError **error)
{
    char *token_owner;

    token_owner = seaf_repo_manager_get_email_by_token (mgr, repo_id, token);
    if (!token_owner || strcmp (user, token_owner) != 0) {
        seaf_warning ("Requesting user is %s, token owner is %s, "
                      "refuse to delete token %.10s.\n", user, token_owner, token);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Permission denied");
        return -1;
    }

    if (seaf_db_statement_query (mgr->seaf->db,
                                 "DELETE FROM RepoUserToken "
                                 "WHERE repo_id=? and token=?",
                                 2, "string", repo_id, "string", token) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
        return -1;
    }

    if (seaf_db_statement_query (mgr->seaf->db,
                                 "DELETE FROM RepoTokenPeerInfo WHERE token=?",
                                 1, "string", token) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
        return -1;
    }

    GList *tokens = NULL;
    tokens = g_list_append (tokens, g_strdup(token));
    seaf_http_server_invalidate_tokens (seaf->http_server, tokens);
    g_list_free_full (tokens, (GDestroyNotify)g_free);

    return 0;
}

static gboolean
collect_repo_token (SeafDBRow *row, void *data)
{
    GList **ret_list = data;
    const char *repo_id, *repo_owner, *email, *token;
    const char *peer_id, *peer_ip, *peer_name;
    gint64 sync_time;

    repo_id = seaf_db_row_get_column_text (row, 0);
    repo_owner = seaf_db_row_get_column_text (row, 1);
    email = seaf_db_row_get_column_text (row, 2);
    token = seaf_db_row_get_column_text (row, 3);

    peer_id = seaf_db_row_get_column_text (row, 4);
    peer_ip = seaf_db_row_get_column_text (row, 5);
    peer_name = seaf_db_row_get_column_text (row, 6);
    sync_time = seaf_db_row_get_column_int64 (row, 7);

    char *owner_l = g_ascii_strdown (repo_owner, -1);
    char *email_l = g_ascii_strdown (email, -1);

    SeafileRepoTokenInfo *repo_token_info;
    repo_token_info = g_object_new (SEAFILE_TYPE_REPO_TOKEN_INFO,
                                    "repo_id", repo_id,
                                    "repo_owner", owner_l,
                                    "email", email_l,
                                    "token", token,
                                    "peer_id", peer_id,
                                    "peer_ip", peer_ip,
                                    "peer_name", peer_name,
                                    "sync_time", sync_time,
                                    NULL);

    *ret_list = g_list_prepend (*ret_list, repo_token_info);
    
    return TRUE;
}

static void
fill_in_token_info (GList *info_list)
{
    GList *ptr;
    SeafileRepoTokenInfo *info;
    SeafRepo *repo;
    char *repo_name;

    for (ptr = info_list; ptr; ptr = ptr->next) {
        info = ptr->data;
        repo = seaf_repo_manager_get_repo (seaf->repo_mgr,
                                           seafile_repo_token_info_get_repo_id(info));
        if (repo)
            repo_name = g_strdup(repo->name);
        else
            repo_name = g_strdup("Unknown");
        seaf_repo_unref (repo);

        g_object_set (info, "repo_name", repo_name, NULL);
        g_free (repo_name);
    }
}

GList *
seaf_repo_manager_list_repo_tokens (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    GError **error)
{
    GList *ret_list = NULL;
    char *sql;
    gboolean db_err = FALSE;

    if (!repo_exists_in_db (mgr->seaf->db, repo_id, &db_err)) {
        if (db_err) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
        }
        return NULL;
    }

    sql = "SELECT u.repo_id, o.owner_id, u.email, u.token, "
        "p.peer_id, p.peer_ip, p.peer_name, p.sync_time "
        "FROM RepoUserToken u LEFT JOIN RepoTokenPeerInfo p "
        "ON u.token = p.token, RepoOwner o "
        "WHERE u.repo_id = ? and o.repo_id = ? ";

    int n_row = seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                              collect_repo_token, &ret_list,
                                              2, "string", repo_id,
                                              "string", repo_id);
    if (n_row < 0) {
        seaf_warning ("DB error when get token info for repo %.10s.\n",
                      repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
    }

    fill_in_token_info (ret_list);

    return g_list_reverse(ret_list);
}

GList *
seaf_repo_manager_list_repo_tokens_by_email (SeafRepoManager *mgr,
                                             const char *email,
                                             GError **error)
{
    GList *ret_list = NULL;
    char *sql;

    sql = "SELECT u.repo_id, o.owner_id, u.email, u.token, "
        "p.peer_id, p.peer_ip, p.peer_name, p.sync_time "
        "FROM RepoUserToken u LEFT JOIN RepoTokenPeerInfo p "
        "ON u.token = p.token, RepoOwner o "
        "WHERE u.email = ? and u.repo_id = o.repo_id";

    int n_row = seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                              collect_repo_token, &ret_list,
                                              1, "string", email);
    if (n_row < 0) {
        seaf_warning ("DB error when get token info for email %s.\n",
                      email);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
    }

    fill_in_token_info (ret_list);

    return g_list_reverse(ret_list);
}

static gboolean
collect_token_list (SeafDBRow *row, void *data)
{
    GList **p_tokens = data;
    const char *token;

    token = seaf_db_row_get_column_text (row, 0);
    *p_tokens = g_list_prepend (*p_tokens, g_strdup(token));

    return TRUE;
}

/**
 * Delete all repo tokens for a given user on a given client
 */

int
seaf_repo_manager_delete_repo_tokens_by_peer_id (SeafRepoManager *mgr,
                                                 const char *email,
                                                 const char *peer_id,
                                                 GList **tokens,
                                                 GError **error)
{
    int ret = 0;
    const char *template;
    GList *token_list = NULL;
    GString *token_list_str = g_string_new ("");
    GString *sql = g_string_new ("");
    GList *ptr;
    int rc = 0;

    template = "SELECT u.token "
        "FROM RepoUserToken as u, RepoTokenPeerInfo as p "
        "WHERE u.token = p.token "
        "AND u.email = ? AND p.peer_id = ?";
    rc = seaf_db_statement_foreach_row (mgr->seaf->db, template,
                                        collect_token_list, &token_list,
                                        2, "string", email, "string", peer_id);
    if (rc < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
        goto out;
    }

    if (rc == 0)
        goto out;

    for (ptr = token_list; ptr; ptr = ptr->next) {
        const char *token = (char *)ptr->data;
        if (token_list_str->len == 0)
            g_string_append_printf (token_list_str, "'%s'", token);
        else
            g_string_append_printf (token_list_str, ",'%s'", token);
    }

    /* Note that there is a size limit on sql query. In MySQL it's 1MB by default.
     * Normally the token_list won't be that long.
     */
    g_string_printf (sql, "DELETE FROM RepoUserToken WHERE token in (%s)",
                     token_list_str->str);
    rc = seaf_db_statement_query (mgr->seaf->db, sql->str, 0);
    if (rc < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
        goto out;
    }

    g_string_printf (sql, "DELETE FROM RepoTokenPeerInfo WHERE token in (%s)",
                     token_list_str->str);
    rc = seaf_db_statement_query (mgr->seaf->db, sql->str, 0);
    if (rc < 0)
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");

out:
    g_string_free (token_list_str, TRUE);
    g_string_free (sql, TRUE);

    if (rc < 0) {
        ret = -1;
        g_list_free_full (token_list, (GDestroyNotify)g_free);
    } else {
        *tokens = token_list;
    }

    return ret;
}

int
seaf_repo_manager_delete_repo_tokens_by_email (SeafRepoManager *mgr,
                                               const char *email,
                                               GError **error)
{
    int ret = 0;
    const char *template;
    GList *token_list = NULL;
    GList *ptr;
    GString *token_list_str = g_string_new ("");
    GString *sql = g_string_new ("");
    int rc;

    template = "SELECT u.token "
        "FROM RepoUserToken as u, RepoTokenPeerInfo as p "
        "WHERE u.token = p.token "
        "AND u.email = ?";
    rc = seaf_db_statement_foreach_row (mgr->seaf->db, template,
                                        collect_token_list, &token_list,
                                        1, "string", email);
    if (rc < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
        goto out;
    }

    if (rc == 0)
        goto out;

    for (ptr = token_list; ptr; ptr = ptr->next) {
        const char *token = (char *)ptr->data;
        if (token_list_str->len == 0)
            g_string_append_printf (token_list_str, "'%s'", token);
        else
            g_string_append_printf (token_list_str, ",'%s'", token);
    }

    /* Note that there is a size limit on sql query. In MySQL it's 1MB by default.
     * Normally the token_list won't be that long.
     */
    g_string_printf (sql, "DELETE FROM RepoUserToken WHERE token in (%s)",
                     token_list_str->str);
    rc = seaf_db_statement_query (mgr->seaf->db, sql->str, 0);
    if (rc < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
        goto out;
    }

    g_string_printf (sql, "DELETE FROM RepoTokenPeerInfo WHERE token in (%s)",
                     token_list_str->str);
    rc = seaf_db_statement_query (mgr->seaf->db, sql->str, 0);
    if (rc < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "DB error");
        goto out;
    }

    seaf_http_server_invalidate_tokens (seaf->http_server, token_list);

out:
    g_string_free (token_list_str, TRUE);
    g_string_free (sql, TRUE);
    g_list_free_full (token_list, (GDestroyNotify)g_free);

    if (rc < 0) {
        ret = -1;
    }

    return ret;
}

static gboolean
get_email_by_token_cb (SeafDBRow *row, void *data)
{
    char **email_ptr = data;

    const char *email = (const char *) seaf_db_row_get_column_text (row, 0);
    *email_ptr = g_ascii_strdown (email, -1);
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
    char *sql;

    sql = "SELECT email FROM RepoUserToken "
        "WHERE repo_id = ? AND token = ?";

    seaf_db_statement_foreach_row (seaf->db, sql,
                                   get_email_by_token_cb, &email,
                                   2, "string", repo_id, "string", token);

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
    char *sql;

    sql = "SELECT size FROM RepoSize WHERE repo_id=?";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       get_repo_size, &size,
                                       1, "string", repo_id) < 0)
        return -1;

    return size;
}

int
seaf_repo_manager_set_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id,
                                          int days)
{
    SeafVirtRepo *vinfo;
    SeafDB *db = mgr->seaf->db;

    vinfo = seaf_repo_manager_get_virtual_repo_info (mgr, repo_id);
    if (vinfo) {
        seaf_virtual_repo_info_free (vinfo);
        return 0;
    }

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;
        int rc;

        exists = seaf_db_statement_exists (db,
                                           "SELECT repo_id FROM RepoHistoryLimit "
                                           "WHERE repo_id=?",
                                           &err, 1, "string", repo_id);
        if (err)
            return -1;

        if (exists)
            rc = seaf_db_statement_query (db,
                                          "UPDATE RepoHistoryLimit SET days=%d"
                                          "WHERE repo_id=?",
                                          2, "int", days, "string", repo_id);
        else
            rc = seaf_db_statement_query (db,
                                          "INSERT INTO RepoHistoryLimit VALUES "
                                          "(?, ?)",
                                          2, "string", repo_id, "int", days);
        return rc;
    } else {
        if (seaf_db_statement_query (db,
                                     "REPLACE INTO RepoHistoryLimit VALUES (?, ?)",
                                     2, "string", repo_id, "int", days) < 0)
            return -1;
    }

    return 0;
}

int
seaf_repo_manager_get_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id)
{
    SeafVirtRepo *vinfo;
    const char *r_repo_id = repo_id;
    char *sql;
    int per_repo_days;

    vinfo = seaf_repo_manager_get_virtual_repo_info (mgr, repo_id);
    if (vinfo)
        r_repo_id = vinfo->origin_repo_id;

    sql = "SELECT days FROM RepoHistoryLimit WHERE repo_id=?";
    per_repo_days = seaf_db_statement_get_int (mgr->seaf->db, sql,
                                               1, "string", r_repo_id);

    seaf_virtual_repo_info_free (vinfo);

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
    SeafDB *db = mgr->seaf->db;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;
        int rc;

        exists = seaf_db_statement_exists (db,
                                           "SELECT repo_id FROM RepoValidSince WHERE "
                                           "repo_id=?", &err, 1, "string", repo_id);
        if (err)
            return -1;

        if (exists)
            rc = seaf_db_statement_query (db,
                                          "UPDATE RepoValidSince SET timestamp=?"
                                          " WHERE repo_id=?",
                                          2, "int64", timestamp, "string", repo_id);
        else
            rc = seaf_db_statement_query (db,
                                          "INSERT INTO RepoValidSince VALUES "
                                          "(?, ?)", 2, "string", repo_id,
                                          "int64", timestamp);
        if (rc < 0)
            return -1;
    } else {
        if (seaf_db_statement_query (db,
                           "REPLACE INTO RepoValidSince VALUES (?, ?)",
                           2, "string", repo_id, "int64", timestamp) < 0)
            return -1;
    }

    return 0;
}

gint64
seaf_repo_manager_get_repo_valid_since (SeafRepoManager *mgr,
                                        const char *repo_id)
{
    char *sql;

    sql = "SELECT timestamp FROM RepoValidSince WHERE repo_id=?";
    /* Also return -1 if doesn't exist. */
    return seaf_db_statement_get_int64 (mgr->seaf->db, sql, 1, "string", repo_id);
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
    SeafDB *db = mgr->seaf->db;
    char sql[256];

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean err;
        snprintf(sql, sizeof(sql),
                 "SELECT repo_id FROM RepoOwner WHERE repo_id='%s'", repo_id);
        if (seaf_db_check_for_existence(db, sql, &err))
            snprintf(sql, sizeof(sql),
                     "UPDATE RepoOwner SET owner_id='%s' WHERE "
                     "repo_id='%s'", email, repo_id);
        else
            snprintf(sql, sizeof(sql),
                     "INSERT INTO RepoOwner VALUES ('%s', '%s')",
                     repo_id, email);
        if (err)
            return -1;
        if (seaf_db_query (db, sql) < 0)
            return -1;
    } else {
        if (seaf_db_statement_query (db, "REPLACE INTO RepoOwner VALUES (?, ?)",
                                     2, "string", repo_id, "string", email) < 0)
            return -1;
    }

    return 0;
}

static gboolean
get_owner (SeafDBRow *row, void *data)
{
    char **owner_id = data;

    const char *owner = (const char *) seaf_db_row_get_column_text (row, 0);
    *owner_id = g_ascii_strdown (owner, -1);
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_repo_owner (SeafRepoManager *mgr,
                                  const char *repo_id)
{
    char *sql;
    char *ret = NULL;

    sql = "SELECT owner_id FROM RepoOwner WHERE repo_id=?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       get_owner, &ret,
                                       1, "string", repo_id) < 0) {
        seaf_warning ("Failed to get owner id for repo %s.\n", repo_id);
        return NULL;
    }

    return ret;
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
seaf_repo_manager_get_orphan_repo_list (SeafRepoManager *mgr)
{
    GList *id_list = NULL, *ptr;
    GList *ret = NULL;
    char sql[256];

    snprintf (sql, sizeof(sql), "SELECT Repo.repo_id FROM Repo LEFT JOIN "
              "RepoOwner ON Repo.repo_id = RepoOwner.repo_id WHERE "
              "RepoOwner.owner_id is NULL");

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      collect_repo_id, &id_list) < 0)
        return NULL;

    for (ptr = id_list; ptr; ptr = ptr->next) {
        char *repo_id = ptr->data;
        SeafRepo *repo = seaf_repo_manager_get_repo (mgr, repo_id);
        if (repo != NULL)
            ret = g_list_prepend (ret, repo);
    }

    string_list_free (id_list);

    return ret;
}

GList *
seaf_repo_manager_get_repos_by_owner (SeafRepoManager *mgr,
                                      const char *email)
{
    GList *id_list = NULL, *ptr;
    GList *ret = NULL;
    char *sql;

    sql = "SELECT repo_id FROM RepoOwner WHERE owner_id=?";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, 
                                       collect_repo_id, &id_list,
                                       1, "string", email) < 0)
        return NULL;

    for (ptr = id_list; ptr; ptr = ptr->next) {
        char *repo_id = ptr->data;
        SeafRepo *repo = seaf_repo_manager_get_repo (mgr, repo_id);
        if (repo != NULL)
            ret = g_list_prepend (ret, repo);
    }

    string_list_free (id_list);

    return ret;
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
    GList *id_list = NULL, *ptr;
    GList *ret = NULL;
    SeafRepo *repo;
    int rc;

    if (start == -1 && limit == -1)
        rc = seaf_db_statement_foreach_row (mgr->seaf->db,
                                       "SELECT repo_id FROM Repo",
                                       collect_repo_id, &id_list,
                                       0);
    else
        rc = seaf_db_statement_foreach_row (mgr->seaf->db,
                                            "SELECT repo_id FROM Repo "
                                            "ORDER BY repo_id LIMIT ? OFFSET ?",
                                            collect_repo_id, &id_list,
                                            2, "int", limit, "int", start);

    if (rc < 0)
        return NULL;

    for (ptr = id_list; ptr; ptr = ptr->next) {
        char *repo_id = ptr->data;
        repo = seaf_repo_manager_get_repo_ex (mgr, repo_id);
        if (repo != NULL)
            ret = g_list_prepend (ret, repo);
    }

    string_list_free (id_list);

    return ret;
}

gint64
seaf_repo_manager_count_repos (SeafRepoManager *mgr, GError **error)
{
    gint64 num = seaf_db_get_int64 (mgr->seaf->db,
                                    "SELECT COUNT(repo_id) FROM Repo");
    if (num < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to count repos from db");
    }

    return num;
}

GList *
seaf_repo_manager_get_repo_ids_by_owner (SeafRepoManager *mgr,
                                         const char *email)
{
    GList *ret = NULL;
    char *sql;

    sql = "SELECT repo_id FROM RepoOwner WHERE owner_id=?";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, 
                                       collect_repo_id, &ret,
                                       1, "string", email) < 0) {
        string_list_free (ret);
        return NULL;
    }

    return ret;
}

static gboolean
collect_trash_repo (SeafDBRow *row, void *data)
{
    GList **trash_repos = data;
    const char *repo_id;
    const char *repo_name;
    const char *head_id;
    const char *owner_id;
    gint64 size;
    gint64 del_time;

    repo_id = seaf_db_row_get_column_text (row, 0);
    repo_name = seaf_db_row_get_column_text (row, 1);
    head_id = seaf_db_row_get_column_text (row, 2);
    owner_id = seaf_db_row_get_column_text (row, 3);
    size = seaf_db_row_get_column_int64 (row, 4);
    del_time = seaf_db_row_get_column_int64 (row, 5);


    if (!repo_id || !repo_name || !head_id || !owner_id)
        return FALSE;

    SeafileTrashRepo *trash_repo = g_object_new (SEAFILE_TYPE_TRASH_REPO,
                                                 "repo_id", repo_id,
                                                 "repo_name", repo_name,
                                                 "head_id", head_id,
                                                 "owner_id", owner_id,
                                                 "size", size,
                                                 "del_time", del_time,
                                                 NULL);
    if (!trash_repo)
        return FALSE;

    *trash_repos = g_list_prepend (*trash_repos, trash_repo);

    return TRUE;
}

GList *
seaf_repo_manager_get_trash_repo_list (SeafRepoManager *mgr,
                                       int start,
                                       int limit,
                                       GError **error)
{
    GList *trash_repos = NULL;
    int rc;

    if (start == -1 && limit == -1)
        rc = seaf_db_statement_foreach_row (mgr->seaf->db,
                                            "SELECT repo_id, repo_name, head_id, owner_id, "
                                            "size, del_time FROM RepoTrash",
                                            collect_trash_repo, &trash_repos,
                                            0);
    else
        rc = seaf_db_statement_foreach_row (mgr->seaf->db,
                                            "SELECT repo_id, repo_name, head_id, owner_id, "
                                            "size, del_time FROM RepoTrash "
                                            "ORDER BY repo_id LIMIT ? OFFSET ?",
                                            collect_trash_repo, &trash_repos,
                                            2, "int", limit, "int", start);

    if (rc < 0) {
        while (trash_repos) {
            g_object_unref (trash_repos->data);
            trash_repos = g_list_delete_link (trash_repos, trash_repos);
        }
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get trashed repo from db.");
        return NULL;
    }

    return trash_repos;
}

GList *
seaf_repo_manager_get_trash_repos_by_owner (SeafRepoManager *mgr,
                                            const char *owner,
                                            GError **error)
{
    GList *trash_repos = NULL;
    int rc;

    rc = seaf_db_statement_foreach_row (mgr->seaf->db,
                                        "SELECT repo_id, repo_name, head_id, owner_id, "
                                        "size, del_time FROM RepoTrash WHERE owner_id = ?",
                                        collect_trash_repo, &trash_repos,
                                        1, "string", owner);

    if (rc < 0) {
        while (trash_repos) {
            g_object_unref (trash_repos->data);
            trash_repos = g_list_delete_link (trash_repos, trash_repos);
        }
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get trashed repo from db.");
        return NULL;
    }

    return trash_repos;
}

SeafileTrashRepo *
seaf_repo_manager_get_repo_from_trash (SeafRepoManager *mgr,
                                       const char *repo_id)
{
    SeafileTrashRepo *ret = NULL;
    GList *trash_repos = NULL;
    char *sql;
    int rc;

    sql = "SELECT repo_id, repo_name, head_id, owner_id, size FROM RepoTrash "
        "WHERE repo_id = ?";
    rc = seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                        collect_trash_repo, &trash_repos,
                                        1, "string", repo_id);
    if (rc < 0)
        return NULL;

    /* There should be only one results, since repo_id is a PK. */
    ret = trash_repos->data;

    g_list_free (trash_repos);
    return ret;
}

int
seaf_repo_manager_del_repo_from_trash (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       GError **error)
{
    int ret = 0;

    /* As long as the repo is successfully moved into GarbageRepo table,
     * we consider this operation successful.
     */
    if (add_deleted_repo_record (mgr, repo_id) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "DB error: Add deleted record");
        return -1;
    }

    /* remove branch */
    GList *p;
    GList *branch_list = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo_id);
    for (p = branch_list; p; p = p->next) {
        SeafBranch *b = (SeafBranch *)p->data;
        seaf_repo_manager_branch_repo_unmap (mgr, b);
        seaf_branch_manager_del_branch (seaf->branch_mgr, repo_id, b->name);
    }
    seaf_branch_list_free (branch_list);

    seaf_db_statement_query (mgr->seaf->db,
                             "DELETE FROM RepoTrash WHERE repo_id = ?",
                             1, "string", repo_id);

    return 0;
}

int
seaf_repo_manager_empty_repo_trash (SeafRepoManager *mgr, GError **error)
{
    GList *trash_repos = NULL, *ptr;
    SeafileTrashRepo *repo;

    trash_repos = seaf_repo_manager_get_trash_repo_list (mgr, -1, -1, error);
    if (*error)
        return -1;

    for (ptr = trash_repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        seaf_repo_manager_del_repo_from_trash (mgr,
                                               seafile_trash_repo_get_repo_id(repo),
                                               NULL);
        g_object_unref (repo);
    }

    g_list_free (trash_repos);
    return 0;
}

int
seaf_repo_manager_empty_repo_trash_by_owner (SeafRepoManager *mgr,
                                             const char *owner,
                                             GError **error)
{
    GList *trash_repos = NULL, *ptr;
    SeafileTrashRepo *repo;

    trash_repos = seaf_repo_manager_get_trash_repos_by_owner (mgr, owner, error);
    if (*error)
        return -1;

    for (ptr = trash_repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        seaf_repo_manager_del_repo_from_trash (mgr,
                                               seafile_trash_repo_get_repo_id(repo),
                                               NULL);
        g_object_unref (repo);
    }

    g_list_free (trash_repos);
    return 0;
}

int
seaf_repo_manager_restore_repo_from_trash (SeafRepoManager *mgr,
                                           const char *repo_id,
                                           GError **error)
{
    SeafileTrashRepo *repo = NULL;
    int ret = 0;
    gboolean exists = FALSE;
    gboolean db_err;

    repo = seaf_repo_manager_get_repo_from_trash (mgr, repo_id);
    if (!repo) {
        seaf_warning ("Repo %.8s not found in trash.\n", repo_id);
        return -1;
    }

    SeafDBTrans *trans = seaf_db_begin_transaction (mgr->seaf->db);

    exists = seaf_db_trans_check_for_existence (trans,
                                                "SELECT 1 FROM Repo WHERE repo_id=?",
                                                &db_err, 1, "string", repo_id);

    if (!exists) {
        ret = seaf_db_trans_query (trans,
                                   "INSERT INTO Repo(repo_id) VALUES (?)",
                                   1, "string", repo_id) < 0;
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "DB error: Insert Repo.");
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
            goto out;
        }
    }

    exists = seaf_db_trans_check_for_existence (trans,
                                                "SELECT 1 FROM RepoOwner WHERE repo_id=?",
                                                &db_err, 1, "string", repo_id);

    if (!exists) {
        ret = seaf_db_trans_query (trans,
                                   "INSERT INTO RepoOwner VALUES (?, ?)",
                                   2, "string", repo_id,
                                   "string", seafile_trash_repo_get_owner_id(repo));
        if (ret < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "DB error: Insert Repo Owner.");
            seaf_db_rollback (trans);
            seaf_db_trans_close (trans);
            goto out;
        }
    }

    ret = seaf_db_trans_query (trans,
                               "DELETE FROM RepoTrash WHERE repo_id = ?",
                               1, "string", repo_id);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "DB error: delete from RepoTrash.");
        seaf_db_rollback (trans);
        seaf_db_trans_close (trans);
        goto out;
    }

    if (seaf_db_commit (trans) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "DB error: Failed to commit.");
        seaf_db_rollback (trans);
        ret = -1;
    }

    seaf_db_trans_close (trans);

out:
    g_object_unref (repo);
    return ret;
}

/* Web access permission. */

int
seaf_repo_manager_set_access_property (SeafRepoManager *mgr, const char *repo_id,
                                       const char *ap)
{
    int rc;

    if (seaf_repo_manager_query_access_property (mgr, repo_id) == NULL) {
        rc = seaf_db_statement_query (mgr->seaf->db,
                                      "INSERT INTO WebAP VALUES (?, ?)",
                                      2, "string", repo_id, "string", ap);
    } else {
        rc = seaf_db_statement_query (mgr->seaf->db,
                                      "UPDATE WebAP SET access_property=? "
                                      "WHERE repo_id=?",
                                      2, "string", ap, "string", repo_id);
    }

    if (rc < 0) {
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
    char *sql;
    char *ret = NULL;

    sql =  "SELECT access_property FROM WebAP WHERE repo_id=?";
 
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_ap, &ret,
                                       1, "string", repo_id) < 0) {
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
    if (seaf_db_statement_query (mgr->seaf->db,
                                 "INSERT INTO RepoGroup VALUES (?, ?, ?, ?)",
                                 4, "string", repo_id, "int", group_id,
                                 "string", owner, "string", permission) < 0)
        return -1;

    return 0;
}

int
seaf_repo_manager_del_group_repo (SeafRepoManager *mgr,
                                  const char *repo_id,
                                  int group_id,
                                  GError **error)
{
    return seaf_db_statement_query (mgr->seaf->db,
                                    "DELETE FROM RepoGroup WHERE group_id=? "
                                    "AND repo_id=?",
                                    2, "int", group_id, "string", repo_id);
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
    char *sql;
    GList *group_ids = NULL;
    
    sql =  "SELECT group_id FROM RepoGroup WHERE repo_id = ?";
    
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_ids_cb,
                                       &group_ids, 1, "string", repo_id) < 0) {
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
    char *sql;
    GList *group_perms = NULL, *p;
    
    sql = "SELECT group_id, permission FROM RepoGroup WHERE repo_id = ?";
    
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_perms_cb,
                                       &group_perms, 1, "string", repo_id) < 0) {
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
    return seaf_db_statement_query (mgr->seaf->db,
                                    "UPDATE RepoGroup SET permission=? WHERE "
                                    "repo_id=? AND group_id=?",
                                    3, "string", permission, "string", repo_id,
                                    "int", group_id);
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
    char *sql;
    GList *repo_ids = NULL;

    sql =  "SELECT repo_id FROM RepoGroup WHERE group_id = ?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_repoids_cb,
                                       &repo_ids, 1, "int", group_id) < 0)
        return NULL;

    return g_list_reverse (repo_ids);
}

static gboolean
get_group_repos_cb (SeafDBRow *row, void *data)
{
    GList **p_list = data;
    SeafileRepo *srepo = NULL;

    const char *repo_id = seaf_db_row_get_column_text (row, 0);
    const char *vrepo_id = seaf_db_row_get_column_text (row, 1);
    int group_id = seaf_db_row_get_column_int (row, 2);
    const char *user_name = seaf_db_row_get_column_text (row, 3);
    const char *permission = seaf_db_row_get_column_text (row, 4);
    const char *commit_id = seaf_db_row_get_column_text (row, 5);
    gint64 size = seaf_db_row_get_column_int64 (row, 6);

    char *user_name_l = g_ascii_strdown (user_name, -1);

    srepo = g_object_new (SEAFILE_TYPE_REPO,
                          "share_type", "group",
                          "repo_id", repo_id,
                          "id", repo_id,
                          "head_cmmt_id", commit_id,
                          "group_id", group_id,
                          "user", user_name_l,
                          "permission", permission,
                          "is_virtual", (vrepo_id != NULL),
                          "size", size,
                          NULL);
    g_free (user_name_l);

    if (srepo != NULL) {
        if (vrepo_id) {
            const char *origin_repo_id = seaf_db_row_get_column_text (row, 7);
            const char *origin_path = seaf_db_row_get_column_text (row, 8);
            g_object_set (srepo, "store_id", origin_repo_id,
                          "origin_repo_id", origin_repo_id,
                          "origin_path", origin_path, NULL);
        } else {
            g_object_set (srepo, "store_id", repo_id, NULL);
        }

        *p_list = g_list_prepend (*p_list, srepo);
    }

    return TRUE;
}

void
seaf_fill_repo_obj_from_commit (GList **repos)
{
    SeafileRepo *repo;
    SeafCommit *commit;
    char *repo_id;
    char *commit_id;
    GList *p = *repos;
    GList *next;

    while (p) {
        repo = p->data;
        g_object_get (repo, "repo_id", &repo_id, "head_cmmt_id", &commit_id, NULL);
        commit = seaf_commit_manager_get_commit_compatible (seaf->commit_mgr,
                                                            repo_id, commit_id);
        if (!commit) {
            g_object_unref (repo);
            next = p->next;
            *repos = g_list_delete_link (*repos, p);
            p = next;
        } else {
            g_object_set (repo, "name", commit->repo_name, "desc", commit->repo_desc,
                          "encrypted", commit->encrypted, "magic", commit->magic,
                          "enc_version", commit->enc_version, "root", commit->root_id,
                          "version", commit->version, "last_modify", commit->ctime,
                          "repo_name", commit->repo_name, "repo_desc", commit->repo_desc,
                          "last_modified", commit->ctime, "repaired", commit->repaired, NULL);
            if (commit->encrypted && commit->enc_version == 2)
                g_object_set (repo, "random_key", commit->random_key, NULL);

            p = p->next;
        }
        g_free (repo_id);
        g_free (commit_id);
        seaf_commit_unref (commit);
    }
}

GList *
seaf_repo_manager_get_repos_by_group (SeafRepoManager *mgr,
                                      int group_id,
                                      GError **error)
{
    char *sql;
    GList *repos = NULL;
    GList *p;

    sql = "SELECT RepoGroup.repo_id, VirtualRepo.repo_id, "
        "group_id, user_name, permission, commit_id, s.size, "
        "VirtualRepo.origin_repo, VirtualRepo.path "
        "FROM RepoGroup LEFT JOIN VirtualRepo ON "
        "RepoGroup.repo_id = VirtualRepo.repo_id "
        "LEFT JOIN RepoSize s ON RepoGroup.repo_id = s.repo_id, "
        "Branch WHERE group_id = ? AND "
        "RepoGroup.repo_id = Branch.repo_id AND "
        "Branch.name = 'master'";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_repos_cb,
                                       &repos, 1, "int", group_id) < 0) {
        for (p = repos; p; p = p->next) {
            g_object_unref (p->data);
        }
        g_list_free (repos);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get repos by group from db.");
        return NULL;
    }

    seaf_fill_repo_obj_from_commit (&repos);

    return g_list_reverse (repos);
}

GList *
seaf_repo_manager_get_group_repos_by_owner (SeafRepoManager *mgr,
                                            const char *owner,
                                            GError **error)
{
    char *sql;
    GList *repos = NULL;
    GList *p;

    sql = "SELECT RepoGroup.repo_id, VirtualRepo.repo_id, "
        "group_id, user_name, permission, commit_id, s.size, "
        "VirtualRepo.origin_repo, VirtualRepo.path "
        "FROM RepoGroup LEFT JOIN VirtualRepo ON "
        "RepoGroup.repo_id = VirtualRepo.repo_id "
        "LEFT JOIN RepoSize s ON RepoGroup.repo_id = s.repo_id, "
        "Branch WHERE user_name = ? AND "
        "RepoGroup.repo_id = Branch.repo_id AND "
        "Branch.name = 'master'";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, get_group_repos_cb,
                                       &repos, 1, "string", owner) < 0) {
        for (p = repos; p; p = p->next) {
            g_object_unref (p->data);
        }
        g_list_free (repos);
        return NULL;
    }

    seaf_fill_repo_obj_from_commit (&repos);

    return g_list_reverse (repos);
}

static gboolean
get_group_repo_owner (SeafDBRow *row, void *data)
{
    char **share_from = data;

    const char *owner = (const char *) seaf_db_row_get_column_text (row, 0);
    *share_from = g_ascii_strdown (owner, -1);
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_group_repo_owner (SeafRepoManager *mgr,
                                        const char *repo_id,
                                        GError **error)
{
    char *sql;
    char *ret = NULL;

    sql = "SELECT user_name FROM RepoGroup WHERE repo_id = ?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       get_group_repo_owner, &ret,
                                       1, "string", repo_id) < 0) {
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
    SeafDB *db = mgr->seaf->db;
    int rc;

    if (!owner) {
        rc = seaf_db_statement_query (db, "DELETE FROM RepoGroup WHERE group_id=?",
                                      1, "int", group_id);
    } else {
        rc = seaf_db_statement_query (db,
                                      "DELETE FROM RepoGroup WHERE group_id=? AND "
                                      "user_name = ?",
                                      2, "int", group_id, "string", owner);
    }

    return rc;
}

/* Inner public repos */

int
seaf_repo_manager_set_inner_pub_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      const char *permission)
{
    SeafDB *db = mgr->seaf->db;
    char sql[256];

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean err;
        snprintf(sql, sizeof(sql),
                 "SELECT repo_id FROM InnerPubRepo WHERE repo_id='%s'",
                 repo_id);
        if (seaf_db_check_for_existence(db, sql, &err))
            snprintf(sql, sizeof(sql),
                     "UPDATE InnerPubRepo SET permission='%s' "
                     "WHERE repo_id='%s'", permission, repo_id);
        else
            snprintf(sql, sizeof(sql),
                     "INSERT INTO InnerPubRepo VALUES "
                     "('%s', '%s')", repo_id, permission);
        if (err)
            return -1;
        return seaf_db_query (db, sql);
    } else {
        return seaf_db_statement_query (db,
                                        "REPLACE INTO InnerPubRepo VALUES (?, ?)",
                                        2, "string", repo_id, "string", permission);
    }

    return -1;
}

int
seaf_repo_manager_unset_inner_pub_repo (SeafRepoManager *mgr,
                                        const char *repo_id)
{
    return seaf_db_statement_query (mgr->seaf->db,
                                    "DELETE FROM InnerPubRepo WHERE repo_id = ?",
                                    1, "string", repo_id);
}

gboolean
seaf_repo_manager_is_inner_pub_repo (SeafRepoManager *mgr,
                                     const char *repo_id)
{
    gboolean db_err = FALSE;

    return seaf_db_statement_exists (mgr->seaf->db,
                                     "SELECT repo_id FROM InnerPubRepo WHERE repo_id=?",
                                     &db_err, 1, "string", repo_id);
}

static gboolean
collect_public_repos (SeafDBRow *row, void *data)
{
    GList **ret = (GList **)data;
    SeafileRepo *srepo;
    const char *repo_id, *vrepo_id, *owner, *permission, *commit_id;
    gint64 size;

    repo_id = seaf_db_row_get_column_text (row, 0);
    vrepo_id = seaf_db_row_get_column_text (row, 1);
    owner = seaf_db_row_get_column_text (row, 2);
    permission = seaf_db_row_get_column_text (row, 3);
    commit_id = seaf_db_row_get_column_text (row, 4);
    size = seaf_db_row_get_column_int64 (row, 5);

    char *owner_l = g_ascii_strdown (owner, -1);

    srepo = g_object_new (SEAFILE_TYPE_REPO,
                          "share_type", "public",
                          "repo_id", repo_id,
                          "id", repo_id,
                          "head_cmmt_id", commit_id,
                          "permission", permission,
                          "user", owner_l,
                          "is_virtual", (vrepo_id != NULL),
                          "size", size,
                          NULL);
    g_free (owner_l);

    if (srepo) {
        if (vrepo_id) {
            const char *origin_repo_id = seaf_db_row_get_column_text (row, 6);
            const char *origin_path = seaf_db_row_get_column_text (row, 7);
            g_object_set (srepo, "store_id", origin_repo_id,
                          "origin_repo_id", origin_repo_id,
                          "origin_path", origin_path, NULL);
        } else {
            g_object_set (srepo, "store_id", repo_id, NULL);
        }

        *ret = g_list_prepend (*ret, srepo);
    }

    return TRUE;
}

GList *
seaf_repo_manager_list_inner_pub_repos (SeafRepoManager *mgr)
{
    GList *ret = NULL, *p;
    char *sql;

    sql = "SELECT InnerPubRepo.repo_id, VirtualRepo.repo_id, "
        "owner_id, permission, commit_id, s.size, "
        "VirtualRepo.origin_repo, VirtualRepo.path "
        "FROM InnerPubRepo LEFT JOIN VirtualRepo ON "
        "InnerPubRepo.repo_id=VirtualRepo.repo_id "
        "LEFT JOIN RepoSize s ON InnerPubRepo.repo_id = s.repo_id, RepoOwner, Branch "
        "WHERE InnerPubRepo.repo_id=RepoOwner.repo_id AND "
        "InnerPubRepo.repo_id = Branch.repo_id AND Branch.name = 'master'";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       collect_public_repos, &ret,
                                       0) < 0) {
        for (p = ret; p != NULL; p = p->next)
            g_object_unref (p->data);
        g_list_free (ret);
        return NULL;
    }

    seaf_fill_repo_obj_from_commit (&ret);

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
    char *sql;

    sql = "SELECT InnerPubRepo.repo_id, VirtualRepo.repo_id, "
        "owner_id, permission, commit_id, s.size, "
        "VirtualRepo.origin_repo, VirtualRepo.path "
        "FROM InnerPubRepo LEFT JOIN VirtualRepo ON "
        "InnerPubRepo.repo_id=VirtualRepo.repo_id "
        "LEFT JOIN RepoSize s ON InnerPubRepo.repo_id = s.repo_id, RepoOwner, Branch "
        "WHERE InnerPubRepo.repo_id=RepoOwner.repo_id AND owner_id=? "
        "AND InnerPubRepo.repo_id = Branch.repo_id AND Branch.name = 'master'";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       collect_public_repos, &ret,
                                       1, "string", user) < 0) {
        for (p = ret; p != NULL; p = p->next)
            g_object_unref (p->data);
        g_list_free (ret);
        return NULL;
    }

    seaf_fill_repo_obj_from_commit (&ret);

    return g_list_reverse (ret);
}

char *
seaf_repo_manager_get_inner_pub_repo_perm (SeafRepoManager *mgr,
                                           const char *repo_id)
{
    char *sql;

    sql = "SELECT permission FROM InnerPubRepo WHERE repo_id=?";
    return seaf_db_statement_get_string(mgr->seaf->db, sql, 1, "string", repo_id);
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

static int
create_repo_common (SeafRepoManager *mgr,
                    const char *repo_id,
                    const char *repo_name,
                    const char *repo_desc,
                    const char *user,
                    const char *magic,
                    const char *random_key,
                    int enc_version,
                    GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;
    SeafBranch *master = NULL;
    int ret = -1;

    if (enc_version != 2 && enc_version != -1) {
        seaf_warning ("Unsupported enc version %d.\n", enc_version);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Unsupported encryption version");
        return -1;
    }

    if (enc_version == 2) {
        if (!magic || strlen(magic) != 64) {
            seaf_warning ("Bad magic.\n");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Bad magic");
            return -1;
        }
        if (!random_key || strlen(random_key) != 96) {
            seaf_warning ("Bad random key.\n");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Bad random key");
            return -1;
        }
    }

    repo = seaf_repo_new (repo_id, repo_name, repo_desc);

    repo->no_local_history = TRUE;
    if (enc_version == 2) {
        repo->encrypted = TRUE;
        repo->enc_version = enc_version;
        memcpy (repo->magic, magic, 64);
        memcpy (repo->random_key, random_key, 96);
    }

    repo->version = CURRENT_REPO_VERSION;
    memcpy (repo->store_id, repo_id, 36);

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

    ret = 0;
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
    char magic[65], random_key[97];

    repo_id = gen_uuid ();

    if (passwd && passwd[0] != 0) {
        seafile_generate_magic (2, repo_id, passwd, magic);
        seafile_generate_random_key (passwd, random_key);
    }

    int rc;
    if (passwd)
        rc = create_repo_common (mgr, repo_id, repo_name, repo_desc, owner_email,
                                 magic, random_key, CURRENT_ENC_VERSION, error);
    else
        rc = create_repo_common (mgr, repo_id, repo_name, repo_desc, owner_email,
                                 NULL, NULL, -1, error);
    if (rc < 0)
        goto bad;

    if (seaf_repo_manager_set_repo_owner (mgr, repo_id, owner_email) < 0) {
        seaf_warning ("Failed to set repo owner.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to set repo owner.");
        goto bad;
    }

    return repo_id;
    
bad:
    if (repo_id)
        g_free (repo_id);
    return NULL;
}

char *
seaf_repo_manager_create_enc_repo (SeafRepoManager *mgr,
                                   const char *repo_id,
                                   const char *repo_name,
                                   const char *repo_desc,
                                   const char *owner_email,
                                   const char *magic,
                                   const char *random_key,
                                   int enc_version,
                                   GError **error)
{
    if (!repo_id || !is_uuid_valid (repo_id)) {
        seaf_warning ("Invalid repo_id.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo id");
        return NULL;
    }

    if (seaf_repo_manager_repo_exists (mgr, repo_id)) {
        seaf_warning ("Repo %s exists, refuse to create.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Repo already exists");
        return NULL;
    }

    if (create_repo_common (mgr, repo_id, repo_name, repo_desc, owner_email,
                            magic, random_key, enc_version, error) < 0)
        return NULL;

    if (seaf_repo_manager_set_repo_owner (mgr, repo_id, owner_email) < 0) {
        seaf_warning ("Failed to set repo owner.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to set repo owner.");
        return NULL;
    }

    return g_strdup (repo_id);
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
