#include "common.h"

#include "log.h"

#ifndef SEAFILE_SERVER
#include "db.h"
#else
#include "seaf-db.h"
#endif

#include "seafile-session.h"

#include "branch-mgr.h"

#define BRANCH_DB "branch.db"

SeafBranch *
seaf_branch_new (const char *name, const char *repo_id, const char *commit_id)
{
    SeafBranch *branch;

    branch = g_new0 (SeafBranch, 1);

    branch->name = g_strdup (name);
    memcpy (branch->repo_id, repo_id, 36);
    branch->repo_id[36] = '\0';
    memcpy (branch->commit_id, commit_id, 40);
    branch->commit_id[40] = '\0';

    branch->ref = 1;

    return branch;
}

void
seaf_branch_free (SeafBranch *branch)
{
    if (branch == NULL) return;
    g_free (branch->name);
    g_free (branch);
}

void
seaf_branch_list_free (GList *blist)
{
    GList *ptr;

    for (ptr = blist; ptr; ptr = ptr->next) {
        seaf_branch_unref (ptr->data);
    }
    g_list_free (blist);
}


void
seaf_branch_set_commit (SeafBranch *branch, const char *commit_id)
{
    memcpy (branch->commit_id, commit_id, 40);
    branch->commit_id[40] = '\0';
}

void
seaf_branch_ref (SeafBranch *branch)
{
    branch->ref++;
}

void
seaf_branch_unref (SeafBranch *branch)
{
    if (!branch)
        return;

    if (--branch->ref <= 0)
        seaf_branch_free (branch);
}

struct _SeafBranchManagerPriv {
    sqlite3 *db;
#ifndef SEAFILE_SERVER
    pthread_mutex_t db_lock;
#endif

#if defined( SEAFILE_SERVER ) && defined( FULL_FEATURE )
    uint32_t cevent_id;
#endif    
};

#if defined( SEAFILE_SERVER ) && defined( FULL_FEATURE )

#include "mq-mgr.h"
#include <ccnet/cevent.h>
static void publish_repo_update_event (CEvent *event, void *data);

#endif    

static int open_db (SeafBranchManager *mgr);

SeafBranchManager *
seaf_branch_manager_new (struct _SeafileSession *seaf)
{
    SeafBranchManager *mgr;

    mgr = g_new0 (SeafBranchManager, 1);
    mgr->priv = g_new0 (SeafBranchManagerPriv, 1);
    mgr->seaf = seaf;

#ifndef SEAFILE_SERVER
    pthread_mutex_init (&mgr->priv->db_lock, NULL);
#endif

    return mgr;
}

int
seaf_branch_manager_init (SeafBranchManager *mgr)
{
#if defined( SEAFILE_SERVER ) && defined( FULL_FEATURE )
    mgr->priv->cevent_id = cevent_manager_register (seaf->ev_mgr,
                                    (cevent_handler)publish_repo_update_event,
                                                    NULL);
#endif    

    return open_db (mgr);
}

static int
open_db (SeafBranchManager *mgr)
{
#ifndef SEAFILE_SERVER

    char *db_path;
    const char *sql;

    db_path = g_build_filename (mgr->seaf->seaf_dir, BRANCH_DB, NULL);
    if (sqlite_open_db (db_path, &mgr->priv->db) < 0) {
        g_critical ("[Branch mgr] Failed to open branch db\n");
        g_free (db_path);
        return -1;
    }
    g_free (db_path);

    sql = "CREATE TABLE IF NOT EXISTS Branch ("
          "name TEXT, repo_id TEXT, commit_id TEXT);";
    if (sqlite_query_exec (mgr->priv->db, sql) < 0)
        return -1;

    sql = "CREATE INDEX IF NOT EXISTS branch_index ON Branch(repo_id, name);";
    if (sqlite_query_exec (mgr->priv->db, sql) < 0)
        return -1;

#elif defined FULL_FEATURE

    char *sql;
    switch (seaf_db_type (mgr->seaf->db)) {
    case SEAF_DB_TYPE_MYSQL:
        sql = "CREATE TABLE IF NOT EXISTS Branch ("
            "name VARCHAR(10), repo_id CHAR(41), commit_id CHAR(41),"
            "PRIMARY KEY (repo_id, name)) ENGINE = INNODB";
        if (seaf_db_query (mgr->seaf->db, sql) < 0)
            return -1;
        break;
    case SEAF_DB_TYPE_PGSQL:
        sql = "CREATE TABLE IF NOT EXISTS Branch ("
            "name VARCHAR(10), repo_id CHAR(40), commit_id CHAR(40),"
            "PRIMARY KEY (repo_id, name))";
        if (seaf_db_query (mgr->seaf->db, sql) < 0)
            return -1;
        break;
    case SEAF_DB_TYPE_SQLITE:
        sql = "CREATE TABLE IF NOT EXISTS Branch ("
            "name VARCHAR(10), repo_id CHAR(41), commit_id CHAR(41),"
            "PRIMARY KEY (repo_id, name))";
        if (seaf_db_query (mgr->seaf->db, sql) < 0)
            return -1;
        break;
    }

#endif

    return 0;
}

int
seaf_branch_manager_add_branch (SeafBranchManager *mgr, SeafBranch *branch)
{
#ifndef SEAFILE_SERVER
    char sql[256];

    pthread_mutex_lock (&mgr->priv->db_lock);

    sqlite3_snprintf (sizeof(sql), sql,
                      "SELECT 1 FROM Branch WHERE name=%Q and repo_id=%Q",
                      branch->name, branch->repo_id);
    if (sqlite_check_for_existence (mgr->priv->db, sql))
        sqlite3_snprintf (sizeof(sql), sql,
                          "UPDATE Branch SET commit_id=%Q WHERE "
                          "name=%Q and repo_id=%Q",
                          branch->commit_id, branch->name, branch->repo_id);
    else
        sqlite3_snprintf (sizeof(sql), sql,
                          "INSERT INTO Branch VALUES (%Q, %Q, %Q)",
                          branch->name, branch->repo_id, branch->commit_id);

    sqlite_query_exec (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return 0;
#else
    char *sql;
    SeafDB *db = mgr->seaf->db;

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean exists, err;
        int rc;

        sql = "SELECT repo_id FROM Branch WHERE name=? AND repo_id=?";
        exists = seaf_db_statement_exists(db, sql, &err,
                                          2, "string", branch->name,
                                          "string", branch->repo_id);
        if (err)
            return -1;

        if (exists)
            rc = seaf_db_statement_query (db,
                                          "UPDATE Branch SET commit_id=? "
                                          "WHERE name=? AND repo_id=?",
                                          3, "string", branch->commit_id,
                                          "string", branch->name,
                                          "string", branch->repo_id);
        else
            rc = seaf_db_statement_query (db,
                                          "INSERT INTO Branch VALUES (?, ?, ?)",
                                          3, "string", branch->name,
                                          "string", branch->repo_id,
                                          "string", branch->commit_id);
        if (rc < 0)
            return -1;
    } else {
        int rc = seaf_db_statement_query (db,
                                 "REPLACE INTO Branch VALUES (?, ?, ?)",
                                 3, "string", branch->name,
                                 "string", branch->repo_id,
                                 "string", branch->commit_id);
        if (rc < 0)
            return -1;
    }
    return 0;
#endif
}

int
seaf_branch_manager_del_branch (SeafBranchManager *mgr,
                                const char *repo_id,
                                const char *name)
{
#ifndef SEAFILE_SERVER
    char *sql;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = sqlite3_mprintf ("DELETE FROM Branch WHERE name = %Q AND "
                           "repo_id = '%s'", name, repo_id);
    if (sqlite_query_exec (mgr->priv->db, sql) < 0)
        seaf_warning ("Delete branch %s failed\n", name);
    sqlite3_free (sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return 0;
#else
    int rc = seaf_db_statement_query (mgr->seaf->db,
                                      "DELETE FROM Branch WHERE name=? AND repo_id=?",
                                      2, "string", name, "string", repo_id);
    if (rc < 0)
        return -1;
    return 0;
#endif
}

int
seaf_branch_manager_update_branch (SeafBranchManager *mgr, SeafBranch *branch)
{
#ifndef SEAFILE_SERVER
    sqlite3 *db;
    char *sql;

    pthread_mutex_lock (&mgr->priv->db_lock);

    db = mgr->priv->db;
    sql = sqlite3_mprintf ("UPDATE Branch SET commit_id = %Q "
                           "WHERE name = %Q AND repo_id = %Q",
                           branch->commit_id, branch->name, branch->repo_id);
    sqlite_query_exec (db, sql);
    sqlite3_free (sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

    return 0;
#else
    int rc = seaf_db_statement_query (mgr->seaf->db,
                                      "UPDATE Branch SET commit_id = ? "
                                      "WHERE name = ? AND repo_id = ?",
                                      3, "string", branch->commit_id,
                                      "string", branch->name,
                                      "string", branch->repo_id);
    if (rc < 0)
        return -1;
    return 0;
#endif
}

#if defined( SEAFILE_SERVER ) && defined( FULL_FEATURE )

static gboolean
get_commit_id (SeafDBRow *row, void *data)
{
    char *out_commit_id = data;
    const char *commit_id;

    commit_id = seaf_db_row_get_column_text (row, 0);
    memcpy (out_commit_id, commit_id, 41);
    out_commit_id[40] = '\0';

    return FALSE;
}

typedef struct {
    char *repo_id;
    char *commit_id;
} RepoUpdateEventData;

static void
publish_repo_update_event (CEvent *event, void *data)
{
    RepoUpdateEventData *rdata = event->data;

    char buf[128];
    snprintf (buf, sizeof(buf), "repo-update\t%s\t%s",
              rdata->repo_id, rdata->commit_id);

    seaf_mq_manager_publish_event (seaf->mq_mgr, buf);

    g_free (rdata->repo_id);
    g_free (rdata->commit_id);
    g_free (rdata);
}

static void
on_branch_updated (SeafBranchManager *mgr, SeafBranch *branch)
{
    if (seaf_repo_manager_is_virtual_repo (seaf->repo_mgr, branch->repo_id))
        return;

    RepoUpdateEventData *rdata = g_new0 (RepoUpdateEventData, 1);

    rdata->repo_id = g_strdup (branch->repo_id);
    rdata->commit_id = g_strdup (branch->commit_id);
    
    cevent_manager_add_event (seaf->ev_mgr, mgr->priv->cevent_id, rdata);
}

int
seaf_branch_manager_test_and_update_branch (SeafBranchManager *mgr,
                                            SeafBranch *branch,
                                            const char *old_commit_id)
{
    SeafDBTrans *trans;
    char *sql;
    char commit_id[41] = { 0 };

    trans = seaf_db_begin_transaction (mgr->seaf->db);
    if (!trans)
        return -1;

    switch (seaf_db_type (mgr->seaf->db)) {
    case SEAF_DB_TYPE_MYSQL:
    case SEAF_DB_TYPE_PGSQL:
        sql = "SELECT commit_id FROM Branch WHERE name=? "
            "AND repo_id=? FOR UPDATE";
        break;
    case SEAF_DB_TYPE_SQLITE:
        sql = "SELECT commit_id FROM Branch WHERE name=? "
            "AND repo_id=?";
        break;
    default:
        g_return_val_if_reached (-1);
    }
    if (seaf_db_trans_foreach_selected_row (trans, sql,
                                            get_commit_id, commit_id,
                                            2, "string", branch->name,
                                            "string", branch->repo_id) < 0) {
        seaf_db_rollback (trans);
        seaf_db_trans_close (trans);
        return -1;
    }
    if (strcmp (old_commit_id, commit_id) != 0) {
        seaf_db_rollback (trans);
        seaf_db_trans_close (trans);
        return -1;
    }

    sql = "UPDATE Branch SET commit_id = ? "
        "WHERE name = ? AND repo_id = ?";
    if (seaf_db_trans_query (trans, sql, 3, "string", branch->commit_id,
                             "string", branch->name,
                             "string", branch->repo_id) < 0) {
        seaf_db_rollback (trans);
        seaf_db_trans_close (trans);
        return -1;
    }

    if (seaf_db_commit (trans) < 0) {
        seaf_db_rollback (trans);
        seaf_db_trans_close (trans);
        return -1;
    }

    seaf_db_trans_close (trans);

    on_branch_updated (mgr, branch);

    return 0;
}

#endif

#ifndef SEAFILE_SERVER
static SeafBranch *
real_get_branch (SeafBranchManager *mgr,
                 const char *repo_id,
                 const char *name)
{
    SeafBranch *branch = NULL;
    sqlite3_stmt *stmt;
    sqlite3 *db;
    char *sql;
    int result;

    pthread_mutex_lock (&mgr->priv->db_lock);

    db = mgr->priv->db;
    sql = sqlite3_mprintf ("SELECT commit_id FROM Branch "
                           "WHERE name = %Q and repo_id='%s'",
                           name, repo_id);
    if (!(stmt = sqlite_query_prepare (db, sql))) {
        seaf_warning ("[Branch mgr] Couldn't prepare query %s\n", sql);
        sqlite3_free (sql);
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return NULL;
    }
    sqlite3_free (sql);

    result = sqlite3_step (stmt);
    if (result == SQLITE_ROW) {
        char *commit_id = (char *)sqlite3_column_text (stmt, 0);

        branch = seaf_branch_new (name, repo_id, commit_id);
        pthread_mutex_unlock (&mgr->priv->db_lock);
        sqlite3_finalize (stmt);
        return branch;
    } else if (result == SQLITE_ERROR) {
        const char *str = sqlite3_errmsg (db);
        seaf_warning ("Couldn't prepare query, error: %d->'%s'\n",
                   result, str ? str : "no error given");
    }

    sqlite3_finalize (stmt);
    pthread_mutex_unlock (&mgr->priv->db_lock);
    return NULL;
}

SeafBranch *
seaf_branch_manager_get_branch (SeafBranchManager *mgr,
                                const char *repo_id,
                                const char *name)
{
    SeafBranch *branch;

    /* "fetch_head" maps to "local" or "master" on client (LAN sync) */
    if (strcmp (name, "fetch_head") == 0) {
        branch = real_get_branch (mgr, repo_id, "local");
        if (!branch) {
            branch = real_get_branch (mgr, repo_id, "master");
        }
        return branch;
    } else {
        return real_get_branch (mgr, repo_id, name);
    }
}

#else

static gboolean
get_branch (SeafDBRow *row, void *vid)
{
    char *ret = vid;
    const char *commit_id;

    commit_id = seaf_db_row_get_column_text (row, 0);
    memcpy (ret, commit_id, 41);

    return FALSE;
}

static SeafBranch *
real_get_branch (SeafBranchManager *mgr,
                 const char *repo_id,
                 const char *name)
{
    char commit_id[41];
    char *sql;

    commit_id[0] = 0;
    sql = "SELECT commit_id FROM Branch WHERE name=? AND repo_id=?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, 
                                       get_branch, commit_id,
                                       2, "string", name, "string", repo_id) < 0) {
        seaf_warning ("[branch mgr] DB error when get branch %s.\n", name);
        return NULL;
    }

    if (commit_id[0] == 0)
        return NULL;

    return seaf_branch_new (name, repo_id, commit_id);
}

SeafBranch *
seaf_branch_manager_get_branch (SeafBranchManager *mgr,
                                const char *repo_id,
                                const char *name)
{
    SeafBranch *branch;

    /* "fetch_head" maps to "master" on server. */
    if (strcmp (name, "fetch_head") == 0) {
        branch = real_get_branch (mgr, repo_id, "master");
        return branch;
    } else {
        return real_get_branch (mgr, repo_id, name);
    }
}

#endif  /* not SEAFILE_SERVER */

gboolean
seaf_branch_manager_branch_exists (SeafBranchManager *mgr,
                                   const char *repo_id,
                                   const char *name)
{
#ifndef SEAFILE_SERVER
    char *sql;
    gboolean ret;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sql = sqlite3_mprintf ("SELECT name FROM Branch WHERE name = %Q "
                           "AND repo_id='%s'", name, repo_id);
    ret = sqlite_check_for_existence (mgr->priv->db, sql);
    sqlite3_free (sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);
    return ret;
#else
    gboolean db_err = FALSE;

    return seaf_db_statement_exists (mgr->seaf->db,
                                     "SELECT name FROM Branch WHERE name=? "
                                     "AND repo_id=?", &db_err,
                                     2, "string", name, "string", repo_id);
#endif
}

#ifndef SEAFILE_SERVER
GList *
seaf_branch_manager_get_branch_list (SeafBranchManager *mgr,
                                     const char *repo_id)
{
    sqlite3 *db = mgr->priv->db;
    
    int result;
    sqlite3_stmt *stmt;
    char sql[256];
    char *name;
    char *commit_id;
    GList *ret = NULL;
    SeafBranch *branch;

    snprintf (sql, 256, "SELECT name, commit_id FROM branch WHERE repo_id ='%s'",
              repo_id);

    pthread_mutex_lock (&mgr->priv->db_lock);

    if ( !(stmt = sqlite_query_prepare(db, sql)) ) {
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return NULL;
    }

    while (1) {
        result = sqlite3_step (stmt);
        if (result == SQLITE_ROW) {
            name = (char *)sqlite3_column_text(stmt, 0);
            commit_id = (char *)sqlite3_column_text(stmt, 1);
            branch = seaf_branch_new (name, repo_id, commit_id);
            ret = g_list_prepend (ret, branch);
        }
        if (result == SQLITE_DONE)
            break;
        if (result == SQLITE_ERROR) {
            const gchar *str = sqlite3_errmsg (db);
            seaf_warning ("Couldn't prepare query, error: %d->'%s'\n", 
                       result, str ? str : "no error given");
            sqlite3_finalize (stmt);
            seaf_branch_list_free (ret);
            pthread_mutex_unlock (&mgr->priv->db_lock);
            return NULL;
        }
    }

    sqlite3_finalize (stmt);
    pthread_mutex_unlock (&mgr->priv->db_lock);
    return g_list_reverse(ret);
}
#else
static gboolean
get_branches (SeafDBRow *row, void *vplist)
{
    GList **plist = vplist;
    const char *commit_id;
    const char *name;
    const char *repo_id;
    SeafBranch *branch;

    name = seaf_db_row_get_column_text (row, 0);
    repo_id = seaf_db_row_get_column_text (row, 1);
    commit_id = seaf_db_row_get_column_text (row, 2);

    branch = seaf_branch_new (name, repo_id, commit_id);
    *plist = g_list_prepend (*plist, branch);

    return TRUE;
}

GList *
seaf_branch_manager_get_branch_list (SeafBranchManager *mgr,
                                     const char *repo_id)
{
    GList *ret = NULL;
    char *sql;

    sql = "SELECT name, repo_id, commit_id FROM Branch WHERE repo_id=?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, 
                                       get_branches, &ret,
                                       1, "string", repo_id) < 0) {
        seaf_warning ("[branch mgr] DB error when get branch list.\n");
        return NULL;
    }

    return ret;
}
#endif
