/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet/job-mgr.h>
#include "db.h"
#include "seafile-session.h"

#define INFO_DB "info.db"


struct _SeafInfoManagerPriv {
    sqlite3    *db;
    gint64      total_block_size;
    GHashTable *commit_calc;
};

SeafInfoManager*
seaf_info_manager_new (SeafileSession *seaf)
{
    SeafInfoManager *mgr = g_new0 (SeafInfoManager, 1);
    mgr->priv = g_new0 (SeafInfoManagerPriv, 1);    
    mgr->seaf = seaf;
    mgr->priv->commit_calc = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                    g_free, NULL);

    return mgr;
}

static int
init_db (SeafInfoManager *mgr)
{
    char *db_path = g_build_filename (mgr->seaf->seaf_dir, INFO_DB, NULL);
    if (sqlite_open_db (db_path, &mgr->priv->db) < 0) {
        g_critical ("[info-mgr] Failed to open repo info db\n");
        g_free (db_path);
        return -1;
    }
    g_free (db_path);

    const char *sql, *sql2;

    sql = "CREATE TABLE IF NOT EXISTS CommitSize ("
        "commit_id TEXT PRIMARY KEY, block_num INTEGER);";
    if (sqlite_query_exec (mgr->priv->db, sql) < 0)
        return -1;

    sql2 = "CREATE TABLE IF NOT EXISTS RepoSize ("
        "repo_id TEXT PRIMARY KEY, repo_size INTEGER, commit_id TEXT);";
    if (sqlite_query_exec (mgr->priv->db, sql2) < 0)
        return -1;

    return 0;
}

int
seaf_info_manager_init (SeafInfoManager *mgr)
{
    init_db (mgr);

    mgr->priv->total_block_size = -1;    
    return 0;
}

static int
get_commit_tree_block_number_from_db (SeafInfoManager *mgr,
                                      const char *commit_id)
{
    sqlite3_stmt *stmt;
    sqlite3 *db;
    char sql[256];
    int result;
    int size;

    db = mgr->priv->db;
    snprintf (sql, 256, "SELECT block_num FROM CommitSize WHERE commit_id='%s'",
              commit_id);
    if (!(stmt = sqlite_query_prepare (db, sql))) {
        return -1;
    }

    result = sqlite3_step (stmt);
    if (result == SQLITE_ROW) {
        size = (int)sqlite3_column_int (stmt, 0);
        sqlite3_finalize (stmt);
        return size;
    } else if (result == SQLITE_DONE) {
        sqlite3_finalize (stmt);
        return -1;
    } else if (result == SQLITE_ERROR) {
        const char *str = sqlite3_errmsg (db);
        g_warning ("Couldn't prepare query, error: %d->'%s'\n",
                   result, str ? str : "no error given");
        sqlite3_finalize (stmt);
        return -2;
    }

    g_assert (0);
    return -2;
}

static void
save_commit_tree_block_number_to_db (SeafInfoManager *mgr,
                                     const char *commit_id,
                                     int size)
{
    char *sql;

    sql = sqlite3_mprintf ("INSERT INTO CommitSize VALUES (%Q, %d)",
                           commit_id, size);
    sqlite_query_exec (mgr->priv->db, sql);
    sqlite3_free (sql);
}

static gboolean
load_blocklist (SeafCommit *commit, void *data, gboolean *stop)
{
    BlockList *bl = data;

    if (seaf_fs_manager_populate_blocklist (seaf->fs_mgr, commit->root_id, bl) < 0)
        return FALSE;
    return TRUE;
}

static int
get_commit_tree_block_number (const char *commit_id)
{
    BlockList *bl;
    int size;

    bl = block_list_new ();
    if (!seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                   commit_id,
                                                   load_blocklist,
                                                   bl))
    {
        g_warning ("[info-mgr] Failed to populate blocklist.\n");
        block_list_free (bl);
        return -1;
    }

    size = bl->n_blocks;
    block_list_free (bl);
    return size;
}

typedef struct {
    char *commit_id;
    int size;
} CmmtcalResult;

static void *
get_commit_tree_block_number_thread_func(void *data)
{
    char *commit_id = data;
    int size;

    size = get_commit_tree_block_number (commit_id);

    CmmtcalResult *r = g_new0(CmmtcalResult, 1);
    r->commit_id = commit_id;
    r->size = size;
    return (void *)r;
}

static void
get_commit_tree_block_number_done_callback(void *result)
{
    CmmtcalResult *r = result;

    /* we have to use the seaf global variable here */
    SeafInfoManager *mgr = seaf->info_mgr;

    g_hash_table_remove (mgr->priv->commit_calc, r->commit_id);
    
    save_commit_tree_block_number_to_db (mgr, r->commit_id, r->size);
    g_free (r->commit_id);
    g_free (r);
}

static void
schedule_commit_tree_block_number_calculation (SeafInfoManager *mgr,
                                               const char *commit_id)
{
    ccnet_job_manager_schedule_job (mgr->seaf->job_mgr,
                                    get_commit_tree_block_number_thread_func,
                                    get_commit_tree_block_number_done_callback,
                                    g_strdup(commit_id));
    char *dup = g_strdup (commit_id);
    g_hash_table_insert (mgr->priv->commit_calc, dup, dup);
}

int
seaf_info_manager_get_commit_tree_block_number (SeafInfoManager *mgr,
                                                const char *commit_id)
{
    int size;

    if (g_hash_table_lookup (mgr->priv->commit_calc, commit_id))
        return -1;              /* in calculating */

    size = get_commit_tree_block_number_from_db (mgr, commit_id);
    if (size == -2)
        return -2;              /* error occurred */

    if (size >= 0)
        return size;

    if (size == -1) {
        schedule_commit_tree_block_number_calculation (mgr, commit_id);
        return -1;
    }

    g_assert (0);
    return -2;
}

typedef struct {
    guint64 size;
} TotalBlockResult;

static void *
get_total_block_size_thread_func(void *data)
{
    guint64 size;

    size = seaf_block_manager_get_total_size (seaf->block_mgr);

    TotalBlockResult *r = g_new0(TotalBlockResult, 1);
    r->size = size;
    return (void *)r;
}

static void
get_total_block_size_done_callback(void *result)
{
    TotalBlockResult *r = result;

    /* we have to use the seaf global variable here */
    seaf->info_mgr->priv->total_block_size = r->size;

    g_free (r);
}

gint64
seaf_info_manager_get_total_block_size (SeafInfoManager *mgr)
{
    if (mgr->priv->total_block_size == -1) {
        ccnet_job_manager_schedule_job (mgr->seaf->job_mgr,
                                        get_total_block_size_thread_func,
                                        get_total_block_size_done_callback,
                                        NULL);
    }

    return mgr->priv->total_block_size;
}

void
seaf_info_manager_schedule_total_block_size (SeafInfoManager *mgr)
{
    ccnet_job_manager_schedule_job (mgr->seaf->job_mgr,
                                    get_total_block_size_thread_func,
                                    get_total_block_size_done_callback,
                                    NULL);
}

gboolean
seaf_info_manager_repo_size_exists (SeafInfoManager *mgr,
                                    const char *repo_id) 
{
    char *sql;
    int ret;

    sql = sqlite3_mprintf ("SELECT repo_id FROM RepoSize WHERE repo_id = %Q", repo_id);

    ret = sqlite_check_for_existence (mgr->priv->db, sql);
    sqlite3_free (sql);
    return ret;
}

RepoSize *
seaf_info_manager_get_repo_size_from_db (SeafInfoManager *mgr,
                                         const char *repo_id) 
{
    sqlite3 *db = mgr->priv->db;
    
    int result;
    sqlite3_stmt *stmt;
    char sql[256];

    RepoSize *rs = g_new0 (RepoSize, 1);
    rs->size = 0;

    snprintf (sql, 256, "SELECT repo_size, commit_id FROM RepoSize WHERE repo_id ='%s'",
              repo_id);
    if ( !(stmt = sqlite_query_prepare(db, sql)) )
        return NULL;
    while (1) {
        result = sqlite3_step (stmt);
        if (result == SQLITE_ROW) {
            int size = (int)sqlite3_column_int(stmt, 0);
            char *str = (char *)sqlite3_column_text(stmt, 1);
            rs->size = size;
            memcpy (rs->commit_id, str, 41);
        }
        if (result == SQLITE_DONE) 
            break;
        if (result == SQLITE_ERROR) {
            const gchar *str = sqlite3_errmsg (db);
            g_warning ("Couldn't prepare query, error: %d->'%s'\n", 
                       result, str ? str : "no error given");
            g_free (rs);
            sqlite3_finalize (stmt);
            return NULL;
        }
    }

    sqlite3_finalize (stmt);
    return rs; 
}

int
seaf_info_manager_save_repo_size_to_db (SeafInfoManager *mgr, 
                                        const char *repo_id,
                                        gint64 size,
                                        const char *commit_id)
{
    sqlite3 *db = mgr->priv->db;
    char sql[1024];

    if (seaf_info_manager_repo_size_exists (mgr, repo_id)) {
        snprintf (sql, 1024, "UPDATE RepoSize SET repo_size =%"G_GINT64_FORMAT", "
                  "commit_id='%s' WHERE repo_id='%s';", size, commit_id, repo_id);
    } else {
        snprintf (sql, 1024, "INSERT INTO RepoSize (repo_id, repo_size, commit_id) VALUES ('%s',  %"G_GINT64_FORMAT", '%s');", repo_id, size, commit_id);
    }

    if (sqlite_query_exec (db, sql) < 0) {
        const char *str = sqlite3_errmsg (db);
        g_warning ("Couldn't save repo size to db, error: '%s'\n",
                   str ? str : "no error given");
        return -1;
    }

    return 0;
}
