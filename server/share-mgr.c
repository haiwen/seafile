/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "share-mgr.h"

#include "seaf-db.h"

SeafShareManager *
seaf_share_manager_new (SeafileSession *seaf)
{
    SeafShareManager *mgr = g_new0 (SeafShareManager, 1);

    mgr->seaf = seaf;

    return mgr;
}

int
seaf_share_manager_start (SeafShareManager *mgr)
{
    SeafDB *db = mgr->seaf->db;
    const char *sql;

    int db_type = seaf_db_type (db);
    if (db_type == SEAF_DB_TYPE_MYSQL) {
        sql = "CREATE TABLE IF NOT EXISTS SharedRepo "
            "(repo_id CHAR(37) , from_email VARCHAR(512), to_email VARCHAR(512), "
            "permission CHAR(15), INDEX (repo_id))";

        if (seaf_db_query (db, sql) < 0)
            return -1;
    } else if (db_type == SEAF_DB_TYPE_SQLITE) {
        sql = "CREATE TABLE IF NOT EXISTS SharedRepo "
            "(repo_id CHAR(37) , from_email VARCHAR(512), to_email VARCHAR(512), "
            "permission CHAR(15))";
        if (seaf_db_query (db, sql) < 0)
            return -1;
        sql = "CREATE INDEX IF NOT EXISTS RepoIdIndex on SharedRepo (repo_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }
    
    return 0;
}

int
seaf_share_manager_add_share (SeafShareManager *mgr, const char *repo_id,
                              const char *from_email, const char *to_email,
                              const char *permission)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "SELECT repo_id from SharedRepo WHERE repo_id='%s' AND "
              "from_email='%s' AND to_email='%s'", repo_id, from_email,
              to_email);
    if (seaf_db_check_for_existence (mgr->seaf->db, sql))
        return 0;

    snprintf (sql, sizeof(sql),
              "INSERT INTO SharedRepo VALUES ('%s', '%s', '%s', '%s')", repo_id,
              from_email, to_email, permission);
    if (seaf_db_query (mgr->seaf->db, sql) < 0)
        return -1;

    return 0;
}

int
seaf_share_manager_set_permission (SeafShareManager *mgr, const char *repo_id,
                                   const char *from_email, const char *to_email,
                                   const char *permission)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "UPDATE SharedRepo SET permission='%s' WHERE "
              "repo_id='%s' AND from_email='%s' AND to_email='%s'",
              permission, repo_id, from_email, to_email);
    return seaf_db_query (mgr->seaf->db, sql);
}

static gboolean
collect_repos (SeafDBRow *row, void *data)
{
    GList **p_repos = data;
    const char *repo_id;
    const char *email;
    const char *permission;
    SeafRepo *repo;
    ShareRepoInfo *shareRepoInfo;
    
    repo_id = seaf_db_row_get_column_text (row, 0);
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        return TRUE;
    }
    email = seaf_db_row_get_column_text (row, 1);
    permission = seaf_db_row_get_column_text (row, 2);

    shareRepoInfo = g_new0 (ShareRepoInfo, 1);
    shareRepoInfo->email = g_strdup(email);
    shareRepoInfo->repo = repo;
    shareRepoInfo->permission = g_strdup(permission);
    
    *p_repos = g_list_prepend (*p_repos, shareRepoInfo);

    return TRUE;
}

GList*
seaf_share_manager_list_share_repos (SeafShareManager *mgr, const char *email,
                                     const char *type, int start, int limit)
{
    GList *ret = NULL;
    char sql[512];

    if (start == -1 && limit == -1) {
        if (g_strcmp0 (type, "from_email") == 0) {
            snprintf (sql, sizeof(sql), "SELECT repo_id, to_email, permission FROM "
                      "SharedRepo WHERE from_email='%s'", email);
        } else if (g_strcmp0 (type, "to_email") == 0) {
            snprintf (sql, sizeof(sql), "SELECT repo_id, from_email, permission FROM "
                      "SharedRepo WHERE to_email='%s'", email);
        } else {
            /* should never reach here */
            g_warning ("[share mgr] Wrong column type");
            return NULL;
        }
    }
    else {
        if (g_strcmp0 (type, "from_email") == 0) {
            snprintf (sql, sizeof(sql),
                      "SELECT repo_id, to_email, permission FROM "
                      "SharedRepo WHERE from_email='%s' LIMIT %d, %d",
                      email, start, limit);
        } else if (g_strcmp0 (type, "to_email") == 0) {
            snprintf (sql, sizeof(sql),
                      "SELECT repo_id, from_email, permission FROM "
                      "SharedRepo WHERE to_email='%s' LIMIT %d, %d",
                      email, start, limit);
        } else {
            /* should never reach here */
            g_warning ("[share mgr] Wrong column type");
            return NULL;
        }
    }

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      collect_repos, &ret) < 0) {
        g_warning ("[share mgr] DB error when get shared repo id and email "
                   "for %s.\n", email);
        return NULL;
    }

    return g_list_reverse (ret);
}

int
seaf_share_manager_remove_share (SeafShareManager *mgr, const char *repo_id,
                                 const char *from_email, const char *to_email)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "DELETE FROM SharedRepo WHERE repo_id = '%s' AND from_email ="
              " '%s' AND to_email = '%s'", repo_id, from_email, to_email);
    
    if (seaf_db_query (mgr->seaf->db, sql) < 0)
        return -1;

    return 0;
}

int
seaf_share_manager_remove_repo (SeafShareManager *mgr, const char *repo_id)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "DELETE FROM SharedRepo WHERE repo_id = '%s'", 
              repo_id);
    
    if (seaf_db_query (mgr->seaf->db, sql) < 0)
        return -1;

    return 0;
}

char *
seaf_share_manager_check_permission (SeafShareManager *mgr,
                                     const char *repo_id,
                                     const char *email)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "SELECT permission FROM SharedRepo WHERE repo_id='%s' AND to_email='%s'",
              repo_id, email);
    return seaf_db_get_string (mgr->seaf->db, sql);
}
