/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include "utils.h"

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
            "permission CHAR(15), INDEX (repo_id)) ENGINE=INNODB";

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
    } else if (db_type == SEAF_DB_TYPE_PGSQL) {
        sql = "CREATE TABLE IF NOT EXISTS SharedRepo "
            "(repo_id CHAR(36) , from_email VARCHAR(512), to_email VARCHAR(512), "
            "permission VARCHAR(15))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        if (!pgsql_index_exists (db, "sharedrepo_repoid_idx")) {
            sql = "CREATE INDEX sharedrepo_repoid_idx ON SharedRepo (repo_id)";
            if (seaf_db_query (db, sql) < 0)
                return -1;
        }
    }
    
    return 0;
}

int
seaf_share_manager_add_share (SeafShareManager *mgr, const char *repo_id,
                              const char *from_email, const char *to_email,
                              const char *permission)
{
    char sql[512];
    gboolean db_err = FALSE;

    snprintf (sql, sizeof(sql),
              "SELECT repo_id from SharedRepo WHERE repo_id='%s' AND "
              "from_email='%s' AND to_email='%s'", repo_id, from_email,
              to_email);
    if (seaf_db_check_for_existence (mgr->seaf->db, sql, &db_err))
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
    SeafileSharedRepo *srepo;
    
    repo_id = seaf_db_row_get_column_text (row, 0);
    email = seaf_db_row_get_column_text (row, 1);
    permission = seaf_db_row_get_column_text (row, 2);

    srepo = g_object_new (SEAFILE_TYPE_SHARED_REPO,
                          "share_type", "personal",
                          "repo_id", repo_id,
                          "user", email,
                          "permission", permission,
                          NULL);
    
    *p_repos = g_list_prepend (*p_repos, srepo);

    return TRUE;
}

static void
fill_in_repo_info (GList *shared_repos)
{
    SeafileSharedRepo *srepo;
    GList *ptr;
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;

    for (ptr = shared_repos; ptr; ptr = ptr->next) {
        srepo = ptr->data;
        repo = seaf_repo_manager_get_repo (seaf->repo_mgr,
                                           seafile_shared_repo_get_repo_id(srepo));
        if (!repo)
            continue;
        commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 repo->head->commit_id);
        if (!commit) {
            seaf_repo_unref (repo);
            continue;
        }
        g_object_set (srepo,
                      "repo_name", repo->name,
                      "repo_desc", repo->desc,
                      "encrypted", repo->encrypted,
                      "last_modified", commit->ctime,
                      NULL);
        seaf_repo_unref (repo);
        seaf_commit_unref (commit);
    }
}

GList*
seaf_share_manager_list_share_repos (SeafShareManager *mgr, const char *email,
                                     const char *type, int start, int limit)
{
    GList *ret = NULL, *p;
    char sql[512];

    if (start == -1 && limit == -1) {
        if (g_strcmp0 (type, "from_email") == 0) {
            snprintf (sql, sizeof(sql),
                      "SELECT SharedRepo.repo_id, to_email, permission FROM "
                      "SharedRepo, RepoOwner "
                      "WHERE from_email='%s' AND "
                      "SharedRepo.repo_id=RepoOwner.repo_id",
                      email);
        } else if (g_strcmp0 (type, "to_email") == 0) {
            snprintf (sql, sizeof(sql),
                      "SELECT SharedRepo.repo_id, from_email, permission FROM "
                      "SharedRepo, RepoOwner "
                      "WHERE to_email='%s' AND "
                      "SharedRepo.repo_id=RepoOwner.repo_id",
                      email);
        } else {
            /* should never reach here */
            g_warning ("[share mgr] Wrong column type");
            return NULL;
        }
    }
    else {
        if (g_strcmp0 (type, "from_email") == 0) {
            snprintf (sql, sizeof(sql),
                      "SELECT SharedRepo.repo_id, to_email, permission FROM "
                      "SharedRepo, RepoOwner WHERE "
                      "from_email='%s' AND "
                      "SharedRepo.repo_id=RepoOwner.repo_id "
                      "ORDER BY SharedRepo.repo_id "
                      "LIMIT %d OFFSET %d",
                      email, limit, start);
        } else if (g_strcmp0 (type, "to_email") == 0) {
            snprintf (sql, sizeof(sql),
                      "SELECT SharedRepo.repo_id, from_email, permission FROM "
                      "SharedRepo, RepoOwner WHERE "
                      "to_email='%s' AND "
                      "SharedRepo.repo_id=RepoOwner.repo_id "
                      "ORDER BY SharedRepo.repo_id "
                      "LIMIT %d OFFSET %d",
                      email, limit, start);
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
        for (p = ret; p; p = p->next)
            g_object_unref (p->data);
        g_list_free (ret);
        return NULL;
    }

    fill_in_repo_info (ret);

    return g_list_reverse (ret);
}

GList*
seaf_share_manager_list_org_share_repos (SeafShareManager *mgr,
                                         int org_id,
                                         const char *email,
                                         const char *type,
                                         int start, int limit)
{
    GList *ret = NULL, *p;
    char sql[512];

    if (start == -1 && limit == -1) {
        if (g_strcmp0 (type, "from_email") == 0) {
            snprintf (sql, sizeof(sql),
                      "SELECT SharedRepo.repo_id, to_email, permission FROM "
                      "SharedRepo, OrgRepo "
                      "WHERE from_email='%s' AND "
                      "OrgRepo.org_id=%d AND "
                      "SharedRepo.repo_id=OrgRepo.repo_id",
                      email, org_id);
        } else if (g_strcmp0 (type, "to_email") == 0) {
            snprintf (sql, sizeof(sql),
                      "SELECT SharedRepo.repo_id, from_email, permission FROM "
                      "SharedRepo, OrgRepo "
                      "WHERE to_email='%s' AND "
                      "OrgRepo.org_id=%d AND "
                      "SharedRepo.repo_id=OrgRepo.repo_id",
                      email, org_id);
        } else {
            /* should never reach here */
            g_warning ("[share mgr] Wrong column type");
            return NULL;
        }
    }
    else {
        if (g_strcmp0 (type, "from_email") == 0) {
            snprintf (sql, sizeof(sql),
                      "SELECT SharedRepo.repo_id, to_email, permission FROM "
                      "SharedRepo, OrgRepo WHERE "
                      "from_email='%s' AND "
                      "OrgRepo.org_id=%d AND "
                      "SharedRepo.repo_id=OrgRepo.repo_id "
                      "ORDER BY SharedRepo.repo_id "
                      "LIMIT %d OFFSET %d",
                      email, org_id, limit, start);
        } else if (g_strcmp0 (type, "to_email") == 0) {
            snprintf (sql, sizeof(sql),
                      "SELECT SharedRepo.repo_id, from_email, permission FROM "
                      "SharedRepo, OrgRepo WHERE "
                      "to_email='%s' AND "
                      "OrgRepo.org_id=%d AND "
                      "SharedRepo.repo_id=OrgRepo.repo_id "
                      "ORDER BY SharedRepo.repo_id "
                      "LIMIT %d OFFSET %d",
                      email, org_id, limit, start);
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
        for (p = ret; p; p = p->next)
            g_object_unref (p->data);
        g_list_free (ret);
        return NULL;
    }

    fill_in_repo_info (ret);

    return g_list_reverse (ret);
}

static gboolean
collect_shared_to (SeafDBRow *row, void *data)
{
    GList **plist = data;
    const char *to_email;

    to_email = seaf_db_row_get_column_text (row, 0);
    *plist = g_list_prepend (*plist, g_strdup(to_email));

    return TRUE;
}

GList *
seaf_share_manager_list_shared_to (SeafShareManager *mgr,
                                   const char *owner,
                                   const char *repo_id)
{
    char sql[512];
    GList *ret = NULL;

    snprintf (sql, sizeof(sql),
              "SELECT to_email FROM SharedRepo WHERE "
              "from_email='%s' AND repo_id='%s'",
              owner, repo_id);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                      collect_shared_to, &ret) < 0) {
        g_warning ("[share mgr] DB error when list shared to.\n");
        string_list_free (ret);
        return NULL;
    }

    return ret;
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
