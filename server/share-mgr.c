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
            "(id INTEGER NOT NULL PRIMARY KEY AUTO_INCREMENT,"
            "repo_id CHAR(37) , from_email VARCHAR(255), to_email VARCHAR(255), "
            "permission CHAR(15), INDEX (repo_id), "
            "INDEX(from_email), INDEX(to_email)) ENGINE=INNODB";

        if (seaf_db_query (db, sql) < 0)
            return -1;
    } else if (db_type == SEAF_DB_TYPE_SQLITE) {
        sql = "CREATE TABLE IF NOT EXISTS SharedRepo "
            "(repo_id CHAR(37) , from_email VARCHAR(255), to_email VARCHAR(255), "
            "permission CHAR(15))";
        if (seaf_db_query (db, sql) < 0)
            return -1;
        sql = "CREATE INDEX IF NOT EXISTS RepoIdIndex on SharedRepo (repo_id)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
        sql = "CREATE INDEX IF NOT EXISTS FromEmailIndex on SharedRepo (from_email)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
        sql = "CREATE INDEX IF NOT EXISTS ToEmailIndex on SharedRepo (to_email)";
        if (seaf_db_query (db, sql) < 0)
            return -1;
    } else if (db_type == SEAF_DB_TYPE_PGSQL) {
        sql = "CREATE TABLE IF NOT EXISTS SharedRepo "
            "(repo_id CHAR(36) , from_email VARCHAR(255), to_email VARCHAR(255), "
            "permission VARCHAR(15))";
        if (seaf_db_query (db, sql) < 0)
            return -1;

        if (!pgsql_index_exists (db, "sharedrepo_repoid_idx")) {
            sql = "CREATE INDEX sharedrepo_repoid_idx ON SharedRepo (repo_id)";
            if (seaf_db_query (db, sql) < 0)
                return -1;
        }
        if (!pgsql_index_exists (db, "sharedrepo_from_email_idx")) {
            sql = "CREATE INDEX sharedrepo_from_email_idx ON SharedRepo (from_email)";
            if (seaf_db_query (db, sql) < 0)
                return -1;
        }
        if (!pgsql_index_exists (db, "sharedrepo_to_email_idx")) {
            sql = "CREATE INDEX sharedrepo_to_email_idx ON SharedRepo (to_email)";
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
    gboolean db_err = FALSE;
    int ret = 0;

    char *from_email_l = g_ascii_strdown (from_email, -1);
    char *to_email_l = g_ascii_strdown (to_email, -1);

    if (seaf_db_statement_exists (mgr->seaf->db,
                                  "SELECT repo_id from SharedRepo "
                                  "WHERE repo_id=? AND "
                                  "from_email=? AND to_email=?",
                                  &db_err, 3, "string", repo_id,
                                  "string", from_email_l, "string", to_email_l))
        goto out;

    if (seaf_db_statement_query (mgr->seaf->db,
                                 "INSERT INTO SharedRepo (repo_id, from_email, "
                                 "to_email, permission) VALUES (?, ?, ?, ?)",
                                 4, "string", repo_id, "string", from_email_l,
                                 "string", to_email_l, "string", permission) < 0) {
        ret = -1;
        goto out;
    }

out:
    g_free (from_email_l);
    g_free (to_email_l);
    return ret;
}

int
seaf_share_manager_set_permission (SeafShareManager *mgr, const char *repo_id,
                                   const char *from_email, const char *to_email,
                                   const char *permission)
{
    char *sql;
    int ret;

    char *from_email_l = g_ascii_strdown (from_email, -1);
    char *to_email_l = g_ascii_strdown (to_email, -1);
    sql = "UPDATE SharedRepo SET permission=? WHERE "
        "repo_id=? AND from_email=? AND to_email=?";

    ret = seaf_db_statement_query (mgr->seaf->db, sql,
                                   4, "string", permission, "string", repo_id,
                                   "string", from_email_l, "string", to_email_l);

    g_free (from_email_l);
    g_free (to_email_l);
    return ret;
}

static gboolean
collect_repos (SeafDBRow *row, void *data)
{
    GList **p_repos = data;
    const char *repo_id;
    const char *vrepo_id;
    const char *email;
    const char *permission;
    const char *commit_id;
    SeafileSharedRepo *srepo;
    SeafCommit *commit;

    repo_id = seaf_db_row_get_column_text (row, 0);
    vrepo_id = seaf_db_row_get_column_text (row, 1);
    email = seaf_db_row_get_column_text (row, 2);
    permission = seaf_db_row_get_column_text (row, 3);
    commit_id = seaf_db_row_get_column_text (row, 4);

    commit = seaf_commit_manager_get_commit_compatible (seaf->commit_mgr,
                                                        repo_id,
                                                        commit_id);
    if (!commit)
        return TRUE;

    char *email_l = g_ascii_strdown (email, -1);

    srepo = g_object_new (SEAFILE_TYPE_SHARED_REPO,
                          "share_type", "personal",
                          "repo_id", repo_id,
                          "user", email_l,
                          "permission", permission,
                          "repo_name", commit->repo_name,
                          "repo_desc", commit->repo_desc,
                          "encrypted", commit->encrypted,
                          "last_modified", commit->ctime,
                          "is_virtual", (vrepo_id != NULL),
                          NULL);
    g_free (email_l);
    seaf_commit_unref (commit);

    *p_repos = g_list_prepend (*p_repos, srepo);

    return TRUE;
}

GList*
seaf_share_manager_list_share_repos (SeafShareManager *mgr, const char *email,
                                     const char *type, int start, int limit)
{
    GList *ret = NULL, *p;
    char *sql;

    if (start == -1 && limit == -1) {
        if (g_strcmp0 (type, "from_email") == 0) {
            sql = "SELECT SharedRepo.repo_id, VirtualRepo.repo_id, "
                "to_email, permission, commit_id FROM "
                "SharedRepo LEFT JOIN VirtualRepo ON "
                "SharedRepo.repo_id=VirtualRepo.repo_id, Branch "
                "WHERE from_email=? AND "
                "SharedRepo.repo_id = Branch.repo_id AND "
                "Branch.name = 'master'";
        } else if (g_strcmp0 (type, "to_email") == 0) {
            sql = "SELECT SharedRepo.repo_id, NULL, "
                "from_email, permission, commit_id FROM "
                "SharedRepo, Branch "
                "WHERE to_email=? AND "
                "SharedRepo.repo_id = Branch.repo_id AND "
                "Branch.name = 'master'";
        } else {
            /* should never reach here */
            g_warning ("[share mgr] Wrong column type");
            return NULL;
        }

        if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                           collect_repos, &ret,
                                           1, "string", email) < 0) {
            g_warning ("[share mgr] DB error when get shared repo id and email "
                       "for %s.\n", email);
            for (p = ret; p; p = p->next)
                g_object_unref (p->data);
            g_list_free (ret);
            return NULL;
        }
    }
    else {
        if (g_strcmp0 (type, "from_email") == 0) {
            sql = "SELECT SharedRepo.repo_id, VirtualRepo.repo_id, "
                "to_email, permission, commit_id FROM "
                "SharedRepo LEFT JOIN VirtualRepo ON "
                "SharedRepo.repo_id=VirtualRepo.repo_id, Branch "
                "WHERE from_email=? "
                "AND SharedRepo.repo_id = Branch.repo_id "
                "AND Branch.name = 'master' "
                "ORDER BY SharedRepo.repo_id "
                "LIMIT ? OFFSET ?";
        } else if (g_strcmp0 (type, "to_email") == 0) {
            sql = "SELECT SharedRepo.repo_id, NULL, "
                "from_email, permission, commit_id FROM "
                "SharedRepo, Branch WHERE "
                "to_email=? "
                "AND SharedRepo.repo_id = Branch.repo_id "
                "AND Branch.name = 'master' "
                "ORDER BY SharedRepo.repo_id "
                "LIMIT ? OFFSET ?";
        } else {
            /* should never reach here */
            g_warning ("[share mgr] Wrong column type");
            return NULL;
        }

        if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                           collect_repos, &ret,
                                           3, "string", email,
                                           "int", limit, "int", start) < 0) {
            g_warning ("[share mgr] DB error when get shared repo id and email "
                       "for %s.\n", email);
            for (p = ret; p; p = p->next)
                g_object_unref (p->data);
            g_list_free (ret);
            return NULL;
        }
    }

    return g_list_reverse (ret);
}

static gboolean
collect_shared_to (SeafDBRow *row, void *data)
{
    GList **plist = data;
    const char *to_email;

    to_email = seaf_db_row_get_column_text (row, 0);
    *plist = g_list_prepend (*plist, g_ascii_strdown(to_email, -1));

    return TRUE;
}

GList *
seaf_share_manager_list_shared_to (SeafShareManager *mgr,
                                   const char *owner,
                                   const char *repo_id)
{
    char *sql;
    GList *ret = NULL;

    sql = "SELECT to_email FROM SharedRepo WHERE "
        "from_email=? AND repo_id=?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql,
                                       collect_shared_to, &ret,
                                       2, "string", owner, "string", repo_id) < 0) {
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
    if (seaf_db_statement_query (mgr->seaf->db,
                       "DELETE FROM SharedRepo WHERE repo_id = ? AND from_email ="
                       " ? AND to_email = ?",
                       3, "string", repo_id, "string", from_email,
                       "string", to_email) < 0)
        return -1;

    return 0;
}

int
seaf_share_manager_remove_repo (SeafShareManager *mgr, const char *repo_id)
{
    if (seaf_db_statement_query (mgr->seaf->db,
                       "DELETE FROM SharedRepo WHERE repo_id = ?",
                       1, "string", repo_id) < 0)
        return -1;

    return 0;
}

char *
seaf_share_manager_check_permission (SeafShareManager *mgr,
                                     const char *repo_id,
                                     const char *email)
{
    char *sql;

    sql = "SELECT permission FROM SharedRepo WHERE repo_id=? AND to_email=?";
    return seaf_db_statement_get_string (mgr->seaf->db, sql,
                                         2, "string", repo_id, "string", email);
}
