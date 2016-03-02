/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <glib/gstdio.h>

#include <ccnet.h>
#include "utils.h"
#include "log.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "fs-mgr.h"
#include "seafile-error.h"

#include "seaf-db.h"

#define INDEX_DIR "index"

struct _SeafRepoManagerPriv {

};

static SeafRepo *
load_repo (SeafRepoManager *manager, const char *repo_id, gboolean ret_corrupt);

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

void
seaf_repo_from_commit (SeafRepo *repo, SeafCommit *commit)
{
    repo->name = g_strdup (commit->repo_name);
    repo->desc = g_strdup (commit->repo_desc);
    repo->encrypted = commit->encrypted;
    repo->repaired = commit->repaired;
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

SeafRepoManager*
seaf_repo_manager_new (SeafileSession *seaf)
{
    SeafRepoManager *mgr = g_new0 (SeafRepoManager, 1);

    mgr->priv = g_new0 (SeafRepoManagerPriv, 1);
    mgr->seaf = seaf;

    return mgr;
}

int
seaf_repo_manager_init (SeafRepoManager *mgr)
{
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
    gboolean db_err = FALSE;

    snprintf (sql, sizeof(sql), "SELECT repo_id FROM Repo WHERE repo_id = '%s'",
              id);
    return seaf_db_check_for_existence (db, sql, &db_err);
}

static gboolean
repo_exists_in_db_ex (SeafDB *db, const char *id, gboolean *db_err)
{
    char sql[256];

    snprintf (sql, sizeof(sql), "SELECT repo_id FROM Repo WHERE repo_id = '%s'",
              id);
    return seaf_db_check_for_existence (db, sql, db_err);
}

SeafRepo*
seaf_repo_manager_get_repo (SeafRepoManager *manager, const gchar *id)
{
    SeafRepo repo;
    int len = strlen(id);

    if (len >= 37)
        return NULL;

    memcpy (repo.id, id, len + 1);

    if (repo_exists_in_db (manager->seaf->db, id)) {
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

    exists = repo_exists_in_db_ex (manager->seaf->db, id, &db_err);

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
    SeafRepo repo;
    memcpy (repo.id, id, 37);

    return repo_exists_in_db (manager->seaf->db, id);
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

static SeafRepo *
load_repo (SeafRepoManager *manager, const char *repo_id, gboolean ret_corrupt)
{
    SeafRepo *repo;
    SeafBranch *branch;
    SeafVirtRepo *vinfo = NULL;

    repo = seaf_repo_new(repo_id, NULL, NULL);
    if (!repo) {
        seaf_warning ("[repo mgr] failed to alloc repo.\n");
        return NULL;
    }

    repo->manager = manager;

    branch = seaf_branch_manager_get_branch (seaf->branch_mgr, repo_id, "master");
    if (!branch) {
        seaf_warning ("Failed to get master branch of repo %.8s.\n", repo_id);
        repo->is_corrupted = TRUE;
    } else {
        load_repo_commit (manager, repo, branch);
        seaf_branch_unref (branch);
    }

    if (repo->is_corrupted) {
        if (!ret_corrupt) {
            seaf_repo_free (repo);
            return NULL;
        }
        return repo;
    }

    vinfo = seaf_repo_manager_get_virtual_repo_info (manager, repo_id);
    if (vinfo) {
        repo->is_virtual = TRUE;
        memcpy (repo->store_id, vinfo->origin_repo_id, 36);
    } else {
        repo->is_virtual = FALSE;
        memcpy (repo->store_id, repo->id, 36);
    }
    seaf_virtual_repo_info_free (vinfo);

    return repo;
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
seaf_repo_manager_get_repo_list (SeafRepoManager *mgr,
                                 int start, int limit,
                                 gboolean *error)
{
    char sql[256];
    GList *id_list = NULL, *ptr;
    GList *ret = NULL;
    SeafRepo *repo;

    *error = FALSE;

    if (start == -1 && limit == -1)
        snprintf (sql, 256, "SELECT repo_id FROM Repo");
    else
        snprintf (sql, 256, "SELECT repo_id FROM Repo LIMIT %d, %d", start, limit);

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_repo_id, &id_list) < 0)
        goto error;

    for (ptr = id_list; ptr; ptr = ptr->next) {
        char *repo_id = ptr->data;
        repo = seaf_repo_manager_get_repo_ex (mgr, repo_id);
        if (repo)
            ret = g_list_prepend (ret, repo);
    }

    string_list_free (id_list);
    return ret;

error:
    *error = TRUE;
    string_list_free (id_list);
    return NULL;
}

int
seaf_repo_manager_set_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id,
                                          int days)
{
    SeafVirtRepo *vinfo;
    SeafDB *db = mgr->seaf->db;
    char sql[256];

    vinfo = seaf_repo_manager_get_virtual_repo_info (mgr, repo_id);
    if (vinfo) {
        seaf_virtual_repo_info_free (vinfo);
        return 0;
    }

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean err;
        snprintf(sql, sizeof(sql),
                 "SELECT repo_id FROM RepoHistoryLimit "
                 "WHERE repo_id='%s'", repo_id);
        if (seaf_db_check_for_existence(db, sql, &err))
            snprintf(sql, sizeof(sql),
                     "UPDATE RepoHistoryLimit SET days=%d"
                     "WHERE repo_id='%s'", days, repo_id);
        else
            snprintf(sql, sizeof(sql),
                     "INSERT INTO RepoHistoryLimit VALUES "
                     "('%s', %d)", repo_id, days);
        if (err)
            return -1;
        return seaf_db_query(db, sql);
    } else {
        snprintf (sql, sizeof(sql),
                  "REPLACE INTO RepoHistoryLimit VALUES ('%s', %d)",
                  repo_id, days);
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    return 0;
}

static gboolean
get_limit (SeafDBRow *row, void *vdays)
{
    int *days = vdays;

    *days = seaf_db_row_get_column_int (row, 0);

    return FALSE;
}

int
seaf_repo_manager_get_repo_history_limit (SeafRepoManager *mgr,
                                          const char *repo_id)
{
    SeafVirtRepo *vinfo;
    const char *r_repo_id = repo_id;
    char sql[256];
    int per_repo_days = -1;
    int ret;

    vinfo = seaf_repo_manager_get_virtual_repo_info (mgr, repo_id);
    if (vinfo)
        r_repo_id = vinfo->origin_repo_id;

    snprintf (sql, sizeof(sql),
              "SELECT days FROM RepoHistoryLimit WHERE repo_id='%s'",
              r_repo_id);
    seaf_virtual_repo_info_free (vinfo);

    /* We don't use seaf_db_get_int() because we need to differ DB error
     * from not exist.
     * We can't just return global config value if DB error occured,
     * since the global value may be smaller than per repo one.
     * This can lead to data lose in GC.
     */
    ret = seaf_db_foreach_selected_row (mgr->seaf->db, sql,
                                        get_limit, &per_repo_days);
    if (ret == 0) {
        /* If per repo value is not set, return the global one. */
        return mgr->seaf->keep_history_days;
    }

    if (per_repo_days < 0) {
        per_repo_days = -1;
    }

    return per_repo_days;
}

int
seaf_repo_manager_set_repo_valid_since (SeafRepoManager *mgr,
                                        const char *repo_id,
                                        gint64 timestamp)
{
    SeafDB *db = mgr->seaf->db;
    char sql[256];

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean err;
        snprintf(sql, sizeof(sql),
                 "SELECT repo_id FROM RepoValidSince WHERE "
                 "repo_id='%s'", repo_id);
        if (seaf_db_check_for_existence(db, sql, &err))
            snprintf(sql, sizeof(sql),
                     "UPDATE RepoValidSince SET timestamp=%"G_GINT64_FORMAT
                     " WHERE repo_id='%s'", timestamp, repo_id);
        else
            snprintf(sql, sizeof(sql),
                     "INSERT INTO RepoValidSince VALUES "
                     "('%s', %"G_GINT64_FORMAT")", repo_id, timestamp);
        if (err)
            return -1;
        if (seaf_db_query (db, sql) < 0)
            return -1;
    } else {
        snprintf (sql, sizeof(sql),
                  "REPLACE INTO RepoValidSince VALUES ('%s', %"G_GINT64_FORMAT")",
                  repo_id, timestamp);
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

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
    /* Also return -1 if DB error. */
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

static gboolean
load_virtual_info (SeafDBRow *row, void *p_vinfo)
{
    SeafVirtRepo *vinfo;
    const char *origin_repo_id, *path, *base_commit;

    origin_repo_id = seaf_db_row_get_column_text (row, 0);
    path = seaf_db_row_get_column_text (row, 1);
    base_commit = seaf_db_row_get_column_text (row, 2);

    vinfo = g_new0 (SeafVirtRepo, 1);
    memcpy (vinfo->origin_repo_id, origin_repo_id, 36);
    vinfo->path = g_strdup(path);
    memcpy (vinfo->base_commit, base_commit, 40);

    *((SeafVirtRepo **)p_vinfo) = vinfo;

    return FALSE;
}

SeafVirtRepo *
seaf_repo_manager_get_virtual_repo_info (SeafRepoManager *mgr,
                                         const char *repo_id)
{
    char sql[256];
    SeafVirtRepo *vinfo = NULL;

    snprintf (sql, 256,
              "SELECT origin_repo, path, base_commit FROM VirtualRepo "
              "WHERE repo_id = '%s'", repo_id);
    seaf_db_foreach_selected_row (seaf->db, sql, load_virtual_info, &vinfo);

    return vinfo;
}

void
seaf_virtual_repo_info_free (SeafVirtRepo *vinfo)
{
    if (!vinfo) return;

    g_free (vinfo->path);
    g_free (vinfo);
}

static gboolean
collect_virtual_repo_ids (SeafDBRow *row, void *data)
{
    GList **p_ids = data;
    const char *repo_id;

    repo_id = seaf_db_row_get_column_text (row, 0);
    *p_ids = g_list_prepend (*p_ids, g_strdup(repo_id));

    return TRUE;
}

GList *
seaf_repo_manager_get_virtual_repo_ids_by_origin (SeafRepoManager *mgr,
                                                  const char *origin_repo)
{
    GList *ret = NULL;
    char sql[256];

    snprintf (sql, 256,
              "SELECT repo_id FROM VirtualRepo WHERE origin_repo='%s'",
              origin_repo);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_virtual_repo_ids, &ret) < 0) {
        return NULL;
    }

    return g_list_reverse (ret);
}

static gboolean
get_garbage_repo_id (SeafDBRow *row, void *vid_list)
{
    GList **ret = vid_list;
    char *repo_id;

    repo_id = g_strdup(seaf_db_row_get_column_text (row, 0));
    *ret = g_list_prepend (*ret, repo_id);

    return TRUE;
}

GList *
seaf_repo_manager_list_garbage_repos (SeafRepoManager *mgr)
{
    GList *repo_ids = NULL;

    seaf_db_foreach_selected_row (seaf->db,
                                  "SELECT repo_id FROM GarbageRepos",
                                  get_garbage_repo_id, &repo_ids);

    return repo_ids;
}

void
seaf_repo_manager_remove_garbage_repo (SeafRepoManager *mgr, const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql), "DELETE FROM GarbageRepos WHERE repo_id='%s'",
              repo_id);
    seaf_db_query (seaf->db, sql);
}
