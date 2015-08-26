/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "utils.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

#include <ccnet.h>
#include <ccnet/job-mgr.h>
#include <pthread.h>

#include "seafile-session.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "fs-mgr.h"
#include "seafile-error.h"
#include "seafile-crypt.h"
#include "merge-new.h"
#include "seafile-error.h"

#include "seaf-db.h"
#include "diff-simple.h"

#define MAX_RUNNING_TASKS 5
#define SCHEDULE_INTERVAL 1000  /* 1s */

typedef struct MergeTask {
    char repo_id[37];
} MergeTask;

typedef struct MergeScheduler {
    pthread_mutex_t q_lock;
    GQueue *queue;
    GHashTable *running;
    CcnetJobManager *tpool;
    CcnetTimer *timer;
} MergeScheduler;

static MergeScheduler *scheduler = NULL;

static void
add_merge_task (const char *repo_id);

static int
save_virtual_repo_info (SeafRepoManager *mgr,
                        const char *repo_id,
                        const char *origin_repo_id,
                        const char *path,
                        const char *base_commit)
{
    int ret = 0;

    if (seaf_db_statement_query (mgr->seaf->db,
                       "INSERT INTO VirtualRepo VALUES (?, ?, ?, ?)",
                       4, "string", repo_id, "string", origin_repo_id,
                       "string", path, "string", base_commit) < 0)
        ret = -1;

    return ret;
}

static int
do_create_virtual_repo (SeafRepoManager *mgr,
                        SeafRepo *origin_repo,
                        const char *repo_id,
                        const char *repo_name,
                        const char *repo_desc,
                        const char *root_id,
                        const char *user,
                        const char *passwd,
                        GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;
    SeafBranch *master = NULL;
    int ret = 0;

    repo = seaf_repo_new (repo_id, repo_name, repo_desc);

    repo->no_local_history = TRUE;
    if (passwd != NULL && passwd[0] != '\0') {
        repo->encrypted = TRUE;
        repo->enc_version = origin_repo->enc_version;
        seafile_generate_magic (repo->enc_version, repo_id, passwd, repo->magic);
        if (repo->enc_version == 2)
            memcpy (repo->random_key, origin_repo->random_key, 96);
    }

    /* Virtual repos share fs and block store with origin repo and
     * have the same version as the origin.
     */
    repo->version = origin_repo->version;
    memcpy (repo->store_id, origin_repo->id, 36);

    commit = seaf_commit_new (NULL, repo->id,
                              root_id, /* root id */
                              user, /* creator */
                              EMPTY_SHA1, /* creator id */
                              repo_desc,  /* description */
                              0);         /* ctime */

    seaf_repo_to_commit (repo, commit);
    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0) {
        seaf_warning ("Failed to add commit.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add commit");
        ret = -1;
        goto out;
    }

    master = seaf_branch_new ("master", repo->id, commit->commit_id);
    if (seaf_branch_manager_add_branch (seaf->branch_mgr, master) < 0) {
        seaf_warning ("Failed to add branch.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add branch");
        ret = -1;
        goto out;
    }

    if (seaf_repo_set_head (repo, master) < 0) {
        seaf_warning ("Failed to set repo head.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to set repo head.");
        ret = -1;
        goto out;
    }

    if (seaf_repo_manager_add_repo (mgr, repo) < 0) {
        seaf_warning ("Failed to add repo.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add repo.");
        ret = -1;
        goto out;
    }

out:
    if (repo)
        seaf_repo_unref (repo);
    if (commit)
        seaf_commit_unref (commit);
    if (master)
        seaf_branch_unref (master);
    
    return ret;    
}

static void
update_repo_size(const char *repo_id)
{
    schedule_repo_size_computation (seaf->size_sched, repo_id);
}

static char *
get_existing_virtual_repo (SeafRepoManager *mgr,
                           const char *origin_repo_id,
                           const char *path)
{
    char *sql = "SELECT repo_id FROM VirtualRepo WHERE origin_repo = ? AND path = ?";

    return seaf_db_statement_get_string (mgr->seaf->db, sql, 2,
                                         "string", origin_repo_id, "string", path);
}

char *
seaf_repo_manager_create_virtual_repo (SeafRepoManager *mgr,
                                       const char *origin_repo_id,
                                       const char *path,
                                       const char *repo_name,
                                       const char *repo_desc,
                                       const char *owner,
                                       const char *passwd,
                                       GError **error)
{
    SeafRepo *origin_repo = NULL;
    SeafCommit *origin_head = NULL;
    char *repo_id = NULL;
    char *dir_id = NULL;
    char *orig_owner = NULL;

    if (seaf_repo_manager_is_virtual_repo (mgr, origin_repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Cannot create sub-library from a sub-library");
        return NULL;
    }

    repo_id = get_existing_virtual_repo (mgr, origin_repo_id, path);
    if (repo_id) {
        return repo_id;
    }

    origin_repo = seaf_repo_manager_get_repo (mgr, origin_repo_id);
    if (!origin_repo) {
        seaf_warning ("Failed to get origin repo %.10s\n", origin_repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Origin library not exists");
        return NULL;
    }

    if (origin_repo->encrypted) {
        if (origin_repo->enc_version < 2) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Library encryption version must be higher than 2");
            seaf_repo_unref (origin_repo);
            return NULL;
        }

        if (!passwd || passwd[0] == 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Password is not set");
            seaf_repo_unref (origin_repo);
            return NULL;
        }

        if (seafile_verify_repo_passwd (origin_repo_id,
                                        passwd,
                                        origin_repo->magic,
                                        origin_repo->enc_version) < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Incorrect password");
            seaf_repo_unref (origin_repo);
            return NULL;
        }
    }

    origin_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                  origin_repo->id,
                                                  origin_repo->version,
                                                  origin_repo->head->commit_id);
    if (!origin_head) {
        seaf_warning ("Failed to get head commit %.8s of repo %s.\n",
                      origin_repo->head->commit_id, origin_repo->id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Bad origin repo head");
        goto error;
    }

    dir_id = seaf_fs_manager_get_seafdir_id_by_path (seaf->fs_mgr,
                                                     origin_repo->store_id,
                                                     origin_repo->version,
                                                     origin_head->root_id,
                                                     path, NULL);
    if (!dir_id) {
        seaf_warning ("Path %s doesn't exist or is not a dir in repo %.10s.\n",
                      path, origin_repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad path");
        goto error;
    }

    repo_id = gen_uuid();

    /* Save virtual repo info before actually create the repo.
     */
    if (save_virtual_repo_info (mgr, repo_id, origin_repo_id,
                                path, origin_head->commit_id) < 0) {
        seaf_warning ("Failed to save virtual repo info for %.10s:%s",
                      origin_repo_id, path);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal error");
        goto error;
    }

    orig_owner = seaf_repo_manager_get_repo_owner (mgr, origin_repo_id);

    if (do_create_virtual_repo (mgr, origin_repo, repo_id, repo_name, repo_desc,
                                dir_id, orig_owner, passwd, error) < 0)
        goto error;

    if (seaf_repo_manager_set_repo_owner (mgr, repo_id, orig_owner) < 0) {
        seaf_warning ("Failed to set repo owner for %.10s.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to set repo owner.");
        goto error;
    }

    /* The size of virtual repo is non-zero at the beginning. */
    update_repo_size (repo_id);

    seaf_repo_unref (origin_repo);
    seaf_commit_unref (origin_head);
    g_free (dir_id);
    g_free (orig_owner);
    return repo_id;

error:
    seaf_repo_unref (origin_repo);
    seaf_commit_unref (origin_head);
    g_free (repo_id);
    g_free (dir_id);
    g_free (orig_owner);
    return NULL;
}

static gboolean
load_virtual_info (SeafDBRow *row, void *p_vinfo)
{
    SeafVirtRepo *vinfo;
    const char *repo_id, *origin_repo_id, *path, *base_commit;

    repo_id = seaf_db_row_get_column_text (row, 0);
    origin_repo_id = seaf_db_row_get_column_text (row, 1);
    path = seaf_db_row_get_column_text (row, 2);
    base_commit = seaf_db_row_get_column_text (row, 3);

    vinfo = g_new0 (SeafVirtRepo, 1);
    memcpy (vinfo->repo_id, repo_id, 36);
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
    char *sql;
    SeafVirtRepo *vinfo = NULL;

    sql = "SELECT repo_id, origin_repo, path, base_commit FROM VirtualRepo "
        "WHERE repo_id = ?";
    seaf_db_statement_foreach_row (seaf->db, sql, load_virtual_info, &vinfo,
                                   1, "string", repo_id);

    return vinfo;
}

void
seaf_virtual_repo_info_free (SeafVirtRepo *vinfo)
{
    if (!vinfo) return;

    g_free (vinfo->path);
    g_free (vinfo);
}

gboolean
seaf_repo_manager_is_virtual_repo (SeafRepoManager *mgr, const char *repo_id)
{
    gboolean db_err;

    char *sql = "SELECT 1 FROM VirtualRepo WHERE repo_id = ?";
    return seaf_db_statement_exists (seaf->db, sql, &db_err,
                                     1, "string", repo_id);
}

char *
seaf_repo_manager_get_virtual_repo_id (SeafRepoManager *mgr,
                                       const char *origin_repo,
                                       const char *path,
                                       const char *owner)
{
    char *sql;
    char *ret;

    sql = "SELECT RepoOwner.repo_id FROM RepoOwner, VirtualRepo "
        "WHERE owner_id=? AND origin_repo=? AND path=? "
        "AND RepoOwner.repo_id = VirtualRepo.repo_id";

    ret = seaf_db_statement_get_string (mgr->seaf->db, sql,
                                        3, "string", owner, "string", origin_repo,
                                        "string", path);

    return ret;
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
seaf_repo_manager_get_virtual_repos_by_owner (SeafRepoManager *mgr,
                                              const char *owner,
                                              GError **error)
{
    GList *id_list = NULL, *ptr;
    GList *ret = NULL;
    char *sql;

    sql = "SELECT RepoOwner.repo_id FROM RepoOwner, VirtualRepo "
        "WHERE owner_id=? "
        "AND RepoOwner.repo_id = VirtualRepo.repo_id";

    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, 
                                       collect_virtual_repo_ids, &id_list,
                                       1, "string", owner) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "DB error");
        return NULL;
    }

    char *repo_id;
    SeafRepo *repo;
    for (ptr = id_list; ptr; ptr = ptr->next) {
        repo_id = ptr->data;
        repo = seaf_repo_manager_get_repo (mgr, repo_id);
        if (repo != NULL)
            ret = g_list_prepend (ret, repo);
    }

    string_list_free (id_list);
    return ret;
}

GList *
seaf_repo_manager_get_virtual_repo_ids_by_origin (SeafRepoManager *mgr,
                                                  const char *origin_repo)
{
    GList *ret = NULL;
    char *sql;

    sql = "SELECT repo_id FROM VirtualRepo WHERE origin_repo=?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, 
                                       collect_virtual_repo_ids, &ret,
                                       1, "string", origin_repo) < 0) {
        return NULL;
    }

    return g_list_reverse (ret);
}

static gboolean
collect_virtual_info (SeafDBRow *row, void *plist)
{
    GList **pret = plist;
    SeafVirtRepo *vinfo;
    const char *repo_id, *origin_repo_id, *path, *base_commit;

    repo_id = seaf_db_row_get_column_text (row, 0);
    origin_repo_id = seaf_db_row_get_column_text (row, 1);
    path = seaf_db_row_get_column_text (row, 2);
    base_commit = seaf_db_row_get_column_text (row, 3);

    vinfo = g_new0 (SeafVirtRepo, 1);
    memcpy (vinfo->repo_id, repo_id, 36);
    memcpy (vinfo->origin_repo_id, origin_repo_id, 36);
    vinfo->path = g_strdup(path);
    memcpy (vinfo->base_commit, base_commit, 40);

    *pret = g_list_prepend (*pret, vinfo);

    return TRUE;
}

GList *
seaf_repo_manager_get_virtual_info_by_origin (SeafRepoManager *mgr,
                                              const char *origin_repo)
{
    GList *ret = NULL;
    char *sql;

    sql = "SELECT repo_id, origin_repo, path, base_commit "
        "FROM VirtualRepo WHERE origin_repo=?";
    if (seaf_db_statement_foreach_row (mgr->seaf->db, sql, 
                                       collect_virtual_info, &ret,
                                       1, "string", origin_repo) < 0) {
        return NULL;
    }

    return g_list_reverse (ret);
}

static void
set_virtual_repo_base_commit_path (const char *vrepo_id, const char *base_commit_id,
                                   const char *new_path)
{
    seaf_db_statement_query (seaf->db,
                             "UPDATE VirtualRepo SET base_commit=?, path=? WHERE repo_id=?",
                             3, "string", base_commit_id, "string", new_path,
                             "string", vrepo_id);
}

int
seaf_repo_manager_merge_virtual_repo (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      const char *exclude_repo)
{
    GList *vrepos = NULL, *ptr;
    char *vrepo_id;
    int ret = 0;

    if (seaf_repo_manager_is_virtual_repo (mgr, repo_id)) {
        add_merge_task (repo_id);
        return 0;
    }

    vrepos = seaf_repo_manager_get_virtual_repo_ids_by_origin (mgr, repo_id);
    for (ptr = vrepos; ptr; ptr = ptr->next) {
        vrepo_id = ptr->data;

        if (g_strcmp0 (exclude_repo, vrepo_id) == 0)
            continue;

        add_merge_task (vrepo_id);
    }

    string_list_free (vrepos);
    return ret;
}

/*
 * If the missing virtual repo is renamed, update database entry;
 * otherwise delete the virtual repo.
 */
static void
handle_missing_virtual_repo (SeafRepoManager *mgr,
                             SeafRepo *repo, SeafCommit *head, SeafVirtRepo *vinfo)
{
    SeafCommit *parent = NULL;
    char *old_dir_id = NULL;
    GList *diff_res = NULL, *ptr;
    DiffEntry *de;

    parent = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             head->repo_id, head->version,
                                             head->parent_id);
    if (!parent) {
        seaf_warning ("Failed to find commit %s:%s.\n", head->repo_id, head->parent_id);
        return;
    }

    int rc = diff_commits (parent, head, &diff_res, TRUE);
    if (rc < 0) {
        seaf_warning ("Failed to diff commit %s to %s.\n",
                      parent->commit_id, head->commit_id);
        seaf_commit_unref (parent);
        return;
    }

    char *path = vinfo->path, *sub_path, *p, *par_path;
    gboolean is_renamed = FALSE;
    p = &path[strlen(path)];
    par_path = g_strdup(path);
    sub_path = NULL;

    while (1) {
        GError *error = NULL;
        old_dir_id = seaf_fs_manager_get_seafdir_id_by_path (seaf->fs_mgr,
                                                             repo->store_id,
                                                             repo->version,
                                                             parent->root_id,
                                                             par_path, &error);
        if (!old_dir_id) {
            if (error && error->code == SEAF_ERR_PATH_NO_EXIST) {
                seaf_warning ("Failed to find %s under commit %s in repo %s.\n",
                              par_path, parent->commit_id, repo->store_id);
                seaf_debug ("Delete virtual repo %.10s.\n", vinfo->repo_id);
                seaf_repo_manager_del_virtual_repo (mgr, vinfo->repo_id);
                g_clear_error (&error);
            }
            goto out;
        }

        char de_id[41];
        char *new_path;

        for (ptr = diff_res; ptr; ptr = ptr->next) {
            de = ptr->data;
            if (de->status == DIFF_STATUS_DIR_RENAMED) {
                rawdata_to_hex (de->sha1, de_id, 20);
                if (strcmp (de_id, old_dir_id) == 0) {
                    if (sub_path != NULL)
                        new_path = g_strconcat ("/", de->new_name, "/", sub_path, NULL);
                    else
                        new_path = g_strconcat ("/", de->new_name, NULL);
                    seaf_debug ("Updating path of virtual repo %s to %s.\n",
                                vinfo->repo_id, new_path);
                    set_virtual_repo_base_commit_path (vinfo->repo_id,
                                                       head->commit_id, new_path);
                    is_renamed = TRUE;
                    break;
                }
            }
        }
        g_free (old_dir_id);

        if (is_renamed)
            break;

        while (--p != path && *p != '/');

        if (p == path)
            break;

        g_free (par_path);
        g_free (sub_path);
        par_path = g_strndup (path, p - path);
        sub_path = g_strdup (p + 1);
    }

    if (!is_renamed) {
        seaf_debug ("Delete virtual repo %.10s.\n", vinfo->repo_id);
        seaf_repo_manager_del_virtual_repo (mgr, vinfo->repo_id);
    }

out:
    g_free (par_path);
    g_free (sub_path);

    for (ptr = diff_res; ptr; ptr = ptr->next)
        diff_entry_free ((DiffEntry *)ptr->data);
    g_list_free (diff_res);

    seaf_commit_unref (parent);
}

void
seaf_repo_manager_cleanup_virtual_repos (SeafRepoManager *mgr,
                                         const char *origin_repo_id)
{
    SeafRepo *repo = NULL;
    SeafCommit *head = NULL;
    GList *vinfo_list = NULL, *ptr;
    SeafVirtRepo *vinfo;
    SeafDir *dir;
    GError *error = NULL;

    repo = seaf_repo_manager_get_repo (mgr, origin_repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %.10s.\n", origin_repo_id);
        goto out;
    }

    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id,
                                           repo->version,
                                           repo->head->commit_id);
    if (!head) {
        seaf_warning ("Failed to get commit %s:%.8s.\n",
                      repo->id, repo->head->commit_id);
        goto out;
    }

    vinfo_list = seaf_repo_manager_get_virtual_info_by_origin (mgr,
                                                               origin_repo_id);
    for (ptr = vinfo_list; ptr; ptr = ptr->next) {
        vinfo = ptr->data;
        dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                                   repo->store_id,
                                                   repo->version,
                                                   head->root_id,
                                                   vinfo->path,
                                                   &error);
        if (error) {
            if (error->code == SEAF_ERR_PATH_NO_EXIST) {
                handle_missing_virtual_repo (mgr, repo, head, vinfo);
            }
            g_clear_error (&error);
        } else
            seaf_dir_free (dir);
        seaf_virtual_repo_info_free (vinfo);
    }

out:
    seaf_repo_unref (repo);
    seaf_commit_unref (head);
    g_list_free (vinfo_list);
}

static void *merge_virtual_repo (void *vtask)
{
    MergeTask *task = vtask;
    SeafRepoManager *mgr = seaf->repo_mgr;
    char *repo_id = task->repo_id;
    SeafVirtRepo *vinfo;
    SeafRepo *repo = NULL, *orig_repo = NULL;
    SeafCommit *head = NULL, *orig_head = NULL, *base = NULL;
    char *root = NULL, *orig_root = NULL, *base_root = NULL;
    char new_base_commit[41] = {0};
    int ret = 0;

    /* repos */
    repo = seaf_repo_manager_get_repo (mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get virt repo %.10s.\n", repo_id);
        ret = -1;
        goto out;
    }

    vinfo = repo->virtual_info;

    orig_repo = seaf_repo_manager_get_repo (mgr, vinfo->origin_repo_id);
    if (!orig_repo) {
        seaf_warning ("Failed to get orig repo %.10s.\n", vinfo->origin_repo_id);
        ret = -1;
        goto out;
    }

    /* commits */
    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id, repo->version,
                                           repo->head->commit_id);
    if (!head) {
        seaf_warning ("Failed to get commit %s:%.8s.\n",
                      repo->id, repo->head->commit_id);
        ret = -1;
        goto out;
    }

    orig_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                orig_repo->id, orig_repo->version,
                                                orig_repo->head->commit_id);
    if (!orig_head) {
        seaf_warning ("Failed to get commit %s:%.8s.\n",
                      orig_repo->id, orig_repo->head->commit_id);
        ret = -1;
        goto out;
    }

    base = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           orig_repo->id, orig_repo->version,
                                           vinfo->base_commit);
    if (!base) {
        seaf_warning ("Failed to get commit %s:%.8s.\n",
                      orig_repo->id, vinfo->base_commit);
        ret = -1;
        goto out;
    }

    /* fs roots */
    root = head->root_id;

    base_root = seaf_fs_manager_get_seafdir_id_by_path (seaf->fs_mgr,
                                                        orig_repo->store_id,
                                                        orig_repo->version,
                                                        base->root_id,
                                                        vinfo->path,
                                                        NULL);
    if (!base_root) {
        seaf_warning ("Cannot find seafdir for repo %.10s path %s.\n",
                      vinfo->origin_repo_id, vinfo->path);
        ret = -1;
        goto out;
    }

    orig_root = seaf_fs_manager_get_seafdir_id_by_path (seaf->fs_mgr,
                                                        orig_repo->store_id,
                                                        orig_repo->version,
                                                        orig_head->root_id,
                                                        vinfo->path,
                                                        NULL);
    if (!orig_root) {
        seaf_warning ("Cannot find seafdir for repo %.10s path %s.\n",
                      vinfo->origin_repo_id, vinfo->path);
        ret = -1;
        goto out;
    }

    if (strcmp (root, orig_root) == 0) {
        /* Nothing to merge. */
        seaf_debug ("Nothing to merge.\n");
    } else if (strcmp (base_root, root) == 0) {
        /* Origin changed, virtual repo not changed. */
        seaf_debug ("Origin changed, virtual repo not changed.\n");
        ret = seaf_repo_manager_update_dir (mgr,
                                            repo_id,
                                            "/",
                                            orig_root,
                                            orig_head->creator_name,
                                            head->commit_id,
                                            NULL,
                                            NULL);
        if (ret < 0) {
            seaf_warning ("Failed to update root of virtual repo %.10s.\n",
                          repo_id);
            goto out;
        }

        set_virtual_repo_base_commit_path (repo->id, orig_repo->head->commit_id,
                                           vinfo->path);
    } else if (strcmp (base_root, orig_root) == 0) {
        /* Origin not changed, virutal repo changed. */
        seaf_debug ("Origin not changed, virutal repo changed.\n");
        ret = seaf_repo_manager_update_dir (mgr,
                                            vinfo->origin_repo_id,
                                            vinfo->path,
                                            root,
                                            head->creator_name,
                                            orig_head->commit_id,
                                            new_base_commit,
                                            NULL);
        if (ret < 0) {
            seaf_warning ("Failed to update origin repo %.10s path %s.\n",
                          vinfo->origin_repo_id, vinfo->path);
            goto out;
        }

        set_virtual_repo_base_commit_path (repo->id, new_base_commit, vinfo->path);

        /* Since origin repo is updated, we have to merge it with other
         * virtual repos if necessary. But we don't need to merge with
         * the current virtual repo again.
         */
        seaf_repo_manager_cleanup_virtual_repos (mgr, vinfo->origin_repo_id);
        seaf_repo_manager_merge_virtual_repo (mgr,
                                              vinfo->origin_repo_id,
                                              repo_id);
    } else {
        /* Both origin and virtual repo are changed. */
        seaf_debug ("Both origin and virtual repo are changed.\n");
        MergeOptions opt;
        const char *roots[3];

        memset (&opt, 0, sizeof(opt));
        opt.n_ways = 3;
        memcpy (opt.remote_repo_id, repo_id, 36);
        memcpy (opt.remote_head, head->commit_id, 40);
        opt.do_merge = TRUE;

        roots[0] = base_root; /* base */
        roots[1] = orig_root; /* head */
        roots[2] = root;  /* remote */

        /* Merge virtual into origin */
        if (seaf_merge_trees (orig_repo->store_id, orig_repo->version,
                              3, roots, &opt) < 0) {
            seaf_warning ("Failed to merge virtual repo %.10s.\n", repo_id);
            ret = -1;
            goto out;
        }

        seaf_debug ("Number of dirs visted in merge: %d.\n", opt.visit_dirs);

        /* Update virtual repo root. */
        ret = seaf_repo_manager_update_dir (mgr,
                                            repo_id,
                                            "/",
                                            opt.merged_tree_root,
                                            orig_head->creator_name,
                                            head->commit_id,
                                            NULL,
                                            NULL);
        if (ret < 0) {
            seaf_warning ("Failed to update root of virtual repo %.10s.\n",
                          repo_id);
            goto out;
        }

        /* Update origin repo path. */
        ret = seaf_repo_manager_update_dir (mgr,
                                            vinfo->origin_repo_id,
                                            vinfo->path,
                                            opt.merged_tree_root,
                                            head->creator_name,
                                            orig_head->commit_id,
                                            new_base_commit,
                                            NULL);
        if (ret < 0) {
            seaf_warning ("Failed to update origin repo %.10s path %s.\n",
                          vinfo->origin_repo_id, vinfo->path);
            goto out;
        }

        set_virtual_repo_base_commit_path (repo->id, new_base_commit, vinfo->path);

        seaf_repo_manager_cleanup_virtual_repos (mgr, vinfo->origin_repo_id);
        seaf_repo_manager_merge_virtual_repo (mgr,
                                              vinfo->origin_repo_id,
                                              repo_id);
    }

out:
    seaf_repo_unref (repo);
    seaf_repo_unref (orig_repo);
    seaf_commit_unref (head);
    seaf_commit_unref (orig_head);
    seaf_commit_unref (base);
    g_free (base_root);
    g_free (orig_root);
    return vtask;
}

static void merge_virtual_repo_done (void *vtask)
{
    MergeTask *task = vtask;

    seaf_debug ("Task %.8s done.\n", task->repo_id);

    g_hash_table_remove (scheduler->running, task->repo_id);
}

static int
schedule_merge_tasks (void *vscheduler)
{
    MergeScheduler *scheduler = vscheduler;
    int n_running = g_hash_table_size (scheduler->running);
    MergeTask *task;

    /* seaf_debug ("Waiting tasks %d, running tasks %d.\n", */
    /*             g_queue_get_length (scheduler->queue), n_running); */

    if (n_running >= MAX_RUNNING_TASKS)
        return TRUE;

    pthread_mutex_lock (&scheduler->q_lock);

    while (n_running < MAX_RUNNING_TASKS) {
        task = g_queue_pop_head (scheduler->queue);
        if (!task)
            break;

        if (!g_hash_table_lookup (scheduler->running, task->repo_id)) {
            int ret = ccnet_job_manager_schedule_job (scheduler->tpool,
                                                      merge_virtual_repo,
                                                      merge_virtual_repo_done,
                                                      task);
            if (ret < 0) {
                g_queue_push_tail (scheduler->queue, task);
                break;
            }

            g_hash_table_insert (scheduler->running,
                                 g_strdup(task->repo_id),
                                 task);
            n_running++;

            seaf_debug ("Run task for repo %.8s.\n", task->repo_id);
        } else {
            seaf_debug ("A task for repo %.8s is already running.\n", task->repo_id);

            g_queue_push_tail (scheduler->queue, task);
            break;
        }
    }

    pthread_mutex_unlock (&scheduler->q_lock);

    return TRUE;
}

static gint task_cmp (gconstpointer a, gconstpointer b)
{
    const MergeTask *task_a = a;
    const MergeTask *task_b = b;

    return strcmp (task_a->repo_id, task_b->repo_id);
}

static void
add_merge_task (const char *repo_id)
{
    MergeTask *task = g_new0 (MergeTask, 1);

    seaf_debug ("Add merge task for repo %.8s.\n", repo_id);

    memcpy (task->repo_id, repo_id, 36);

    pthread_mutex_lock (&scheduler->q_lock);

    if (g_queue_find_custom (scheduler->queue, task, task_cmp) != NULL) {
        seaf_debug ("Task for repo %.8s is already queued.\n", repo_id);
        g_free (task);
    } else
        g_queue_push_tail (scheduler->queue, task);

    pthread_mutex_unlock (&scheduler->q_lock);
}

int
seaf_repo_manager_init_merge_scheduler ()
{
    scheduler = g_new0 (MergeScheduler, 1);
    if (!scheduler)
        return -1;

    pthread_mutex_init (&scheduler->q_lock, NULL);

    scheduler->queue = g_queue_new ();
    scheduler->running = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, g_free);

    scheduler->tpool = ccnet_job_manager_new (MAX_RUNNING_TASKS);
    scheduler->timer = ccnet_timer_new (schedule_merge_tasks,
                                        scheduler,
                                        SCHEDULE_INTERVAL);
    return 0;
}
