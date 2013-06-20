/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "utils.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

#include <ccnet.h>
#include <ccnet/job-mgr.h>
#include <pthread.h>

#include "seafile-session.h"
#include "seafile-config.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "fs-mgr.h"
#include "seafile-error.h"
#include "seafile-crypt.h"
#include "merge-new.h"
#include "seafile-error.h"

#include "seaf-db.h"

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
    GString *sql = g_string_new (NULL);
    int ret = 0;

    char *esc_path = seaf_db_escape_string (mgr->seaf->db, path);
    g_string_printf (sql,
                     "INSERT INTO VirtualRepo VALUES ('%s', '%s', '%s', '%s')",
                     repo_id, origin_repo_id, esc_path, base_commit);
    g_free (esc_path);

    if (seaf_db_query (mgr->seaf->db, sql->str) < 0)
        ret = -1;

    g_string_free (sql, TRUE);
    return ret;
}

static int
do_create_virtual_repo (SeafRepoManager *mgr,
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
        repo->enc_version = CURRENT_ENC_VERSION;
        seaf_repo_generate_magic (repo, passwd);
    }

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

static gboolean
is_virtual_repo_duplicated (SeafRepoManager *mgr,
                            const char *origin_repo_id,
                            const char *path,
                            const char *owner)
{
    GString *sql = g_string_new (NULL);
    char *esc_path = seaf_db_escape_string (mgr->seaf->db, path);
    gboolean db_err;
    gboolean ret;

    g_string_printf (sql,
                     "SELECT 1 FROM VirtualRepo v, RepoOwner o WHERE"
                     " v.origin_repo = '%s' AND v.path = '%s' AND o.owner_id = '%s'"
                     " AND o.repo_id = v.repo_id",
                     origin_repo_id, esc_path, owner);
    g_free (esc_path);

    ret = seaf_db_check_for_existence (mgr->seaf->db, sql->str, &db_err);
    g_string_free (sql, TRUE);

    return ret;
}

char *
seaf_repo_manager_create_virtual_repo (SeafRepoManager *mgr,
                                       const char *origin_repo_id,
                                       const char *path,
                                       const char *repo_name,
                                       const char *repo_desc,
                                       const char *owner,
                                       GError **error)
{
    SeafRepo *origin_repo = NULL;
    SeafCommit *origin_head = NULL;
    char *repo_id = NULL;
    char *dir_id = NULL;
    char *passwd = NULL;

    if (seaf_repo_manager_is_virtual_repo (mgr, origin_repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Cannot create sub-library from a sub-library");
        return NULL;
    }

    if (is_virtual_repo_duplicated (mgr, origin_repo_id, path, owner)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Sub-libray already exists");
        return NULL;
    }

    origin_repo = seaf_repo_manager_get_repo (mgr, origin_repo_id);
    if (!origin_repo) {
        seaf_warning ("Failed to get origin repo %.10s\n", origin_repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Origin library not exists");
        return NULL;
    }

    if (origin_repo->encrypted) {
        passwd = seaf_passwd_manager_get_repo_passwd (seaf->passwd_mgr,
                                                      origin_repo_id,
                                                      owner);
        if (!passwd) {
            seaf_warning ("Password for repo %.10s and user %s is not set.\n",
                          origin_repo_id, owner);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Password is not provided");
            goto error;
        }
    }

    origin_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                  origin_repo->head->commit_id);
    if (!origin_head) {
        seaf_warning ("Failed to get head commit %.8s.\n",
                      origin_repo->head->commit_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Bad origin repo head");
        goto error;
    }

    dir_id = seaf_fs_manager_get_seafdir_id_by_path (seaf->fs_mgr,
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

    if (do_create_virtual_repo (mgr, repo_id, repo_name, repo_desc,
                                dir_id, owner, passwd, error) < 0)
        goto error;

    if (seaf_repo_manager_set_repo_owner (mgr, repo_id, owner) < 0) {
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
    return repo_id;

error:
    seaf_repo_unref (origin_repo);
    seaf_commit_unref (origin_head);
    g_free (repo_id);
    g_free (dir_id);
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
    char sql[256];
    SeafVirtRepo *vinfo = NULL;

    snprintf (sql, 256,
              "SELECT repo_id, origin_repo, path, base_commit FROM VirtualRepo "
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

gboolean
seaf_repo_manager_is_virtual_repo (SeafRepoManager *mgr, const char *repo_id)
{
    char sql[256];
    gboolean db_err;

    snprintf (sql, 256,
              "SELECT 1 FROM VirtualRepo WHERE repo_id = '%s'", repo_id);
    return seaf_db_check_for_existence (seaf->db, sql, &db_err);
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
    char sql[256];

    snprintf (sql, 256,
              "SELECT RepoOwner.repo_id FROM RepoOwner, VirtualRepo "
              "WHERE owner_id='%s' "
              "AND RepoOwner.repo_id = VirtualRepo.repo_id",
              owner);

    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_virtual_repo_ids, &id_list) < 0) {
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
    char sql[256];

    snprintf (sql, 256,
              "SELECT repo_id, origin_repo, path, base_commit "
              "FROM VirtualRepo WHERE origin_repo='%s'",
              origin_repo);
    if (seaf_db_foreach_selected_row (mgr->seaf->db, sql, 
                                      collect_virtual_info, &ret) < 0) {
        return NULL;
    }

    return g_list_reverse (ret);
}

static void
set_virtual_repo_base_commit (SeafRepo *repo, const char *base_commit_id)
{
    char sql[256];

    snprintf (sql, 256,
              "UPDATE VirtualRepo SET base_commit='%s' WHERE repo_id='%s'",
              base_commit_id, repo->id);
    seaf_db_query (seaf->db, sql);
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

    head = seaf_commit_manager_get_commit (seaf->commit_mgr, repo->head->commit_id);
    if (!head) {
        seaf_warning ("Failed to get commit %.8s.\n", repo->head->commit_id);
        goto out;
    }

    vinfo_list = seaf_repo_manager_get_virtual_info_by_origin (mgr,
                                                               origin_repo_id);
    for (ptr = vinfo_list; ptr; ptr = ptr->next) {
        vinfo = ptr->data;
        dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                                   head->root_id,
                                                   vinfo->path,
                                                   &error);
        if (error) {
            if (error->code == SEAF_ERR_PATH_NO_EXIST) {
                seaf_debug ("Delete virtual repo %.10s.\n", vinfo->repo_id);
                seaf_repo_manager_del_repo (mgr, vinfo->repo_id);
                seaf_share_manager_remove_repo (seaf->share_mgr, vinfo->repo_id);
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
    head = seaf_commit_manager_get_commit (seaf->commit_mgr, repo->head->commit_id);
    if (!head) {
        seaf_warning ("Failed to get commit %.8s.\n", repo->head->commit_id);
        ret = -1;
        goto out;
    }

    orig_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                orig_repo->head->commit_id);
    if (!orig_head) {
        seaf_warning ("Failed to get commit %.8s.\n", orig_repo->head->commit_id);
        ret = -1;
        goto out;
    }

    base = seaf_commit_manager_get_commit (seaf->commit_mgr, vinfo->base_commit);
    if (!base) {
        seaf_warning ("Failed to get commit %.8s.\n", vinfo->base_commit);
        ret = -1;
        goto out;
    }

    /* fs roots */
    root = head->root_id;

    base_root = seaf_fs_manager_get_seafdir_id_by_path (seaf->fs_mgr,
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

        set_virtual_repo_base_commit (repo, orig_repo->head->commit_id);
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

        set_virtual_repo_base_commit (repo, new_base_commit);

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
        memcpy (opt.remote_head, head->commit_id, 40);
        opt.do_merge = TRUE;

        roots[0] = base_root; /* base */
        roots[1] = orig_root; /* head */
        roots[2] = root;  /* remote */

        /* Merge virtual into origin */
        if (seaf_merge_trees (3, roots, &opt) < 0) {
            seaf_warning ("Failed to merge virtual repo %.10s.\n", repo_id);
            ret = -1;
            goto out;
        }

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

        set_virtual_repo_base_commit (repo, new_base_commit);

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

    if (g_queue_find_custom (scheduler->queue, task, task_cmp) != NULL)
        seaf_debug ("Task for repo %.8s is already queued.\n", repo_id);
    else
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
