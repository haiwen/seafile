/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <glib/gstdio.h>
#include <ctype.h>

#include <sys/stat.h>
#ifndef WIN32
#include <dirent.h>
#endif
#include "utils.h"

#include "seafile-session.h"
#include "fs-mgr.h"
#include "repo-mgr.h"
#include "seafile-error.h"
#include "seafile-rpc.h"
#include "common/mq-mgr.h"
#include "seafile-config.h"
#include "seafile-object.h"
#include "seafile-error-impl.h"
#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

#include "../daemon/vc-utils.h"


/* -------- Utilities -------- */
static GObject*
convert_repo (SeafRepo *r)
{
    SeafileRepo *repo = NULL;

    if (r->head == NULL)
        return NULL;

    if (r->worktree_invalid && !seafile_session_config_get_allow_invalid_worktree(seaf))
        return NULL;

    repo = seafile_repo_new ();
    if (!repo)
        return NULL;

    g_object_set (repo, "id", r->id, "name", r->name,
                  "desc", r->desc, "encrypted", r->encrypted,
                  "magic", r->magic, "enc_version", r->enc_version,
                  "head_cmmt_id", r->head ? r->head->commit_id : NULL,
                  "root", r->root_id,
                  "version", r->version, "last_modify", (int)r->last_modify,
                  NULL);
    g_object_set (repo,
                  "repo_id", r->id, "repo_name", r->name,
                  "repo_desc", r->desc, "last_modified", (int)r->last_modify,
                  NULL);

    g_object_set (repo, "worktree", r->worktree,
                  "relay-id", r->relay_id,
                  "worktree-invalid", r->worktree_invalid,
                  "last-sync-time", r->last_sync_time,
                  "auto-sync", r->auto_sync,
                  NULL);

    return (GObject *)repo;
}

static void
free_repo_obj (gpointer repo)
{
    if (!repo)
        return;
    g_object_unref ((GObject *)repo);
}

static GList *
convert_repo_list (GList *inner_repos)
{
    GList *ret = NULL, *ptr;
    GObject *repo = NULL;

    for (ptr = inner_repos; ptr; ptr=ptr->next) {
        SeafRepo *r = ptr->data;
        repo = convert_repo (r);
        if (!repo) {
            g_list_free_full (ret, free_repo_obj);
            return NULL;
        }

        ret = g_list_prepend (ret, repo);
    }

    return g_list_reverse (ret);
}

/*
 * RPC functions only available for clients.
 */

#include "sync-mgr.h"

int
seafile_set_config (const char *key, const char *value, GError **error)
{
    return seafile_session_config_set_string(seaf, key, value);
}

char *
seafile_get_config (const char *key, GError **error)
{
    return seafile_session_config_get_string(seaf, key);
}

int
seafile_set_config_int (const char *key, int value, GError **error)
{
    return seafile_session_config_set_int(seaf, key, value);
}

int
seafile_get_config_int (const char *key, GError **error)
{
    gboolean exists = TRUE;

    int ret = seafile_session_config_get_int(seaf, key, &exists);

    if (!exists) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Config not exists");
        return -1;
    }

    return ret;
}

int
seafile_set_upload_rate_limit (int limit, GError **error)
{
    if (limit < 0)
        limit = 0;

    seaf->sync_mgr->upload_limit = limit;

    return seafile_session_config_set_int (seaf, KEY_UPLOAD_LIMIT, limit);
}

int
seafile_set_download_rate_limit (int limit, GError **error)
{
    if (limit < 0)
        limit = 0;

    seaf->sync_mgr->download_limit = limit;

    return seafile_session_config_set_int (seaf, KEY_DOWNLOAD_LIMIT, limit);
}

char *
seafile_gen_default_worktree (const char *worktree_parent,
                              const char *repo_name,
                              GError **error)
{
    if (!worktree_parent || !repo_name) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Empty args");
        return NULL;
    }

    return seaf_clone_manager_gen_default_worktree (seaf->clone_mgr,
                                                    worktree_parent,
                                                    repo_name);
}

int
seafile_check_path_for_clone (const char *path, GError **error)
{
    if (!seaf_clone_manager_check_worktree_path(seaf->clone_mgr, path, error)) {
        return -1;
    }

    return 0;
}

char *
seafile_clone (const char *repo_id,
               int repo_version,
               const char *repo_name,
               const char *worktree,
               const char *token,
               const char *passwd,
               const char *magic,
               const char *email,
               const char *random_key,
               int enc_version,
               const char *more_info,
               GError **error)
{
    if (!repo_id || strlen(repo_id) != 36) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    if (!worktree) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Worktre must be specified");
        return NULL;
    }

    if (!token || !email ) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument can't be NULL");
        return NULL;
    }

    return seaf_clone_manager_add_task (seaf->clone_mgr,
                                        repo_id, repo_version,
                                        repo_name, token,
                                        passwd, magic,
                                        enc_version,
                                        random_key,
                                        worktree,
                                        email, more_info,
                                        error);
}

char *
seafile_download (const char *repo_id,
                  int repo_version,
                  const char *repo_name,
                  const char *wt_parent,
                  const char *token,
                  const char *passwd,
                  const char *magic,
                  const char *email,
                  const char *random_key,
                  int enc_version,
                  const char *more_info,
                  GError **error)
{
    if (!repo_id || strlen(repo_id) != 36) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    if (!wt_parent) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Worktre must be specified");
        return NULL;
    }

    if (!token || !email ) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument can't be NULL");
        return NULL;
    }

    return seaf_clone_manager_add_download_task (seaf->clone_mgr,
                                                 repo_id, repo_version,
                                                 repo_name, token,
                                                 passwd, magic,
                                                 enc_version, random_key,
                                                 wt_parent,
                                                 email, more_info,
                                                 error);
}

int
seafile_cancel_clone_task (const char *repo_id, GError **error)
{
    return seaf_clone_manager_cancel_task (seaf->clone_mgr, repo_id);
}

GList *
seafile_get_clone_tasks (GError **error)
{
    GList *tasks, *ptr;
    GList *ret = NULL;
    CloneTask *task;
    SeafileCloneTask *t;

    tasks = seaf_clone_manager_get_tasks (seaf->clone_mgr);
    for (ptr = tasks; ptr != NULL; ptr = ptr->next) {
        task = ptr->data;
        t = g_object_new (SEAFILE_TYPE_CLONE_TASK,
                          "state", clone_task_state_to_str(task->state),
                          "error", task->error,
                          "repo_id", task->repo_id,
                          "repo_name", task->repo_name,
                          "worktree", task->worktree,
                          NULL);
        ret = g_list_prepend (ret, t);
    }

    g_list_free (tasks);
    return ret;
}

int
seafile_sync (const char *repo_id, const char *peer_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Repo ID should not be null");
        return -1;
    }

    return seaf_sync_manager_add_sync_task (seaf->sync_mgr, repo_id, error);
}

static SeafileTask *
convert_http_task (HttpTxTask *task)
{
    SeafileTask *t = seafile_task_new();

    g_object_set (t,
                  "repo_id", task->repo_id,
                  "state", http_task_state_to_str(task->state),
                  "rt_state", http_task_rt_state_to_str(task->runtime_state),
                  NULL);

    if (task->type == HTTP_TASK_TYPE_DOWNLOAD) {
        g_object_set (t, "ttype", "download", NULL);
        if (task->runtime_state == HTTP_TASK_RT_STATE_BLOCK) {
            g_object_set (t, "block_total", task->total_download,
                          "block_done", task->done_download,
                          NULL);
            g_object_set (t, "rate", http_tx_task_get_rate(task), NULL);
        } else if (task->runtime_state == HTTP_TASK_RT_STATE_FS) {
            g_object_set (t, "fs_objects_total", task->n_fs_objs,
                          "fs_objects_done", task->done_fs_objs,
                          NULL);
        }
    } else {
        g_object_set (t, "ttype", "upload", NULL);
        if (task->runtime_state == HTTP_TASK_RT_STATE_BLOCK) {
            SyncInfo *info = seaf_sync_manager_get_sync_info (seaf->sync_mgr, task->repo_id);
            if (info && info->multipart_upload) {
                g_object_set (t, "block_total", info->total_bytes,
                              "block_done", info->uploaded_bytes,
                              NULL);
            } else {
                g_object_set (t, "block_total", (gint64)task->n_blocks,
                              "block_done", (gint64)task->done_blocks,
                              NULL);
            }
            g_object_set (t, "rate", http_tx_task_get_rate(task), NULL);
        }
    }

    return t;
}

GObject *
seafile_find_transfer_task (const char *repo_id, GError *error)
{
    HttpTxTask *http_task;

    http_task = http_tx_manager_find_task (seaf->http_tx_mgr, repo_id);
    if (http_task)
        return (GObject *)convert_http_task (http_task);

    return NULL;
}

int
seafile_get_upload_rate(GError **error)
{
    return seaf->sync_mgr->last_sent_bytes;
}

int
seafile_get_download_rate(GError **error)
{
    return seaf->sync_mgr->last_recv_bytes;
}

GObject *
seafile_get_repo_sync_task (const char *repo_id, GError **error)
{
    SeafRepo *repo;
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);

    if (!repo) {
        return NULL;
    }

    SyncInfo *info = seaf_sync_manager_get_sync_info (seaf->sync_mgr, repo_id);
    if (!info || !info->current_task)
        return NULL;

    SyncTask *task = info->current_task;
    const char *sync_state;
    char allzeros[41] = {0};

    if (!info->in_sync && memcmp(allzeros, info->head_commit, 41) == 0) {
        sync_state = "waiting for sync";
    } else {
        sync_state = sync_state_to_str(task->state);
    }

    SeafileSyncTask *s_task;
    s_task = g_object_new (SEAFILE_TYPE_SYNC_TASK,
                           "force_upload", task->is_manual_sync,
                           "state", sync_state,
                           "error", task->error,
                           "repo_id", info->repo_id,
                           NULL);

    return (GObject *)s_task;
}

int
seafile_set_repo_property (const char *repo_id,
                           const char *key,
                           const char *value,
                           GError **error)
{
    int ret;

    if (repo_id == NULL || key == NULL || value == NULL) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    SeafRepo *repo;
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "Can't find Repo %s", repo_id);
        return -1;
    }

    ret = seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                               repo->id, key, value);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Failed to set key for repo %s", repo_id);
        return -1;
    }

    return 0;
}

gchar *
seafile_get_repo_property (const char *repo_id,
                           const char *key,
                           GError **error)
{
    char *value = NULL;

    if (!repo_id || !key) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return NULL;
    }

    SeafRepo *repo;
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "Can't find Repo %s", repo_id);
        return NULL;
    }

    value = seaf_repo_manager_get_repo_property (seaf->repo_mgr, repo->id, key);
    return value;
}

int
seafile_update_repos_server_host (const char *old_server_url,
                                  const char *new_server_url,
                                  GError **error)
{
    if (!old_server_url || !new_server_url) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    return seaf_repo_manager_update_repos_server_host(
        seaf->repo_mgr, old_server_url, new_server_url);
}

int
seafile_calc_dir_size (const char *path, GError **error)
{
    if (!path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    gint64 size_64 = ccnet_calc_directory_size(path, error);
    if (size_64 < 0) {
        seaf_warning ("failed to calculate dir size for %s\n", path);
        return -1;
    }

    /* get the size in MB */
    int size = (int) (size_64 >> 20);
    return size;
}

int
seafile_disable_auto_sync (GError **error)
{
    return seaf_sync_manager_disable_auto_sync (seaf->sync_mgr);
}

int
seafile_enable_auto_sync (GError **error)
{
    return seaf_sync_manager_enable_auto_sync (seaf->sync_mgr);
}

int seafile_is_auto_sync_enabled (GError **error)
{
    return seaf_sync_manager_is_auto_sync_enabled (seaf->sync_mgr);
}

char *
seafile_get_path_sync_status (const char *repo_id,
                              const char *path,
                              int is_dir,
                              GError **error)
{
    char *canon_path = NULL;
    int len;
    char *status;

    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    /* Empty path means to get status of the worktree folder. */
    if (strcmp (path, "") != 0) {
        if (*path == '/')
            ++path;
        canon_path = g_strdup(path);
        len = strlen(canon_path);
        if (canon_path[len-1] == '/')
            canon_path[len-1] = 0;
    } else {
        canon_path = g_strdup(path);
    }

    status = seaf_sync_manager_get_path_sync_status (seaf->sync_mgr,
                                                     repo_id,
                                                     canon_path,
                                                     is_dir);
    g_free (canon_path);
    return status;
}

int
seafile_mark_file_locked (const char *repo_id, const char *path, GError **error)
{
    char *canon_path = NULL;
    int len;
    int ret;

    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (*path == '/')
        ++path;

    if (path[0] == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid path");
        return -1;
    }

    canon_path = g_strdup(path);
    len = strlen(canon_path);
    if (canon_path[len-1] == '/')
        canon_path[len-1] = 0;

    ret = seaf_filelock_manager_mark_file_locked (seaf->filelock_mgr,
                                                  repo_id, path, FALSE);

    g_free (canon_path);
    return ret;
}

int
seafile_mark_file_unlocked (const char *repo_id, const char *path, GError **error)
{
    char *canon_path = NULL;
    int len;
    int ret;

    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (*path == '/')
        ++path;

    if (path[0] == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid path");
        return -1;
    }

    canon_path = g_strdup(path);
    len = strlen(canon_path);
    if (canon_path[len-1] == '/')
        canon_path[len-1] = 0;

    ret = seaf_filelock_manager_mark_file_unlocked (seaf->filelock_mgr,
                                                    repo_id, path);

    g_free (canon_path);
    return ret;
}

json_t *
seafile_get_sync_notification (GError **error)
{
    return seaf_mq_manager_pop_message (seaf->mq_mgr);
}

char *
seafile_get_server_property (const char *server_url, const char *key, GError **error)
{
    if (!server_url || !key) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument should not be null");
        return NULL;
    }

    return seaf_repo_manager_get_server_property (seaf->repo_mgr,
                                                  server_url,
                                                  key);
}

int
seafile_set_server_property (const char *server_url,
                             const char *key,
                             const char *value,
                             GError **error)
{
    if (!server_url || !key || !value) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument should not be null");
        return -1;
    }

    return seaf_repo_manager_set_server_property (seaf->repo_mgr,
                                                  server_url,
                                                  key, value);
}

GList *
seafile_get_file_sync_errors (int offset, int limit, GError **error)
{
    return seaf_repo_manager_get_file_sync_errors (seaf->repo_mgr, offset, limit);
}

int
seafile_del_file_sync_error_by_id (int id, GError **error)
{
    return seaf_repo_manager_del_file_sync_error_by_id (seaf->repo_mgr, id);
}

GList*
seafile_get_repo_list (int start, int limit, GError **error)
{
    GList *repos = seaf_repo_manager_get_repo_list(seaf->repo_mgr, start, limit);
    GList *ret = NULL;

    ret = convert_repo_list (repos);

    g_list_free (repos);

    return ret;
}

GObject*
seafile_get_repo (const char *repo_id, GError **error)
{
    SeafRepo *r;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    r = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    /* Don't return repo that's not checked out. */
    if (r == NULL)
        return NULL;

    GObject *repo = convert_repo (r);

    return repo;
}

static
int do_unsync_repo(SeafRepo *repo)
{
    if (!seaf->started) {
        seaf_message ("System not started, skip removing repo.\n");
        return -1;
    }

    if (repo->auto_sync && (repo->sync_interval == 0))
        seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo->id);

    seaf_sync_manager_cancel_sync_task (seaf->sync_mgr, repo->id);

    SyncInfo *info = seaf_sync_manager_get_sync_info (seaf->sync_mgr, repo->id);

    /* If we are syncing the repo,
     * we just mark the repo as deleted and let sync-mgr actually delete it.
     * Otherwise we are safe to delete the repo.
     */
    char *worktree = g_strdup (repo->worktree);
    if (info != NULL && info->in_sync) {
        seaf_repo_manager_mark_repo_deleted (seaf->repo_mgr, repo);
    } else {
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
    }

    g_free (worktree);

    return 0;
}

static void
cancel_clone_tasks_by_account (const char *account_server_url, const char *account_email)
{
    GList *ptr, *tasks;
    CloneTask *task;

    tasks = seaf_clone_manager_get_tasks (seaf->clone_mgr);
    for (ptr = tasks; ptr != NULL; ptr = ptr->next) {
        task = ptr->data;

        if (g_strcmp0(account_server_url, task->server_url) == 0
            && g_strcmp0(account_email, task->email) == 0) {
            seaf_clone_manager_cancel_task (seaf->clone_mgr, task->repo_id);
        }
    }

    g_list_free (tasks);
}

int
seafile_unsync_repos_by_account (const char *server_url, const char *email, GError **error)
{
    if (!server_url || !email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }
    char *canon_server_url = canonical_server_url (server_url);

    GList *ptr, *repos = seaf_repo_manager_get_repo_list(seaf->repo_mgr, -1, -1);
    if (!repos) {
        return 0;
    }

    for (ptr = repos; ptr; ptr = ptr->next) {
        SeafRepo *repo = (SeafRepo*)ptr->data;
        if (g_strcmp0(repo->server_url, canon_server_url) == 0 && g_strcmp0(repo->email, email) == 0) {
            if (do_unsync_repo(repo) < 0) {
                return -1;
            }
        }
    }

    g_list_free (repos);
    g_free (canon_server_url);

    cancel_clone_tasks_by_account (server_url, email);

    return 0;
}

int
seafile_remove_repo_tokens_by_account (const char *server_url, const char *email, GError **error)
{
    if (!server_url || !email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }
    char *canon_server_url = canonical_server_url (server_url);

    GList *ptr, *repos = seaf_repo_manager_get_repo_list(seaf->repo_mgr, -1, -1);
    if (!repos) {
        return 0;
    }

    for (ptr = repos; ptr; ptr = ptr->next) {
        SeafRepo *repo = (SeafRepo*)ptr->data;
        if (g_strcmp0(repo->server_url, canon_server_url) == 0 && g_strcmp0(repo->email, email) == 0) {
            if (seaf_repo_manager_remove_repo_token(seaf->repo_mgr, repo) < 0) {
                return -1;
            }
        }
    }

    g_list_free (repos);
    g_free (canon_server_url);

    cancel_clone_tasks_by_account (server_url, email);

    return 0;
}

int
seafile_set_repo_token (const char *repo_id,
                        const char *token,
                        GError **error)
{
    int ret;

    if (repo_id == NULL || token == NULL) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    SeafRepo *repo;
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "Can't find Repo %s", repo_id);
        return -1;
    }

    ret = seaf_repo_manager_set_repo_token (seaf->repo_mgr,
                                            repo, token);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Failed to set token for repo %s", repo_id);
        return -1;
    }

    return 0;
}

int
seafile_destroy_repo (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }
    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return -1;
    }

    return do_unsync_repo(repo);
}


GObject *
seafile_generate_magic_and_random_key(int enc_version,
                                      const char* repo_id,
                                      const char *passwd,
                                      GError **error)
{
    if (!repo_id || !passwd) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    gchar salt[65] = {0};
    gchar magic[65] = {0};
    gchar random_key[97] = {0};

    if (enc_version >= 3 && seafile_generate_repo_salt (salt) < 0) {
        return NULL;
    }

    seafile_generate_magic (enc_version, repo_id, passwd, salt, magic);
    if (seafile_generate_random_key (passwd, enc_version, salt, random_key) < 0) {
        return NULL;
    }
    
    SeafileEncryptionInfo *sinfo;
    sinfo = g_object_new (SEAFILE_TYPE_ENCRYPTION_INFO,
                          "repo_id", repo_id,
                          "passwd", passwd,
                          "enc_version", enc_version,
                          "magic", magic,
                          "random_key", random_key,
                          NULL);

    if (enc_version >= 3)
        g_object_set (sinfo, "salt", salt, NULL);

    return (GObject *)sinfo;

}

#include "diff-simple.h"

inline static const char*
get_diff_status_str(char status)
{
    if (status == DIFF_STATUS_ADDED)
        return "add";
    if (status == DIFF_STATUS_DELETED)
        return "del";
    if (status == DIFF_STATUS_MODIFIED)
        return "mod";
    if (status == DIFF_STATUS_RENAMED)
        return "mov";
    if (status == DIFF_STATUS_DIR_ADDED)
        return "newdir";
    if (status == DIFF_STATUS_DIR_DELETED)
        return "deldir";
    return NULL;
}

GList *
seafile_diff (const char *repo_id, const char *arg1, const char *arg2, int fold_dir_diff, GError **error)
{
    SeafRepo *repo;
    char *err_msgs = NULL;
    GList *diff_entries, *p;
    GList *ret = NULL;

    if (!repo_id || !arg1 || !arg2) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    if (!is_uuid_valid (repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    if ((arg1[0] != 0 && !is_object_id_valid (arg1)) || !is_object_id_valid(arg2)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid commit id");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return NULL;
    }

    diff_entries = seaf_repo_diff (repo, arg1, arg2, fold_dir_diff, &err_msgs);
    if (err_msgs) {
        g_set_error (error, SEAFILE_DOMAIN, -1, "%s", err_msgs);
        g_free (err_msgs);
        return NULL;
    }

    for (p = diff_entries; p != NULL; p = p->next) {
        DiffEntry *de = p->data;
        SeafileDiffEntry *entry = g_object_new (
            SEAFILE_TYPE_DIFF_ENTRY,
            "status", get_diff_status_str(de->status),
            "name", de->name,
            "new_name", de->new_name,
            NULL);
        ret = g_list_prepend (ret, entry);
    }

    for (p = diff_entries; p != NULL; p = p->next) {
        DiffEntry *de = p->data;
        diff_entry_free (de);
    }
    g_list_free (diff_entries);

    return g_list_reverse (ret);
}

int
seafile_shutdown (GError **error)
{
    seaf_warning ("Got an exit command. Now exiting\n");
    exit(0);
    return 0;
}

char*
seafile_sync_error_id_to_str (int error_id, GError **error)
{
    return g_strdup(sync_error_id_to_str (error_id));
}
