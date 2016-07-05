#include "common.h"
#include "log.h"

#include <pthread.h>

#include <ccnet/job-mgr.h>

#include "seafile-session.h"
#include "seafile-object.h"
#include "seafile-error.h"

#include "copy-mgr.h"

#include "utils.h"

#include "log.h"

#define DEFAULT_MAX_THREADS 50

struct _SeafCopyManagerPriv {
    GHashTable *copy_tasks;
    pthread_mutex_t lock;
    CcnetJobManager *job_mgr;
};

static void
copy_task_free (CopyTask *task)
{
    if (!task) return;

    g_free (task);
}

SeafCopyManager *
seaf_copy_manager_new (struct _SeafileSession *session)
{
    SeafCopyManager *mgr = g_new0 (SeafCopyManager, 1);

    mgr->session = session;
    mgr->priv = g_new0 (struct _SeafCopyManagerPriv, 1);
    mgr->priv->copy_tasks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                   g_free,
                                                   (GDestroyNotify)copy_task_free);
    pthread_mutex_init (&mgr->priv->lock, NULL);

    mgr->max_files = g_key_file_get_int64 (session->config,
                                           "web_copy", "max_files", NULL);
    mgr->max_size = g_key_file_get_int64 (session->config,
                                          "web_copy", "max_size", NULL);
    /* size is given in MB */
    mgr->max_size <<= 20;

    return mgr;
}

int
seaf_copy_manager_start (SeafCopyManager *mgr)
{
    mgr->priv->job_mgr = ccnet_job_manager_new (DEFAULT_MAX_THREADS);

    return 1;
}

SeafileCopyTask *
seaf_copy_manager_get_task (SeafCopyManager *mgr,
                            const char *task_id)
{
    SeafCopyManagerPriv *priv = mgr->priv;
    CopyTask *task;
    SeafileCopyTask *t = NULL;

    pthread_mutex_lock (&priv->lock);

    task = g_hash_table_lookup (priv->copy_tasks, task_id);
    if (task) {
        t = seafile_copy_task_new ();
        g_object_set (t, "done", task->done, "total", task->total,
                      "canceled", task->canceled, "failed", task->failed,
                      "successful", task->successful,
                      NULL);
    }

    pthread_mutex_unlock (&priv->lock);

    return t;
}

struct CopyThreadData {
    SeafCopyManager *mgr;
    char src_repo_id[37];
    char *src_path;
    char *src_filename;
    char dst_repo_id[37];
    char *dst_path;
    char *dst_filename;
    int replace;
    char *modifier;
    CopyTask *task;
    CopyTaskFunc func;
};
typedef struct CopyThreadData CopyThreadData;

static void *
copy_thread (void *vdata)
{
    CopyThreadData *data = vdata;

    data->func (data->src_repo_id, data->src_path, data->src_filename,
                data->dst_repo_id, data->dst_path, data->dst_filename,
                data->replace, data->modifier, data->task);

    return vdata;
}

static void
copy_done (void *vdata)
{
    CopyThreadData *data = vdata;

    g_free (data->src_path);
    g_free (data->src_filename);
    g_free (data->dst_path);
    g_free (data->dst_filename);
    g_free (data->modifier);
    g_free (data);
}

char *
seaf_copy_manager_add_task (SeafCopyManager *mgr,
                            const char *src_repo_id,
                            const char *src_path,
                            const char *src_filename,
                            const char *dst_repo_id,
                            const char *dst_path,
                            const char *dst_filename,
                            int replace,
                            const char *modifier,
                            gint64 total_files,
                            CopyTaskFunc function,
                            gboolean need_progress)
{
    SeafCopyManagerPriv *priv = mgr->priv;
    char *task_id = NULL;
    CopyTask *task = NULL;
    struct CopyThreadData *data;

    if (need_progress) {
        task_id = gen_uuid();
        task = g_new0 (CopyTask, 1);
        memcpy (task->task_id, task_id, 36);
        task->total = total_files;

        pthread_mutex_lock (&priv->lock);
        g_hash_table_insert (priv->copy_tasks, g_strdup(task_id), task);
        pthread_mutex_unlock (&priv->lock);
    }

    data = g_new0 (CopyThreadData, 1);
    data->mgr = mgr;
    memcpy (data->src_repo_id, src_repo_id, 36);
    data->src_path = g_strdup(src_path);
    data->src_filename = g_strdup(src_filename);
    memcpy (data->dst_repo_id, dst_repo_id, 36);
    data->dst_path = g_strdup(dst_path);
    data->dst_filename = g_strdup(dst_filename);
    data->replace = replace;
    data->modifier = g_strdup(modifier);
    data->task = task;
    data->func = function;

    ccnet_job_manager_schedule_job (mgr->priv->job_mgr,
                                    copy_thread,
                                    copy_done,
                                    data);
    return task_id;
}

int
seaf_copy_manager_cancel_task (SeafCopyManager *mgr, const char *task_id)
{
    SeafCopyManagerPriv *priv = mgr->priv;
    CopyTask *task;

    pthread_mutex_lock (&priv->lock);

    task = g_hash_table_lookup (priv->copy_tasks, task_id);

    pthread_mutex_unlock (&priv->lock);

    if (task) {
        if (task->canceled || task->failed || task->successful)
            return -1;
        g_atomic_int_set (&task->canceled, 1);
    }

    return 0;
}
