#include "common.h"

#include <ccnet/timer.h>

#include "seafile-session.h"
#include "scheduler.h"

typedef struct SchedulerPriv {
    GQueue *repo_size_job_queue;
    int n_running_repo_size_jobs;

    CcnetTimer *sched_timer;
} SchedulerPriv;

typedef struct RepoSizeJob {
    Scheduler *sched;
    char repo_id[37];
} RepoSizeJob;

#define SCHEDULER_INTV 10000    /* 10s */
#define CONCURRENT_JOBS 5

static int
schedule_pulse (void *vscheduler);
static void*
compute_repo_size (void *vjob);
static void
compute_repo_size_done (void *vjob);

Scheduler *
scheduler_new (SeafileSession *session)
{
    Scheduler *sched = g_new0 (Scheduler, 1);

    if (!sched)
        return NULL;

    sched->priv = g_new0 (SchedulerPriv, 1);
    if (!sched->priv) {
        g_free (sched);
        return NULL;
    }

    sched->seaf = session;

    return sched;
}

int
scheduler_init (Scheduler *scheduler)
{
    scheduler->priv->repo_size_job_queue = g_queue_new ();
    scheduler->priv->sched_timer = ccnet_timer_new (schedule_pulse,
                                              scheduler,
                                              SCHEDULER_INTV);

    return 0;
}

void
schedule_repo_size_computation (Scheduler *scheduler, const char *repo_id)
{
    RepoSizeJob *job = g_new0(RepoSizeJob, 1);

    job->sched = scheduler;
    memcpy (job->repo_id, repo_id, 37);

    g_queue_push_tail (scheduler->priv->repo_size_job_queue, job);
}

static int
schedule_pulse (void *vscheduler)
{
    Scheduler *sched = vscheduler;
    RepoSizeJob *job;

    while (sched->priv->n_running_repo_size_jobs < CONCURRENT_JOBS) {
        job = (RepoSizeJob *)g_queue_pop_head (sched->priv->repo_size_job_queue);
        if (!job)
            break;

        int ret = ccnet_job_manager_schedule_job (sched->seaf->job_mgr,
                                        compute_repo_size,
                                        compute_repo_size_done,
                                        job);
        if (ret < 0) {
            g_warning ("[scheduler] failed to start compute job.\n");
            g_queue_push_head (sched->priv->repo_size_job_queue, job);
            break;
        }
        ++(sched->priv->n_running_repo_size_jobs);
    }

    return 1;
}

static int
set_repo_size (SeafDB *db, const char *repo_id, const char *head_id, guint64 size)
{
    char sql[256];

    if (seaf_db_type(db) == SEAF_DB_TYPE_PGSQL) {
        gboolean err;
        snprintf (sql, sizeof(sql),
                  "SELECT 1 FROM RepoSize WHERE repo_id='%s'",
                  repo_id);
        if (seaf_db_check_for_existence(db, sql, &err))
            snprintf (sql, sizeof(sql),
                      "UPDATE RepoSize SET size=%"G_GUINT64_FORMAT
                      ", head_id='%s' WHERE repo_id='%s'",
                      size, head_id, repo_id);
        else
            snprintf (sql, sizeof(sql),
                      "INSERT INTO RepoSize VALUES('%s', %"G_GUINT64_FORMAT", '%s')",
                      repo_id, size, head_id);
        if (err)
            return -1;
        if (seaf_db_query (db, sql) < 0)
            return -1;
    } else {
        snprintf (sql, sizeof(sql),
                  "REPLACE INTO RepoSize (repo_id, size, head_id) "
                  "VALUES ('%s', %"G_GUINT64_FORMAT", '%s')",
                  repo_id, size, head_id);
        if (seaf_db_query (db, sql) < 0)
            return -1;
    }

    return 0;
}

static char *
get_cached_head_id (SeafDB *db, const char *repo_id)
{
    char sql[256];

    snprintf (sql, sizeof(sql), "SELECT head_id FROM RepoSize WHERE repo_id='%s'",
              repo_id);
    return seaf_db_get_string (db, sql);
}

static void*
compute_repo_size (void *vjob)
{
    RepoSizeJob *job = vjob;
    Scheduler *sched = job->sched;
    SeafRepo *repo = NULL;
    SeafCommit *head = NULL;
    char *cached_head_id = NULL;
    BlockList *bl;
    char *block_id;
    BlockMetadata *bmd;
    guint64 size = 0;

    repo = seaf_repo_manager_get_repo (sched->seaf->repo_mgr, job->repo_id);
    if (!repo) {
        g_warning ("[scheduler] failed to get repo %s.\n", job->repo_id);
        return vjob;
    }

    cached_head_id = get_cached_head_id (sched->seaf->db, job->repo_id);
    if (g_strcmp0 (cached_head_id, repo->head->commit_id) == 0)
        goto out;

    head = seaf_commit_manager_get_commit (sched->seaf->commit_mgr,
                                           repo->head->commit_id);
    if (!head) {
        g_warning ("[scheduler] failed to get head commit %s.\n",
                   repo->head->commit_id);
        goto out;
    }

    /* Load block list first so that we don't need to count duplicate blocks.
     * We only calculate the size of the head commit.
     */
    bl = block_list_new ();
    if (seaf_fs_manager_populate_blocklist (seaf->fs_mgr,
                                            head->root_id,
                                            bl) < 0) {
        block_list_free (bl);
        goto out;
    }

    int i;
    for (i = 0; i < bl->n_blocks; ++i) {
        block_id = g_ptr_array_index (bl->block_ids, i);
        bmd = seaf_block_manager_stat_block (sched->seaf->block_mgr, block_id);
        if (bmd) {
            size += bmd->size;
            g_free (bmd);
        }
    }
    block_list_free (bl);

    if (set_repo_size (sched->seaf->db,
                       job->repo_id,
                       repo->head->commit_id,
                       size) < 0)
        g_warning ("[scheduler] failed to store repo size %s.\n", job->repo_id);

out:
    seaf_repo_unref (repo);
    seaf_commit_unref (head);
    g_free (cached_head_id);

    return vjob;
}

static void
compute_repo_size_done (void *vjob)
{
    RepoSizeJob *job = vjob;
    --(job->sched->priv->n_running_repo_size_jobs);
    g_free (job);
}
