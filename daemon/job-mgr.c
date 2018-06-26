/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#include <event2/event_compat.h>
#else
#include <event.h>
#endif

#include <glib.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "utils.h"
#include "log.h"

#include "seafile-session.h"
#include "job-mgr.h"

struct _SeafJobManager {
    SeafileSession  *session;
    GThreadPool     *thread_pool;
    int              next_job_id;
};

struct _SeafJob {
    SeafJobManager *manager;

    int             id;
    seaf_pipe_t    pipefd[2];

    JobThreadFunc   thread_func;
    JobDoneCallback done_func;  /* called when the thread is done */
    void           *data;

    /* the done callback should only access this field */
    void           *result;
};
typedef struct _SeafJob SeafJob;

SeafJob *
seaf_job_new ()
{
    SeafJob *job;

    job = g_new0 (SeafJob, 1);
    return job;
}

void
seaf_job_free (SeafJob *job)
{
    g_free (job);
}

static void
job_thread_wrapper (void *vdata, void *unused)
{
    SeafJob *job = vdata;
   
    job->result = job->thread_func (job->data);
    if (seaf_pipe_writen (job->pipefd[1], "a", 1) != 1) {
        seaf_warning ("[Job Manager] write to pipe error: %s\n", strerror(errno));
    }
}

static void
job_done_cb (evutil_socket_t fd, short event, void *vdata)
{
    SeafJob *job = vdata;
    char buf[1];

    if (seaf_pipe_readn (job->pipefd[0], buf, 1) != 1) {
        seaf_warning ("[Job Manager] read pipe error: %s\n", strerror(errno));
    }
    seaf_pipe_close (job->pipefd[0]);
    seaf_pipe_close (job->pipefd[1]);
    if (job->done_func) {
        job->done_func (job->result);
    }

    seaf_job_free (job);
}

int
job_thread_create (SeafJob *job)
{
    SeafileSession *session = job->manager->session;

    if (seaf_pipe (job->pipefd) < 0) {
        seaf_warning ("[Job Manager] pipe error: %s\n", strerror(errno));
        return -1;
    }

    g_thread_pool_push (job->manager->thread_pool, job, NULL);

    event_base_once (session->ev_base, job->pipefd[0], EV_READ, job_done_cb, job, NULL);

    return 0;
}

SeafJobManager *
seaf_job_manager_new (SeafileSession *session, int max_threads)
{
    SeafJobManager *mgr;

    mgr = g_new0 (SeafJobManager, 1);
    mgr->session = session;
    mgr->thread_pool = g_thread_pool_new (job_thread_wrapper,
                                          NULL,
                                          max_threads,
                                          FALSE,
                                          NULL);

    return mgr;
}

void
seaf_job_manager_free (SeafJobManager *mgr)
{
    g_thread_pool_free (mgr->thread_pool, TRUE, FALSE);
    g_free (mgr);
}

int
seaf_job_manager_schedule_job (SeafJobManager *mgr,
                               JobThreadFunc func,
                               JobDoneCallback done_func,
                               void *data)
{
    SeafJob *job = seaf_job_new ();
    job->id = mgr->next_job_id++;
    job->manager = mgr;
    job->thread_func = func;
    job->done_func = done_func;
    job->data = data;
    
    if (job_thread_create (job) < 0) {
        seaf_job_free (job);
        return -1;
    }

    return 0;
}
