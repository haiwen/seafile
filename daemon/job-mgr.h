/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/**
 * Job Manager manages long term jobs. These jobs are run in their
 * own threads.
 */

#ifndef SEAF_JOB_MGR_H
#define SEAF_JOB_MGR_H

struct _SeafJobManager;
typedef struct _SeafJobManager SeafJobManager;

struct _SeafileSession;

/*
  The thread func should return the result back by
     return (void *)result;
  The result will be passed to JobDoneCallback.
 */
typedef void* (*JobThreadFunc)(void *data);
typedef void (*JobDoneCallback)(void *result);

SeafJobManager *
seaf_job_manager_new (struct _SeafileSession *session, int max_threads);

void
seaf_job_manager_free (struct _SeafJobManager *mgr);

int
seaf_job_manager_schedule_job (struct _SeafJobManager *mgr,
                               JobThreadFunc func,
                               JobDoneCallback done_func,
                               void *data);

#endif
