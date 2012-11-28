/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include "log.h"

#include "seafile-session.h"
#include "gc.h"
#include "gc-core.h"

static gboolean gc_started = FALSE;

static void *gc_thread_func (void *data);
static void gc_thread_done (void *data);

int
gc_start ()
{
    int ret;

    gc_started = TRUE;

    ret = ccnet_job_manager_schedule_job (seaf->job_mgr,
                                          gc_thread_func,
                                          gc_thread_done,
                                          NULL);
    if (ret < 0)
        return ret;

    return 0;
}

gboolean
gc_is_started ()
{
    return gc_started;
}

static void *
gc_thread_func (void *data)
{
    gc_core_run ();
    return NULL;
}

static void
gc_thread_done (void *data)
{
    gc_started = FALSE;
}
