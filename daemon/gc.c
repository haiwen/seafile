/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include "log.h"

#include "seafile-session.h"
#include "gc.h"
#include "gc-core.h"

static int gc_started = 0;

static void *gc_thread_func (void *data);
static void gc_thread_done (void *data);

int
gc_start ()
{
    int ret;

    g_atomic_int_set (&gc_started, 1);

    ret = ccnet_job_manager_schedule_job (seaf->job_mgr,
                                          gc_thread_func,
                                          gc_thread_done,
                                          NULL);
    if (ret < 0)
        return ret;

    return 0;
}

int
gc_is_started ()
{
    return g_atomic_int_get (&gc_started);
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
    g_atomic_int_set (&gc_started, 0);
}
