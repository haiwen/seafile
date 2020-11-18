/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#include <event2/event_compat.h>
#include <event2/event_struct.h>
#else
#include <event.h>
#endif

#ifndef WIN32
#include <sys/time.h>
#endif

#include "seafile-session.h"

#include "utils.h"

#include "timer.h"

struct SeafTimer
{
    struct event   *event;
    struct timeval tv;
    TimerCB        func;
    void          *user_data;
    uint8_t        in_callback;
};

static void
timer_callback (evutil_socket_t fd, short event, void *vtimer)
{
    int more;
    struct SeafTimer *timer = vtimer;

    timer->in_callback = 1;
    more = (*timer->func) (timer->user_data);
    timer->in_callback = 0;

    if (more)
        evtimer_add (timer->event, &timer->tv);
    else
        seaf_timer_free (&timer);
}

void
seaf_timer_free (SeafTimer **ptimer)
{
    SeafTimer *timer;

    /* zero out the argument passed in */
    g_return_if_fail (ptimer);

    timer = *ptimer;
    *ptimer = NULL;

    /* destroy the timer directly or via the command queue */
    if (timer && !timer->in_callback)
    {
        event_del (timer->event);
        event_free (timer->event);
        g_free (timer);
    }
}

struct timeval
timeval_from_msec (uint64_t milliseconds)
{
    struct timeval ret;
    const uint64_t microseconds = milliseconds * 1000;
    ret.tv_sec  = microseconds / 1000000;
    ret.tv_usec = microseconds % 1000000;
    return ret;
}

SeafTimer*
seaf_timer_new (TimerCB         func,
                void           *user_data,
                uint64_t        interval_milliseconds)
{
    SeafTimer *timer = g_new0 (SeafTimer, 1);

    timer->tv = timeval_from_msec (interval_milliseconds);
    timer->func = func;
    timer->user_data = user_data;

    timer->event = evtimer_new (seaf->ev_base, timer_callback, timer);
    evtimer_add (timer->event, &timer->tv);

    return timer;
}
