/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_TIMER_H
#define SEAF_TIMER_H

/* return TRUE to reschedule the timer, return FALSE to cancle the timer */
typedef int (*TimerCB) (void *data);

struct SeafTimer;

typedef struct SeafTimer SeafTimer;

/**
 * Calls timer_func(user_data) after the specified interval.
 * The timer is freed if timer_func returns zero.
 * Otherwise, it's called again after the same interval.
 */
SeafTimer* seaf_timer_new (TimerCB           func,
                           void             *user_data,
                           uint64_t          timeout_milliseconds);

/**
 * Frees a timer and sets the timer pointer to NULL.
 */
void seaf_timer_free (SeafTimer **timer);


#endif
