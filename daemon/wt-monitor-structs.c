#include <string.h>

#include "wt-monitor-structs.h"

/* WTEvent */

WTEvent *wt_event_new (int type, const char *path, const char *new_path)
{
    WTEvent *event = g_new0 (WTEvent, 1);

    event->ev_type = type;
    if (path)
        event->path = g_strdup (path);
    if (new_path)
        event->new_path = g_strdup(new_path);

    return event;
}

static void free_path (gpointer data, gpointer user_data)
{
    g_free (data);
}

void wt_event_free (WTEvent *event)
{
    g_free (event->path);
    g_free (event->new_path);
    if (event->remain_files) {
        g_queue_foreach (event->remain_files, free_path, NULL);
        g_queue_free (event->remain_files);
    }
    g_free (event);
}

/* WTStatus */

WTStatus *create_wt_status (const char *repo_id)
{
    WTStatus *status = g_new0 (WTStatus, 1);

    memcpy (status->repo_id, repo_id, 36);
    status->event_q = g_queue_new ();
    pthread_mutex_init (&status->q_lock, NULL);

    status->active_paths = g_queue_new ();
    pthread_mutex_init (&status->ap_q_lock, NULL);

    /* The monitor thread always holds a reference to this status
     * until it's unwatched
     */
    status->ref_count = 1;

    return status;
}

static void free_event_cb (gpointer data, gpointer user_data)
{
    WTEvent *event = data;
    wt_event_free (event);
}

static void free_wt_status (WTStatus *status)
{
    if (status->event_q) {
        g_queue_foreach (status->event_q, free_event_cb, NULL);
        g_queue_free (status->event_q);
    }
    pthread_mutex_destroy (&status->q_lock);
    g_free (status);
}

void
wt_status_ref (WTStatus *status)
{
    ++(status->ref_count);
}

void
wt_status_unref (WTStatus *status)
{
    if (!status) return;

    if (--(status->ref_count) <= 0)
        free_wt_status (status);
}
