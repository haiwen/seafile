/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "include.h"
#include "cevent.h"

#include "seafile-session.h"

#define CEVENT_SIZE  (sizeof(CEvent))

typedef struct Handler {
    cevent_handler handler;
    void *handler_data;
} Handler;

CEventManager* cevent_manager_new ()
{
    CEventManager *manager;

    manager = g_new0 (CEventManager, 1);
    pthread_mutex_init (&manager->mutex, NULL);
    manager->handler_table = g_hash_table_new_full (g_direct_hash,
                                        g_direct_equal, NULL, g_free);
    
    return manager;
}

void pipe_callback (evutil_socket_t fd, short event, void *vmgr)
{
    CEventManager *manager = (CEventManager *) vmgr;
    CEvent *cevent;
    char buf[CEVENT_SIZE];
    
    if (seaf_pipe_readn(fd, buf, CEVENT_SIZE) != CEVENT_SIZE) {
        return;
    }

    cevent = (CEvent *)buf;
    Handler *h = g_hash_table_lookup (manager->handler_table,
                                      (gconstpointer)(long)cevent->id);
    if (h == NULL) {
        g_warning ("no handler for event type %d\n", cevent->id);
        return;
    }

    h->handler(cevent, h->handler_data);
}

int cevent_manager_start (CEventManager *manager)
{
    if (seaf_pipe(manager->pipefd) < 0) {
        g_warning ("pipe error: %s\n", strerror(errno));
        return -1;
    }

    manager->event = event_new (seaf->ev_base, manager->pipefd[0],
               EV_READ | EV_PERSIST, pipe_callback, manager);
    event_add (manager->event, NULL);

    return 0;
}

uint32_t cevent_manager_register (CEventManager *manager,
                                  cevent_handler handler, void *handler_data)
{
    uint32_t id;
    Handler *h;

    h = g_new0(Handler, 1);
    h->handler = handler;
    h->handler_data = handler_data;

    /* Since we're using 32-bit int for id, it may wrap around to 0.
     * If some caller persistently use one id, it's handler may be
     * overwritten by others.
     */
    do {
        id = manager->next_id++;
    } while (g_hash_table_lookup (manager->handler_table, (gpointer)(long)id));

    g_hash_table_insert (manager->handler_table, (gpointer)(long)id, h);

    return id;
}

void cevent_manager_unregister (CEventManager *manager, uint32_t id)
{
    g_hash_table_remove (manager->handler_table, (gpointer)(long)id);
}

void
cevent_manager_add_event (CEventManager *manager, uint32_t id,
                          void *data)
{
    pthread_mutex_lock (&manager->mutex);

    struct CEvent cevent;
    char *buf = (char *) &cevent;

    cevent.id = id;
    cevent.data = data;
    if (seaf_pipe_writen(manager->pipefd[1], buf, CEVENT_SIZE) != CEVENT_SIZE) {
        g_warning ("add event error\n");
    }

    pthread_mutex_unlock (&manager->mutex);
}
