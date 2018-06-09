/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/* 
 * CEvent is used for send message from a work thread to main thread.
 */
#ifndef CEVENT_H
#define CEVENT_H

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/event.h>
#include <event2/event_compat.h>
#include <event2/event_struct.h>
#else
#include <event.h>
#endif

#include <glib.h>

#include <pthread.h>

#include "utils.h"

typedef struct CEvent  CEvent;

typedef void (*cevent_handler) (CEvent *event, void *handler_data);

struct CEvent {
    uint32_t  id;
    void     *data;
};


typedef struct CEventManager CEventManager;

struct CEventManager {    
    seaf_pipe_t  pipefd[2];
    struct event  *event;
    GHashTable   *handler_table;
    uint32_t      next_id;
    
    pthread_mutex_t  mutex;
};

CEventManager* cevent_manager_new ();

int cevent_manager_start (CEventManager *manager);

uint32_t cevent_manager_register (CEventManager *manager,
                                  cevent_handler handler, void *handler_data);

void cevent_manager_unregister (CEventManager *manager, uint32_t id);

void cevent_manager_add_event (CEventManager *manager, uint32_t id,
                               void *event_data);

#endif
