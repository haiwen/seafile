/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * Seafile-controller is responsible for: 
 *
 *    1. Start: start server processes:
 *
 *       - ccnet-server
 *       - seaf-server
 *       - seaf-mon
 *
 *    2. Repair:
 *
 *       - ensure ccnet process availability by watching client->connfd
 *       - ensure server processes availablity by receiving heartbeat
 *         messages.
 *         If heartbeat messages for some process is not received for a given
 *         time, try to restart it.
 *      
 */

#ifndef SEAFILE_CONTROLLER_H
#define SEAFILE_CONTROLLER_H

typedef struct _SeafileController SeafileController;

enum {
    HB_SEAFILE_SERVER = 0,
    HB_SEAFILE_MONITOR,
    N_HEARTBEAT
};

enum {
    PID_CCNET = 0,
    PID_SERVER,
    PID_MONITOR,
    N_PID
};

struct _SeafileController {
    char *bin_dir;
    char *config_dir;
    char *seafile_dir;
    
    CcnetClient         *client;
    CcnetClient         *sync_client;
    CcnetMqclientProc   *mqclient_proc;

    guint               hearbeat_timer;
    guint               client_io_id; 

    time_t              last_hb[N_HEARTBEAT];
    int                 pid[N_PID];
    char                *pidfile[N_PID];
};
#endif
