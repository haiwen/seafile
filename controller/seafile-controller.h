/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * Seafile-controller is responsible for:
 *
 *    1. Start: start server processes:
 *
 *       - ccnet-server
 *       - seaf-server
 *       - seaf-mon
 *       - httpserver
 *
 *    2. Repair:
 *
 *       - ensure ccnet process availability by watching client->connfd
 *       - ensure server processes availablity by checking process is running periodically
 *         If some process has stopped working, try to restart it.
 *
 */

#ifndef SEAFILE_CONTROLLER_H
#define SEAFILE_CONTROLLER_H

typedef struct _SeafileController SeafileController;

enum {
    PID_CCNET = 0,
    PID_SERVER,
    PID_HTTPSERVER,
    N_PID
};

struct _SeafileController {
    char *config_dir;
    char *seafile_dir;
    char *logdir;

    CcnetClient         *client;
    CcnetClient         *sync_client;
    CcnetMqclientProc   *mqclient_proc;

    guint               check_process_timer;
    guint               client_io_id;
    /* Decide whether to start seaf-server in cloud mode  */
    gboolean            cloud_mode;

    int                 pid[N_PID];
    char                *pidfile[N_PID];
};
#endif
