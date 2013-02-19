/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <ccnet.h>

#include "seafile-session.h"
#include "sync-mgr.h"
#include "notifysync-slave-proc.h"
#include "sync-repo-common.h"
#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
#include "log.h"

#define SC_BAD_REPO         "402"
#define SS_BAD_REPO         "Repo doesn't exist"

G_DEFINE_TYPE (SeafileNotifysyncSlaveProc, seafile_notifysync_slave_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (seafile_notifysync_slave_proc_parent_class)->release_resource (processor);
}


static void
seafile_notifysync_slave_proc_class_init (SeafileNotifysyncSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "seafile-notifysync-slave";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_notifysync_slave_proc_init (SeafileNotifysyncSlaveProc *processor)
{
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    if (argc != 2) {
        g_warning ("[notifysync-slave] argc(%d) must be 2\n", argc);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
    const char *repo_id = argv[0];
    const char *token = argv[1];

    seaf_debug ("[notifysync-slave] Receive notify sync repo %s from %s\n",
                repo_id, processor->peer_id);

    if (!seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id)) {
        ccnet_processor_send_response (processor, SC_BAD_REPO, SS_BAD_REPO, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    seaf_sync_manager_add_sync_task (seaf->sync_mgr, repo_id,
                                     processor->peer_id,
                                     token, TRUE, NULL);
    ccnet_processor_send_response (processor, SC_OK, SS_OK,
                                   NULL, 0);
    ccnet_processor_done (processor, TRUE);
    return 0;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
}
