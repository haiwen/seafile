/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <ccnet.h>

#include "notifysync-proc.h"

#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
#include "log.h"

#define SC_BAD_REPO         "402"
#define SS_BAD_REPO         "Repo doesn't exist"

G_DEFINE_TYPE (SeafileNotifysyncProc, seafile_notifysync_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (seafile_notifysync_proc_parent_class)->release_resource (processor);
}


static void
seafile_notifysync_proc_class_init (SeafileNotifysyncProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "seafile-notifysync";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_notifysync_proc_init (SeafileNotifysyncProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    if (argc != 2) {
        seaf_warning ("[notidysync] argc must be 2.\n");
        ccnet_processor_done (processor, FALSE);
        return 0;
    }

    const char *repo_id = argv[0];
    const char *token = argv[1];
    char buf[256];

    /* Use a virutal "fetch_head" branch that works both on client and server. */
    snprintf (buf, 256, "remote %s seafile-notifysync-slave %s %s",
              processor->peer_id, repo_id, token);

    ccnet_processor_send_request (processor, buf);

    return 0;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    if (memcmp (code, SC_OK, 3) == 0)
        ccnet_processor_done (processor, TRUE);
    else
        ccnet_processor_done (processor, FALSE);
}
