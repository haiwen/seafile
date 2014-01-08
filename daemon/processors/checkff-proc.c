/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "checkff-proc.h"
#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

G_DEFINE_TYPE (SeafileCheckffProc, seafile_checkff_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (seafile_checkff_proc_parent_class)->release_resource (processor);
}


static void
seafile_checkff_proc_class_init (SeafileCheckffProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_checkff_proc_init (SeafileCheckffProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char buf[256];

    snprintf (buf, sizeof(buf),
              "remote %s seafile-checkff %s %s", processor->peer_id,
              argv[0], argv[1]);
    ccnet_processor_send_request (processor, buf);

    return 0;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileCheckffProc *proc = (SeafileCheckffProc *)processor;

    if (memcmp (code, SC_OK, 3) == 0) {
        proc->is_fast_forward = (atoi (content) != 0);
        ccnet_processor_done (processor, TRUE);
    } else {
        seaf_warning ("Bad response: %s %s.\n", code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}
