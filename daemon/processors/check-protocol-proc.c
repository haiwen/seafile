/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "check-protocol-proc.h"

#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
#include "log.h"

G_DEFINE_TYPE (SeafileCheckProtocolProc, seafile_check_protocol_proc, CCNET_TYPE_PROCESSOR)


static int
check_protocol_start (CcnetProcessor *processor, int argc, char **argv);

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen);

static void
seafile_check_protocol_proc_class_init (SeafileCheckProtocolProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "seafile-check-protocol";
    proc_class->start = check_protocol_start;
    proc_class->handle_response = handle_response;
}

static void
seafile_check_protocol_proc_init (SeafileCheckProtocolProc *processor)
{
}


static int
check_protocol_start (CcnetProcessor *processor, int argc, char **argv)
{
    if (argc != 0) {
        seaf_warning ("[sync-repo] argc should be 0.\n");
        ccnet_processor_done (processor, FALSE);
        return 0;
    }

    char buf[256];

    snprintf (buf, 256, "remote %s seafile-check-protocol-slave", processor->peer_id);
    
    ccnet_processor_send_request (processor, buf);

    return 0;
}


static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileCheckProtocolProc *proc = (SeafileCheckProtocolProc *)processor;

    if (memcmp (code, SC_OK, 3) == 0) {
        
        if (content[clen-1] != '\0') {
            seaf_warning ("[check-protocol] Response not end with NULL\n");
            ccnet_processor_done (processor, FALSE);
            return;
        }

        proc->protocol_version = atoi(content);

        ccnet_processor_done (processor, TRUE);
    } else 
        ccnet_processor_done (processor, FALSE);
}
