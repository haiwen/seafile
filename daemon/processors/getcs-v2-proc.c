/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include <ccnet.h>

#include "seafile-session.h"
#include "utils.h"
#include "getcs-v2-proc.h"


G_DEFINE_TYPE (SeafileGetcsV2Proc, seafile_getcs_v2_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_getcs_v2_proc_parent_class)->release_resource (processor);
}


static void
seafile_getcs_v2_proc_class_init (SeafileGetcsV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "getcs-v2-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_getcs_v2_proc_init (SeafileGetcsV2Proc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char buf[256];

    snprintf (buf, 256, "remote %s seafile-putcs-v2", processor->peer_id);
    ccnet_processor_send_request (processor, buf);

    return 0;
}

static int
add_chunk_server (CcnetProcessor *processor, TransferTask *task, char *cs_str)
{
    char **tokens;
    CcnetPeer *peer;
    ChunkServer *cs;

    tokens = g_strsplit (cs_str, ":", -1);
    if (g_strv_length (tokens) != 2) {
        g_warning ("Invalid chunk server address format: %s.\n", cs_str);
        g_strfreev (tokens);
        return -1;
    }

    peer = ccnet_get_peer (seaf->ccnetrpc_client, processor->peer_id);
    if (!peer) {
        g_warning ("[getcs] Invalid peer %s.\n", processor->peer_id);
        g_strfreev (tokens);
        return -1;
    }

    if (!peer->addr_str) {
        g_warning ("[getcs] Peer doesn't have an address.\n");
        g_object_unref (peer);
        g_strfreev (tokens);
        return -1;
    }

    cs = g_new0 (ChunkServer, 1);
    cs->addr = g_strdup (peer->addr_str);
    cs->port = atoi (tokens[1]);

    task->chunk_servers = g_list_prepend (task->chunk_servers, cs);

    g_strfreev (tokens);
    g_object_unref (peer);
    return 0;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileGetcsV2Proc *proc = (SeafileGetcsV2Proc *)processor;
    char *cs_str;

    if (proc->task->state != TASK_STATE_NORMAL) {
        g_debug ("Task not running, get-cs proc exits.\n");
        ccnet_processor_done (processor, FALSE);
        return;
    }

    if (memcmp (code, SC_OK, 3) != 0) {
        g_warning ("Bad response: %s %s.\n", code, code_msg);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    if (content[clen-1] != '\0') {
        g_warning ("Bad chunk server list format.\n");
        ccnet_processor_done (processor, FALSE);
        return;
    }

    cs_str = strtok (content, "\n");
    if (cs_str != NULL) {
        if (add_chunk_server (processor, proc->task, cs_str) < 0)
            goto error;
    } else {
        ccnet_processor_done (processor, TRUE);
        return;
    }

    while ((cs_str = strtok(NULL, "\n")) != NULL) {
        if (add_chunk_server (processor, proc->task, cs_str) < 0)
            goto error;
    }

    ccnet_processor_done (processor, TRUE);

error:
    ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN, NULL, 0);
    ccnet_processor_done (processor, FALSE);
}
