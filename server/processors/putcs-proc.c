/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <ccnet.h>
#include "seafile-session.h"
#include "chunkserv-mgr.h"
#include "putcs-proc.h"

G_DEFINE_TYPE (SeafilePutcsProc, seafile_putcs_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_putcs_proc_parent_class)->release_resource (processor);
}


static void
seafile_putcs_proc_class_init (SeafilePutcsProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "putcs-proc";
    proc_class->start = start;
    proc_class->release_resource = release_resource;
}

static void
seafile_putcs_proc_init (SeafilePutcsProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    GString *buf = g_string_new("");
    GList *chunk_servers, *cs;
    char *cs_id;

    chunk_servers = seaf_cs_manager_get_chunk_servers (seaf->cs_mgr);
    cs = chunk_servers;
    while (cs) {
        cs_id = cs->data;

        /* The public ip of myself is not set. We just send my id to
         * clients, they should already have my ip address.
         */
        if (strcmp (cs_id, seaf->session->base.id) == 0) {
            g_string_append_printf (buf, "%s\n", cs_id);
            goto next;
        }

        CcnetPeer *peer = ccnet_get_peer (seaf->ccnetrpc_client, cs_id);
        if (!peer || !peer->public_addr) {
            /* do nothing */
            if (peer)
                g_object_unref (peer);
        } else {
            g_string_append_printf (buf, "%s %s:%d\n", cs_id,
                                    peer->public_addr,
                                    peer->public_port);
            g_object_unref (peer);
        }
    next:
        cs = cs->next;
    }
    g_list_free (chunk_servers);

    ccnet_processor_send_response (processor, SC_OK, SS_OK, buf->str, buf->len+1);
    g_string_free (buf, TRUE);
    
    ccnet_processor_done (processor, TRUE);

    return 0;
}
