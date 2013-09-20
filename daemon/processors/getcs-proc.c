/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include <ccnet.h>

#include "seafile-session.h"
#include "utils.h"
#include "db.h"
#include "getcs-proc.h"


G_DEFINE_TYPE (SeafileGetcsProc, seafile_getcs_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_getcs_proc_parent_class)->release_resource (processor);
}


static void
seafile_getcs_proc_class_init (SeafileGetcsProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "getcs-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_getcs_proc_init (SeafileGetcsProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char buf[256];

    snprintf (buf, 256, "remote %s seafile-putcs", processor->peer_id);
    ccnet_processor_send_request (processor, buf);

    return 0;
}

static gint
peer_cmp_func (gconstpointer a, gconstpointer b)
{
    const char *id_a = a;
    const char *id_b = b;

    return (g_strcmp0(id_a, id_b));
}

static void
add_chunk_server (CcnetProcessor *processor, TransferTask *task, char *cs_str)
{
    int num;
    char *cs_id;
    char **tokens;

    tokens = strsplit_by_space (cs_str, &num);
    if (num < 1)
        return;
    cs_id = tokens[0];

    if (g_list_find_custom (task->chunk_servers, cs_id, peer_cmp_func) != NULL)
        goto out;

    if (strcmp (cs_id, processor->peer_id) == 0) {
        CcnetPeer *peer = ccnet_get_peer (seaf->ccnetrpc_client,
                                          processor->peer_id);
        g_return_if_fail (peer != NULL);
        if (!peer->public_addr) {
            g_warning ("Public address of relay %s is not set.\n", cs_id);
            g_object_unref (peer);
            goto out;
        }
        task->chunk_servers = g_list_prepend (task->chunk_servers,
                                              g_strdup(cs_id));
        g_object_unref (peer);
        goto out;
    }

    ccnet_add_peer (processor->session, tokens[0], tokens[1]);
    task->chunk_servers = g_list_prepend (task->chunk_servers, g_strdup(cs_id));

out:
    free (tokens);
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileGetcsProc *proc = (SeafileGetcsProc *)processor;
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
        add_chunk_server (processor, proc->task, cs_str);
    } else {
        ccnet_processor_done (processor, TRUE);
        return;
    }

    while ((cs_str = strtok(NULL, "\n")) != NULL)
        add_chunk_server (processor, proc->task, cs_str);

    ccnet_processor_done (processor, TRUE);
}
