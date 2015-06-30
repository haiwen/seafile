/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "sendcommit-v4-proc.h"
#include "processors/objecttx-common.h"
#include "vc-common.h"

enum {
    INIT,
    SEND_OBJECT
};

static int send_commit_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);


G_DEFINE_TYPE (SeafileSendcommitV4Proc, seafile_sendcommit_v4_proc, CCNET_TYPE_PROCESSOR)

static void
seafile_sendcommit_v4_proc_class_init (SeafileSendcommitV4ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "sendcommit-v4-proc";
    proc_class->start = send_commit_start;
    proc_class->handle_response = handle_response;
}

static void
seafile_sendcommit_v4_proc_init (SeafileSendcommitV4Proc *processor)
{
}

static int
send_commit_start (CcnetProcessor *processor, int argc, char **argv)
{
    TransferTask *task = ((SeafileSendcommitV4Proc *)processor)->tx_task;
    GString *buf;
    
    buf = g_string_new (NULL);
    g_string_printf (buf, "remote %s seafile-recvcommit-v3 master %s",
                     processor->peer_id, task->session_token);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

static void
send_commit (CcnetProcessor *processor, const char *object_id)
{
    TransferTask *task = ((SeafileSendcommitV4Proc *)processor)->tx_task;
    char *data;
    int len;
    ObjectPack *pack = NULL;
    int pack_size;

    if (seaf_obj_store_read_obj (seaf->commit_mgr->obj_store,
                                 task->repo_id, task->repo_version,
                                 object_id, (void**)&data, &len) < 0) {
        seaf_warning ("Failed to read commit %s.\n", object_id);
        goto fail;
    }

    pack_size = sizeof(ObjectPack) + len;
    pack = malloc (pack_size);
    memcpy (pack->id, object_id, 41);
    memcpy (pack->object, data, len);

    ccnet_processor_send_update (processor, SC_OBJECT, SS_OBJECT,
                                 (char *)pack, pack_size);

    seaf_debug ("Send commit %.8s.\n", object_id);

    g_free (data);
    free (pack);
    return;

fail:
    ccnet_processor_send_update (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                 object_id, 41);
    ccnet_processor_done (processor, FALSE);
}

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileSendcommitV4Proc *proc = (SeafileSendcommitV4Proc *)processor;
    TransferTask *task = proc->tx_task;
    if (task->state != TASK_STATE_NORMAL) {
        ccnet_processor_done (processor, TRUE);
        return;
    }

    switch (processor->state) {
    case INIT:
        if (memcmp (code, SC_OK, 3) == 0) {
            processor->state = SEND_OBJECT;
            send_commit (processor, task->head);
            return;
        }
        break;
    case SEND_OBJECT:
        if (memcmp (code, SC_ACK, 3) == 0) {
            ccnet_processor_done (processor, TRUE);
            return;
        }
        break;
    default:
        g_return_if_reached ();
    }

    seaf_warning ("Bad response: %s %s.\n", code, code_msg);
    if (memcmp (code, SC_ACCESS_DENIED, 3) == 0)
        transfer_task_set_error (task, TASK_ERR_ACCESS_DENIED);
    ccnet_processor_done (processor, FALSE);
}
