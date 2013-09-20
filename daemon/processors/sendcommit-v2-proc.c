/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <fcntl.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "sendcommit-v2-proc.h"
#include "processors/objecttx-common.h"
#include "vc-common.h"

/*
              seafile-recvcommit-v2
  INIT      --------------------->
                 200 OK
  INIT     <---------------------
                
                  Object
  SEND_OBJ  ----------------------->

                   ...

                    End
           ----------------------->
 */

enum {
    INIT,
    SEND_OBJECT
};

typedef struct  {
    char        end_commit_id[41];
} SeafileSendcommitProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_SENDCOMMIT_V2_PROC, SeafileSendcommitProcPriv))

#define USE_PRIV \
    SeafileSendcommitProcPriv *priv = GET_PRIV(processor);

static int send_commit_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);


G_DEFINE_TYPE (SeafileSendcommitV2Proc, seafile_sendcommit_v2_proc, CCNET_TYPE_PROCESSOR)

static void
seafile_sendcommit_v2_proc_class_init (SeafileSendcommitV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "sendcommit-v2-proc";
    proc_class->start = send_commit_start;
    proc_class->handle_response = handle_response;

    g_type_class_add_private (klass, sizeof (SeafileSendcommitProcPriv));
}

static void
seafile_sendcommit_v2_proc_init (SeafileSendcommitV2Proc *processor)
{
}

static int
send_commit_start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    GString *buf;
    TransferTask *task = ((SeafileSendcommitV2Proc *)processor)->tx_task;

    memcpy (priv->end_commit_id, task->remote_head, 41);

    /* fs_roots can be non-NULL if transfer is resumed from NET_DOWN. */
    if (task->fs_roots != NULL)
        object_list_free (task->fs_roots);
    task->fs_roots = object_list_new ();
    
    buf = g_string_new (NULL);
    g_string_printf (buf, "remote %s seafile-recvcommit-v2 %s %s",
                     processor->peer_id, task->to_branch, task->session_token);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

static void
send_commit (CcnetProcessor *processor, const char *object_id)
{
    char *data;
    int len;
    ObjectPack *pack = NULL;
    int pack_size;

    if (seaf_obj_store_read_obj (seaf->commit_mgr->obj_store,
                                 object_id, (void**)&data, &len) < 0) {
        g_warning ("Failed to read commit %s.\n", object_id);
        goto fail;
    }

    pack_size = sizeof(ObjectPack) + len;
    pack = malloc (pack_size);
    memcpy (pack->id, object_id, 41);
    memcpy (pack->object, data, len);

    ccnet_processor_send_update (processor, SC_OBJECT, SS_OBJECT,
                                 (char *)pack, pack_size);

    g_free (data);
    free (pack);
    return;

fail:
    ccnet_processor_send_update (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                 object_id, 41);
    ccnet_processor_done (processor, FALSE);
}

static gboolean
traverse_commit (SeafCommit *commit, void *data, gboolean *stop)
{
    CcnetProcessor *processor = data;
    TransferTask *task = ((SeafileSendcommitV2Proc *)processor)->tx_task;
    USE_PRIV;

    if (priv->end_commit_id[0] != 0 &&
        strcmp (priv->end_commit_id, commit->commit_id) == 0) {
        *stop = TRUE;
        return TRUE;
    }

    send_commit (processor, commit->commit_id);

    if (strcmp (commit->root_id, EMPTY_SHA1) != 0)
        object_list_insert (task->fs_roots, commit->root_id);

    return TRUE;
}

static void
send_commits (CcnetProcessor *processor, const char *head)
{
    gboolean ret;

    ret = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                    head,
                                                    traverse_commit,
                                                    processor, FALSE);
    if (!ret) {
        ccnet_processor_send_update (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                     NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }

    ccnet_processor_send_update (processor, SC_END, SS_END, NULL, 0);
    ccnet_processor_done (processor, TRUE);
}

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileSendcommitV2Proc *proc = (SeafileSendcommitV2Proc *)processor;
    TransferTask *task = proc->tx_task;
    if (task->state != TASK_STATE_NORMAL) {
        /* TODO: not tested yet */
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                     NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    switch (processor->state) {
    case INIT:
        if (memcmp (code, SC_OK, 3) == 0) {
            processor->state = SEND_OBJECT;
            send_commits (processor, task->head);
        } else {
            g_warning ("Bad response: %s %s.\n", code, code_msg);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    case SEND_OBJECT:
        g_warning ("[sendcommit] Bad response in state SEND_OBJECT: %s %s\n",
                   code, code_msg);
        ccnet_processor_done (processor, FALSE);
        break;
    default:
        g_return_if_reached ();
    }
}
