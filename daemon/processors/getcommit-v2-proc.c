/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"
#include "seaf-utils.h"

#include "seafile-session.h"
#include "getcommit-v2-proc.h"
#include "processors/objecttx-common.h"

/*
              seafile-putcommit-v2 <HEAD> [END] (END is empty in clone)
  INIT      -------------------------->
                 OK
            <-------------------------

                  Object
  FETCH_OBJ <-------------------------

                   ...

                    End
  FETCH_OBJ  <--------------------------
 */

enum {
    INIT,
    RECV_OBJECT
};

static int get_commit_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

G_DEFINE_TYPE (SeafileGetcommitV2Proc, seafile_getcommit_v2_proc, CCNET_TYPE_PROCESSOR)


static void
seafile_getcommit_v2_proc_class_init (SeafileGetcommitV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "getcommit-proc-v2";
    proc_class->start = get_commit_start;
    proc_class->handle_response = handle_response;
}

static void
seafile_getcommit_v2_proc_init (SeafileGetcommitV2Proc *processor)
{
}


static int
get_commit_start (CcnetProcessor *processor, int argc, char **argv)
{
    GString *buf = g_string_new (NULL);
    TransferTask *task = ((SeafileGetcommitV2Proc *)processor)->tx_task;
    SeafBranch *master = NULL;
    char *end_commit_id = NULL;

    g_return_val_if_fail (task->session_token, -1);

    if (!task->is_clone) {
        master = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                 task->repo_id,
                                                 "master");
        if (master != NULL)
            end_commit_id = master->commit_id;
    }

    /* fs_roots can be non-NULL if transfer is resumed from NET_DOWN. */
    if (task->fs_roots != NULL)
        object_list_free (task->fs_roots);
    task->fs_roots = object_list_new ();

    if (end_commit_id != NULL)
        g_string_printf (buf, "remote %s seafile-putcommit-v2 %s %s %s",
                         processor->peer_id, 
                         task->head, end_commit_id, task->session_token);
    else
        g_string_printf (buf, "remote %s seafile-putcommit-v2 %s %s",
                         processor->peer_id, 
                         task->head, task->session_token);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    seaf_branch_unref (master);

    return 0;
}

static int
save_commit (ObjectPack *pack, int len)
{
    return seaf_obj_store_write_obj (seaf->commit_mgr->obj_store,
                                     pack->id,
                                     pack->object,
                                     len - 41);
}

static void
receive_commit (CcnetProcessor *processor, char *content, int clen)
{
    ObjectPack *pack = (ObjectPack *)content;
    TransferTask *task = ((SeafileGetcommitV2Proc *)processor)->tx_task;
    SeafCommit *commit;

    if (clen < sizeof(ObjectPack)) {
        g_warning ("[getcommit] invalid object id.\n");
        goto bad;
    }

    seaf_debug ("[getcommit] recv commit object %.8s\n", pack->id);

    if (save_commit (pack, clen) < 0) {
        goto bad;
    }

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr, pack->id);
    if (!commit)
        goto bad;

    if (strcmp (commit->root_id, EMPTY_SHA1) != 0)
        object_list_insert (task->fs_roots, commit->root_id);
    seaf_commit_unref (commit);

    return;

bad:
    g_warning ("[getcommit] Bad commit object received.\n");
    transfer_task_set_error (((SeafileGetcommitV2Proc *)processor)->tx_task,
                             TASK_ERR_DOWNLOAD_COMMIT);
    ccnet_processor_send_update (processor, SC_BAD_OBJECT, SS_BAD_OBJECT,
                                 NULL, 0);
    ccnet_processor_done (processor, FALSE);
}

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileGetcommitV2Proc *proc = (SeafileGetcommitV2Proc *)processor;
    if (proc->tx_task->state != TASK_STATE_NORMAL) {
        ccnet_processor_done (processor, TRUE);
        return;
    }

    switch (processor->state) {
    case INIT:
        if (strncmp(code, SC_OK, 3) == 0) {
            processor->state = RECV_OBJECT;
            return;
        }
        break;
    case RECV_OBJECT:
        if (strncmp(code, SC_OBJECT, 3) == 0) {
            receive_commit (processor, content, clen);
            return;
        } else if (strncmp (code, SC_END, 3) == 0) {
            seaf_debug ("[getcommit] Get commit end.\n");
            ccnet_processor_done (processor, TRUE);
            return;
        }
        break;
    default:
        g_return_if_reached ();
    }

    g_warning ("Bad response: %s %s.\n", code, code_msg);
    if (memcmp (code, SC_ACCESS_DENIED, 3) == 0)
        transfer_task_set_error (proc->tx_task, TASK_ERR_ACCESS_DENIED);
    ccnet_processor_done (processor, FALSE);
}
