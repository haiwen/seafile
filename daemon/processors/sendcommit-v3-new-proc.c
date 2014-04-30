/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "sendcommit-v3-new-proc.h"
#include "processors/objecttx-common.h"
#include "vc-common.h"

/*
              seafile-recvcommit-v3
  INIT      --------------------->
                 200 OK
  INIT     <---------------------
                
                  Object
  SEND_OBJ  ----------------------->
                Ack or Bad Object
           <---------------------

                   ...

                    End
           ----------------------->
 */

enum {
    INIT,
    SEND_OBJECT
};

typedef struct  {
    char        remote_id[41];
    char        last_uploaded_id[41];
    GList       *id_list;
    gboolean    visited_last_uploaded;
    gboolean    compute_success;
} SeafileSendcommitProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_SENDCOMMIT_V3_NEW_PROC, SeafileSendcommitProcPriv))

#define USE_PRIV \
    SeafileSendcommitProcPriv *priv = GET_PRIV(processor);

static int send_commit_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);


G_DEFINE_TYPE (SeafileSendcommitV3NewProc, seafile_sendcommit_v3_new_proc, CCNET_TYPE_PROCESSOR)

static void
release_resource (CcnetProcessor *processor)
{
    USE_PRIV;

    if (priv->id_list != NULL)
        string_list_free (priv->id_list);

    CCNET_PROCESSOR_CLASS (seafile_sendcommit_v3_new_proc_parent_class)->release_resource (processor);
}

static void
seafile_sendcommit_v3_new_proc_class_init (SeafileSendcommitV3NewProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "sendcommit-v3-new-proc";
    proc_class->start = send_commit_start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileSendcommitProcPriv));
}

static void
seafile_sendcommit_v3_new_proc_init (SeafileSendcommitV3NewProc *processor)
{
}

static int
send_commit_start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    GString *buf;
    TransferTask *task = ((SeafileSendcommitV3NewProc *)processor)->tx_task;

    memcpy (priv->remote_id, task->remote_head, 41);

    /* fs_roots can be non-NULL if transfer is resumed from NET_DOWN. */
    if (task->fs_roots != NULL)
        object_list_free (task->fs_roots);
    task->fs_roots = object_list_new ();

    if (task->commits != NULL)
        object_list_free (task->commits);
    task->commits = object_list_new ();
    
    buf = g_string_new (NULL);
    g_string_printf (buf, "remote %s seafile-recvcommit-v3 %s %s",
                     processor->peer_id, task->to_branch, task->session_token);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

static void
send_commit (CcnetProcessor *processor, const char *object_id)
{
    TransferTask *task = ((SeafileSendcommitV3NewProc *)processor)->tx_task;
    char *data;
    int len;
    ObjectPack *pack = NULL;
    int pack_size;

    if (seaf_obj_store_read_obj (seaf->commit_mgr->obj_store,
                                 task->repo_id, task->repo_version,
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

    seaf_debug ("Send commit %.8s.\n", object_id);

    g_free (data);
    free (pack);
    return;

fail:
    ccnet_processor_send_update (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                 object_id, 41);
    ccnet_processor_done (processor, FALSE);
}

static void
send_one_commit (CcnetProcessor *processor)
{
    USE_PRIV;
    char *commit_id;

    if (!priv->id_list) {
        ccnet_processor_send_update (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    commit_id = priv->id_list->data;
    priv->id_list = g_list_delete_link (priv->id_list, priv->id_list);

    send_commit (processor, commit_id);

    g_free (commit_id);
}

static gboolean
collect_upload_commit_ids (SeafCommit *commit, void *data, gboolean *stop)
{
    CcnetProcessor *processor = data;
    TransferTask *task = ((SeafileSendcommitV3NewProc *)processor)->tx_task;
    USE_PRIV;

    if (strcmp (priv->last_uploaded_id, commit->commit_id) == 0) {
        priv->visited_last_uploaded = TRUE;
        *stop = TRUE;
        return TRUE;
    }

    if (priv->remote_id[0] != 0 &&
        strcmp (priv->remote_id, commit->commit_id) == 0) {
        *stop = TRUE;
        return TRUE;
    }

    if (commit->parent_id &&
        !seaf_commit_manager_commit_exists (seaf->commit_mgr,
                                            commit->repo_id, commit->version,
                                            commit->parent_id)) {
        *stop = TRUE;
        return TRUE;
    }

    if (commit->second_parent_id &&
        !seaf_commit_manager_commit_exists (seaf->commit_mgr,
                                            commit->repo_id, commit->version,
                                            commit->second_parent_id)) {
        *stop = TRUE;
        return TRUE;
    }

    priv->id_list = g_list_prepend (priv->id_list, g_strdup(commit->commit_id));

    /* We don't need to send the contents under an empty dir.
     */
    if (strcmp (commit->root_id, EMPTY_SHA1) != 0)
        object_list_insert (task->fs_roots, commit->root_id);

    object_list_insert (task->commits, commit->commit_id);

    return TRUE;
}

static void *
compute_upload_commits_thread (void *vdata)
{
    CcnetProcessor *processor = vdata;
    SeafileSendcommitV3NewProc *proc = (SeafileSendcommitV3NewProc *)processor;
    TransferTask *task = proc->tx_task;
    USE_PRIV;
    gboolean ret;

    ret = seaf_commit_manager_traverse_commit_tree_truncated (seaf->commit_mgr,
                                                              task->repo_id,
                                                              task->repo_version,
                                                              task->head,
                                                              collect_upload_commit_ids,
                                                              processor, FALSE);
    if (!ret) {
        priv->compute_success = FALSE;
        return vdata;
    }

    /* We have to make sure all commits that need to be uploaded are found locally.
     * If we have traversed up to the last uploaded commit, we've traversed all
     * needed commits.
     */
    if (!priv->visited_last_uploaded) {
        seaf_warning ("Not all commit objects need to be uploaded exist locally.\n");
        priv->compute_success = FALSE;
        return vdata;
    }

    priv->compute_success = TRUE;
    return vdata;
}

static void
compute_upload_commits_done (void *vdata)
{
    CcnetProcessor *processor = vdata;
    USE_PRIV;

    if (!priv->compute_success) {
        ccnet_processor_send_update (processor, SC_NOT_FOUND, SS_NOT_FOUND, 
                                     NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    send_one_commit (processor);
}

static void
send_commits (CcnetProcessor *processor, const char *head)
{
    SeafileSendcommitV3NewProc *proc = (SeafileSendcommitV3NewProc *)processor;
    USE_PRIV;
    char *last_uploaded;

    last_uploaded = seaf_repo_manager_get_repo_property (seaf->repo_mgr,
                                                         proc->tx_task->repo_id,
                                                         REPO_LOCAL_HEAD);
    if (!last_uploaded || strlen(last_uploaded) != 40) {
        seaf_warning ("Last uploaded commit id is not found in db or invalid.\n");
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    memcpy (priv->last_uploaded_id, last_uploaded, 40);
    g_free (last_uploaded);

    ccnet_processor_thread_create (processor,
                                   seaf->job_mgr,
                                   compute_upload_commits_thread,
                                   compute_upload_commits_done,
                                   processor);
}

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileSendcommitV3NewProc *proc = (SeafileSendcommitV3NewProc *)processor;
    TransferTask *task = proc->tx_task;
    if (task->state != TASK_STATE_NORMAL) {
        ccnet_processor_done (processor, TRUE);
        return;
    }

    switch (processor->state) {
    case INIT:
        if (memcmp (code, SC_OK, 3) == 0) {
            processor->state = SEND_OBJECT;
            send_commits (processor, task->head);
            return;
        }
        break;
    case SEND_OBJECT:
        if (memcmp (code, SC_ACK, 3) == 0) {
            send_one_commit (processor);
            return;
        }
        break;
    default:
        g_return_if_reached ();
    }

    g_warning ("Bad response: %s %s.\n", code, code_msg);
    if (memcmp (code, SC_ACCESS_DENIED, 3) == 0)
        transfer_task_set_error (task, TASK_ERR_ACCESS_DENIED);
    ccnet_processor_done (processor, FALSE);
}
