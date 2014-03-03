/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>

#include "common.h"
#include "seafile-session.h"
#include "check-tx-proc.h"
#include "vc-common.h"

#define SC_GET_TOKEN        "301"
#define SS_GET_TOKEN        "Get token"
#define SC_PUT_TOKEN        "302"
#define SS_PUT_TOKEN        "Put token"
#define SC_GET_VERSION      "303"
#define SS_GET_VERSION      "Get version"
#define SC_VERSION          "304"
#define SS_VERSION          "Version"

#define SC_ACCESS_DENIED    "401"
#define SS_ACCESS_DENIED    "Access denied"
#define SC_PROTOCOL_MISMATCH "405"
#define SS_PROTOCOL_MISMATCH "Protocol version mismatch"

/* Only for upload */
#define SC_QUOTA_ERROR      "402"
#define SS_QUOTA_ERROR      "Failed to get quota"
#define SC_QUOTA_FULL       "403"
#define SS_QUOTA_FULL       "storage for the repo's owner is full"

/* Only for download */
#define SC_BAD_REPO         "406"
#define SS_BAD_REPO         "Repo doesn't exist"

G_DEFINE_TYPE (SeafileCheckTxProc, seafile_check_tx_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_check_tx_proc_parent_class)->release_resource (processor);
}


static void
seafile_check_tx_proc_class_init (SeafileCheckTxProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "check-tx-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_check_tx_proc_init (SeafileCheckTxProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char buf[256];
    SeafileCheckTxProc *proc = (SeafileCheckTxProc *)processor;
    TransferTask *task = proc->task;

    if (argc != 1) {
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
    if (strcmp (argv[0], "upload") == 0)
        proc->type = CHECK_TX_TYPE_UPLOAD;
    else
        proc->type = CHECK_TX_TYPE_DOWNLOAD;

    if (proc->type == CHECK_TX_TYPE_UPLOAD)
        snprintf (buf, sizeof(buf), 
                  "remote %s seafile-check-tx-slave upload %d %s %s",
                  processor->peer_id, CURRENT_PROTO_VERSION, 
                  task->repo_id, task->to_branch);
    else
        /* Send the token no matter we're syncing with a server or
         * a peer in LAN. The server will just ignore the token.
         */
        snprintf (buf, sizeof(buf), 
                  "remote %s seafile-check-tx-slave download %d %s %s %s",
                  processor->peer_id, CURRENT_PROTO_VERSION, 
                  task->repo_id, task->from_branch, task->token);

    ccnet_processor_send_request (processor, buf);

    return 0;
}

static void
handle_upload_ok (CcnetProcessor *processor, TransferTask *task,
                  char *content, int clen)
{
    if (clen == 0) {
        ccnet_processor_send_update (processor,
                                     SC_GET_TOKEN, SS_GET_TOKEN,
                                     NULL, 0);
        return;
    }

    if (clen != 41 || content[clen-1] != '\0') {
        g_warning ("Bad response content.\n");
        transfer_task_set_error (task, TASK_ERR_UNKNOWN);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    memcpy (task->remote_head, content, 41);

    ccnet_processor_send_update (processor,
                                 SC_GET_TOKEN, SS_GET_TOKEN,
                                 NULL, 0);
}

static void
handle_download_ok (CcnetProcessor *processor, TransferTask *task,
                    char *content, int clen)
{
    if (clen != 41 || content[clen-1] != '\0') {
        g_warning ("Bad response content.\n");
        transfer_task_set_error (task, TASK_ERR_UNKNOWN);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    memcpy (task->head, content, 41);
    ccnet_processor_send_update (processor,
                                 SC_GET_TOKEN, SS_GET_TOKEN,
                                 NULL, 0);
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileCheckTxProc *proc = (SeafileCheckTxProc *)processor;
    TransferTask *task = proc->task;

    if (strncmp(code, SC_OK, 3) == 0) {
        if (proc->type == CHECK_TX_TYPE_UPLOAD)
            handle_upload_ok (processor, task, content, clen);
        else
            handle_download_ok (processor, task, content, clen);
    } else if (strncmp (code, SC_PUT_TOKEN, 3) == 0) {
        /* In LAN sync, we don't use session token. */
        if (clen == 0) {
            ccnet_processor_done (processor, TRUE);
            return;
        }

        if (content[clen-1] != '\0') {
            g_warning ("Bad response content.\n");
            transfer_task_set_error (task, TASK_ERR_UNKNOWN);
            ccnet_processor_done (processor, FALSE);
            return;
        }
        task->session_token = g_strdup (content);

        ccnet_processor_send_update (processor, SC_GET_VERSION, SS_GET_VERSION,
                                     NULL, 0);
    } else if (strncmp (code, SC_VERSION, 3) == 0) {
        task->protocol_version = atoi(content);
        ccnet_processor_done (processor, TRUE);
    } else {
        g_warning ("[check tx] Bad response: %s %s", code, code_msg);
        if (strncmp(code, SC_ACCESS_DENIED, 3) == 0)
            transfer_task_set_error (task, TASK_ERR_ACCESS_DENIED);
        else if (strncmp(code, SC_QUOTA_ERROR, 3) == 0)
            transfer_task_set_error (task, TASK_ERR_CHECK_QUOTA);
        else if (strncmp(code, SC_QUOTA_FULL, 3) == 0)
            transfer_task_set_error (task, TASK_ERR_QUOTA_FULL);
        else if (strncmp(code, SC_PROTOCOL_MISMATCH, 3) == 0)
            transfer_task_set_error (task, TASK_ERR_PROTOCOL_VERSION);
        else if (strncmp(code, SC_BAD_REPO, 3) == 0)
            transfer_task_set_error (task, TASK_ERR_BAD_REPO_ID);
        else
            transfer_task_set_error (task, TASK_ERR_UNKNOWN);
        ccnet_processor_done (processor, FALSE);
    }
}
