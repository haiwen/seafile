/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>

#include <ccnet.h>
#include "sendbranch-proc.h"

#define SC_NOT_FF       "402"
#define SS_NOT_FF       "Not fast forward"
#define SC_QUOTA_ERROR  "403"
#define SS_QUOTA_ERROR  "Failed to get quota"
#define SC_QUOTA_FULL   "404"
#define SS_QUOTA_FULL   "storage for the repo's owner is full"
#define SC_ACCESS_DENIED "410"
#define SS_ACCESS_DENIED "Access denied"

G_DEFINE_TYPE (SeafileSendbranchProc, seafile_sendbranch_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (seafile_sendbranch_proc_parent_class)->release_resource (processor);
}


static void
seafile_sendbranch_proc_class_init (SeafileSendbranchProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
    proc_class->name = "sendbranch-proc";
}

static void
seafile_sendbranch_proc_init (SeafileSendbranchProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char *repo_id, *branch, *new_head;
    GString *buf;
    TransferTask *task = ((SeafileSendbranchProc *)processor)->task;

    if (argc != 3) {
        return -1;
    }
    repo_id = argv[0];
    branch = argv[1];
    new_head = argv[2];

    buf = g_string_new (NULL);
    g_string_printf (buf, "remote %s seafile-recvbranch %s %s %s %s",
                     processor->peer_id, repo_id, branch, new_head,
                     task->session_token);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileSendbranchProc *proc = (SeafileSendbranchProc *)processor;
    TransferTask *task = proc->task;

    if (memcmp (code, SC_OK, 3) == 0) {
        ccnet_processor_done (processor, TRUE);
    } else {
        g_warning ("[sendbranch] Bad response: %s.\n", code_msg);
        if (strncmp(code, SC_NOT_FF, 3) == 0)
            transfer_task_set_error (task, TASK_ERR_NOT_FAST_FORWARD);
        else if (strncmp(code, SC_QUOTA_ERROR, 3) == 0)
            transfer_task_set_error (task, TASK_ERR_CHECK_QUOTA);
        else if (strncmp(code, SC_QUOTA_FULL, 3) == 0)
            transfer_task_set_error (task, TASK_ERR_QUOTA_FULL);
        else if (strncmp(code, SC_ACCESS_DENIED, 3) == 0)
            transfer_task_set_error (task, TASK_ERR_ACCESS_DENIED);
        else
            transfer_task_set_error (task, TASK_ERR_UNKNOWN);
        ccnet_processor_done (processor, FALSE);
    }
}
