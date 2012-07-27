/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>

#include <ccnet.h>

#include "common.h"
#include "seafile-session.h"
#include "check-tx-slave-proc.h"

#define SC_GET_TOKEN        "301"
#define SS_GET_TOKEN        "Get token"
#define SC_PUT_TOKEN        "302"
#define SS_PUT_TOKEN        "Put token"

#define SC_ACCESS_DENIED    "401"
#define SS_ACCESS_DENIED    "Access denied"
#define SC_BAD_REPO         "402"
#define SS_BAD_REPO         "Repo doesn't exist"
#define SC_NO_BRANCH        "404"
#define SS_NO_BRANCH        "Branch not found"

G_DEFINE_TYPE (SeafileCheckTxSlaveProc, seafile_check_tx_slave_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (seafile_check_tx_slave_proc_parent_class)->release_resource (processor);
}


static void
seafile_check_tx_slave_proc_class_init (SeafileCheckTxSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);
    proc_class->name = "check-tx-slave-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;
}

static void
seafile_check_tx_slave_proc_init (SeafileCheckTxSlaveProc *processor)
{
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char *repo_id, *token, *from_branch, *version;
    SeafBranch *branch;

    if (argc != 5) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (strcmp (argv[0], "download") != 0) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    version = argv[1];
    repo_id = argv[2];
    from_branch = argv[3];
    token = argv[4];

    if (atoi (version) != CURRENT_PROTO_VERSION) {
        ccnet_processor_send_response (processor, 
                                       SC_VERSION_MISMATCH, SS_VERSION_MISMATCH,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (strlen(repo_id) != 36) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        ccnet_processor_send_response (processor, SC_BAD_REPO, SS_BAD_REPO, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (seaf_repo_manager_verify_tmp_token (seaf->repo_mgr, repo_id,
                                            processor->peer_id, token)) {
        g_debug ("[chek-down] verify tmp toke for repo %s success\n", repo_id);
        goto ret_ok;
    }
    if (!repo->net_browsable)
        goto ret_no;

    if (seaf_repo_manager_verify_repo_lantoken (seaf->repo_mgr, repo_id, token))
        goto ret_ok;

ret_no:
    ccnet_processor_send_response (processor, SC_ACCESS_DENIED, SS_ACCESS_DENIED, 
                                   NULL, 0);
    ccnet_processor_done (processor, FALSE);
    return -1;

ret_ok:
    branch = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                             repo_id, from_branch);
    if (branch != NULL) {
        ccnet_processor_send_response (processor, SC_OK, SS_OK,
                                       branch->commit_id, 41);
        seaf_branch_unref (branch);
        return 0;
    } else {
        ccnet_processor_send_response (processor, SC_NO_BRANCH, SS_NO_BRANCH,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
    return 0;
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    /* We don't use session token in LAN sync. */
    if (memcmp (code, SC_GET_TOKEN, 3) == 0) {
        ccnet_processor_send_response (processor, SC_PUT_TOKEN, SS_PUT_TOKEN,
                                       NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    g_warning ("Bad update: %s %s.\n", code, code_msg);
    ccnet_processor_send_response (processor, 
                                   SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                   NULL, 0);
    ccnet_processor_done (processor, FALSE);
}
