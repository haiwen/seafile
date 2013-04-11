/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <string.h>
#include <ccnet.h>

#include "seafile-session.h"
#include "vc-common.h"
#include "seafile-crypt.h"
#include "log.h"
#include "utils.h"

#include "check-tx-v2-proc.h"

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

enum {
    CHECK_TX_TYPE_UPLOAD,
    CHECK_TX_TYPE_DOWNLOAD,
};

G_DEFINE_TYPE (SeafileCheckTxV2Proc, seafile_check_tx_v2_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_check_tx_v2_proc_parent_class)->release_resource (processor);
}


static void
seafile_check_tx_v2_proc_class_init (SeafileCheckTxV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "check-tx-proc-v2";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_check_tx_v2_proc_init (SeafileCheckTxV2Proc *processor)
{
}

/* token -> AES encrypt with session key -> rawdata_to_hex -> output  */
static char *
encrypt_token (CcnetProcessor *processor, const char *token)
{
    CcnetPeer *peer = NULL;
    char *enc_out = NULL;
    SeafileCrypt *crypt = NULL;
    unsigned char key[16], iv[16];
    int len;
    char *output = NULL;

    if (!token)
        goto out;

    peer = ccnet_get_peer(seaf->ccnetrpc_client, processor->peer_id);
    if (!peer || !peer->session_key) {
        seaf_warning ("[check tx v2] peer or peer session key not exist\n");
        goto out;
    }

    seafile_generate_enc_key (peer->session_key,
                              strlen(peer->session_key),
                              CURRENT_ENC_VERSION, key, iv);
                              
    crypt = seafile_crypt_new (CURRENT_ENC_VERSION, key, iv);
    
    /* encrypt the token with session key, including the trailing null byte */
    if (seafile_encrypt (&enc_out, &len, token, strlen(token) + 1, crypt) < 0) {
        seaf_warning ("[check tx v2] failed to encrypt token\n");
        goto out;
    }

    output = g_malloc (len * 2 + 1);
    rawdata_to_hex ((unsigned char *)enc_out, output, len);
    output[len * 2] = '\0';

    
out:
    g_free (crypt);
    g_free (enc_out);
    if (peer)
        g_object_unref(peer);

    return output;
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    SeafileCheckTxV2Proc *proc = (SeafileCheckTxV2Proc *)processor;
    TransferTask *task = proc->task;
    char *type, *enc_token;
    GString *buf;

    if (argc != 1) {
        transition_state_to_error (task, TASK_ERR_CHECK_UPLOAD_START);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    type = argv[0];
    if (strcmp (type, "upload") == 0)
        proc->type = CHECK_TX_TYPE_UPLOAD;
    else
        proc->type = CHECK_TX_TYPE_DOWNLOAD;

    enc_token = encrypt_token (processor, task->token);
    if (!enc_token) {
        transition_state_to_error (task, TASK_ERR_CHECK_UPLOAD_START);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    buf = g_string_new(NULL);
    g_string_append_printf (buf,
              "remote %s seafile-check-tx-slave-v2 %s %d %s %s %s",
              processor->peer_id, type, CURRENT_PROTO_VERSION, 
            task->repo_id, task->to_branch, enc_token);

    ccnet_processor_send_request (processor, buf->str);

    g_free (enc_token);
    g_string_free (buf, TRUE);

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
        ccnet_processor_send_update (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    memcpy (task->remote_head, content, 41);

    /* Check fast-forward here. */
    if (strcmp (task->head, task->remote_head) != 0 &&
        !is_fast_forward (task->head, task->remote_head)) {
        g_warning ("Upload is not fast-forward.\n");
        transfer_task_set_error (task, TASK_ERR_NOT_FAST_FORWARD);
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }
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
        ccnet_processor_send_update (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
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
    SeafileCheckTxV2Proc *proc = (SeafileCheckTxV2Proc *)processor;
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
            ccnet_processor_send_update (processor, SC_BAD_ARGS, SS_BAD_ARGS,
                                         NULL, 0);
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
        g_warning ("[check tx v2] Bad response: %s %s", code, code_msg);
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
