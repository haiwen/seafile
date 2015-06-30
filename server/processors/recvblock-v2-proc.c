/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <ccnet.h>
#include <ccnet/cevent.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "fs-mgr.h"
#include "block-mgr.h"
#include "recvblock-v2-proc.h"

#include "log.h"

enum {
    PREPARE,
    READY,
};

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_RECVBLOCK_V2_PROC, BlockProcPriv))

#define USE_PRIV \
    BlockProcPriv *priv = GET_PRIV(processor);

static int block_proc_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);
static void recv_block_cb (CEvent *event, void *vprocessor);
static void release_resource (CcnetProcessor *processor);

G_DEFINE_TYPE (SeafileRecvblockV2Proc, seafile_recvblock_v2_proc, CCNET_TYPE_PROCESSOR)

#define RECVBLOCK_PROC
#include "processors/blocktx-common-impl-v2.h"

static void
seafile_recvblock_v2_proc_class_init (SeafileRecvblockV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "recvblock-v2-proc";
    proc_class->start = block_proc_start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (BlockProcPriv));
}

static void
seafile_recvblock_v2_proc_init (SeafileRecvblockV2Proc *processor)
{
}

static int
block_proc_start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    if (verify_session_token (processor, priv->repo_id, argc, argv) < 0) {
        ccnet_processor_send_response (processor, 
                                       SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
    
    prepare_thread_data(processor, recv_blocks, recv_block_cb, priv->repo_id);
    ccnet_processor_send_response (processor, "200", "OK", NULL, 0);

    return 0;
}

static void
release_resource (CcnetProcessor *processor)
{
    release_thread (processor);

    CCNET_PROCESSOR_CLASS(seafile_recvblock_v2_proc_parent_class)->release_resource (processor);
}

static void
recv_block_cb (CEvent *event, void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    BlockResponse *blk_rsp = event->data;
    char buf[32];
    int len;

    len = snprintf (buf, 32, "%d", blk_rsp->block_idx);
    ccnet_processor_send_response (processor, SC_ACK, SS_ACK,
                                   buf, len + 1);

    g_free (blk_rsp);
}

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    USE_PRIV;

    switch (priv->tdata->state) {
    case PREPARE:
        if (memcmp (code, SC_BLOCKLIST, 3) == 0) {
            process_block_list (processor, content, clen);
            return;
        } else if (memcmp (code, SC_GET_PORT, 3) == 0) {
            send_port (processor);
            return;
        }
        break;
    }

    seaf_warning ("Bad code: %s %s\n", code, code_msg);
    ccnet_processor_send_response (processor, SC_BAD_UPDATE_CODE, 
                                   SS_BAD_UPDATE_CODE, NULL, 0);
    ccnet_processor_done (processor, FALSE);
}
