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
#include "recvblock-proc.h"
#include "processors/blocktx-common.h"

#include "log.h"

enum {
    PREPARE,
    READY,
};

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_RECVBLOCK_PROC, BlockProcPriv))

#define USE_PRIV \
    BlockProcPriv *priv = GET_PRIV(processor);

static int block_proc_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);
static void recv_block_cb (CEvent *event, void *vprocessor);
static void release_resource (CcnetProcessor *processor);

G_DEFINE_TYPE (SeafileRecvblockProc, seafile_recvblock_proc, CCNET_TYPE_PROCESSOR)

static void
seafile_recvblock_proc_class_init (SeafileRecvblockProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "recvblock-proc";
    proc_class->start = block_proc_start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (BlockProcPriv));
}

static void
seafile_recvblock_proc_init (SeafileRecvblockProc *processor)
{
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

#include "processors/blocktx-common-impl.h"

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    switch (processor->state) {
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
