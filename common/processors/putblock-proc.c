/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "fs-mgr.h"
#include "block-mgr.h"
#include "putblock-proc.h"
#include "processors/blocktx-common.h"

enum {
    PREPARE,
    READY,
};

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_PUTBLOCK_PROC, BlockProcPriv))

#define USE_PRIV \
    BlockProcPriv *priv = GET_PRIV(processor);

static int block_proc_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);
static void release_resource (CcnetProcessor *processor);

G_DEFINE_TYPE (SeafilePutblockProc, seafile_putblock_proc, CCNET_TYPE_PROCESSOR)

static void
seafile_putblock_proc_class_init (SeafilePutblockProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "putblock-proc";
    proc_class->start = block_proc_start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (BlockProcPriv));
}

static void
seafile_putblock_proc_init (SeafilePutblockProc *processor)
{
}

#define SEND
#include "processors/blocktx-common-impl.h"

static void
process_get_block (CcnetProcessor *processor, char *content, int clen)
{
    char *space, *block_id;
    USE_PRIV;

    if (content[clen-1] != '\0') {
        ccnet_processor_send_response (processor, SC_BAD_BLK_REQ, SS_BAD_BLK_REQ,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    space = strchr (content, ' ');
    if (!space) {
        ccnet_processor_send_response (processor, SC_BAD_BLK_REQ, SS_BAD_BLK_REQ,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    *space = '\0';
    block_id = space + 1;

    BlockRequest req;
    req.block_idx = atoi(content);
    memcpy (req.block_id, block_id, 41);
    if (pipewriten (priv->tdata->task_pipe[1], &req, sizeof(BlockRequest)) < 0) {
        g_warning ("[put block] failed to write task pipe.\n");
        ccnet_processor_done (processor, FALSE);
    }
}

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
    case READY:
        if (memcmp (code, SC_GET_BLOCK, 3) == 0) {
            process_get_block (processor, content, clen);
            return;
        }
        break;
    }

    g_warning ("Bad code: %s %s\n", code, code_msg);
    ccnet_processor_send_response (processor, SC_BAD_UPDATE_CODE, 
                                   SS_BAD_UPDATE_CODE, NULL, 0);
    ccnet_processor_done (processor, FALSE);
}
