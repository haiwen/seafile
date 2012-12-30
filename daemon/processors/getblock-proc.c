/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, 
 * Boston, MA 02111-1307, USA.
 */

#include "common.h"

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <ccnet.h>
#include <ccnet/cevent.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "fs-mgr.h"
#include "block-mgr.h"
#include "getblock-proc.h"
#include "processors/blocktx-common.h"

enum {
    REQUEST_SENT,
    BLOCKLIST_SENT,
    GET_PORT,
    READY,
};

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_GETBLOCK_PROC, BlockProcPriv))

#define USE_PRIV \
    BlockProcPriv *priv = GET_PRIV(processor);

static int block_proc_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);
static void release_resource (CcnetProcessor *processor);
static void got_block_cb (CEvent *event, void *vprocessor);

G_DEFINE_TYPE (SeafileGetblockProc, seafile_getblock_proc, CCNET_TYPE_PROCESSOR)

static void
seafile_getblock_proc_class_init (SeafileGetblockProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "getblock-proc";
    proc_class->start = block_proc_start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (BlockProcPriv));
}

static void
seafile_getblock_proc_init (SeafileGetblockProc *processor)
{
}

int
seafile_getblock_proc_get_block (SeafileGetblockProc *proc,
                                 int block_idx)
{
    CcnetProcessor *processor = (CcnetProcessor *)proc;
    char *block_id;
    char buf[128];
    int len;

    if (processor->state != READY)
        return -1;

    ++(proc->pending_blocks);
    BitfieldAdd (&proc->active, block_idx);

    block_id = g_ptr_array_index (proc->tx_task->block_list->block_ids, block_idx);
    len = snprintf (buf, 128, "%d %s", block_idx, block_id);
    ccnet_processor_send_update (processor,
                                 SC_GET_BLOCK, SS_GET_BLOCK,
                                 buf, len + 1);

    return 0;
}

gboolean
seafile_getblock_proc_is_ready (SeafileGetblockProc *proc)
{
    return (((CcnetProcessor *)proc)->state == READY);
}

static void
got_block_cb (CEvent *event, void *vprocessor)
{
    SeafileGetblockProc *proc = vprocessor;
    BlockResponse *blk_rsp = event->data;

    if (blk_rsp->block_idx >= 0) {
        BitfieldAdd (&proc->tx_task->block_list->block_map, blk_rsp->block_idx);
        BitfieldRem (&proc->active, blk_rsp->block_idx);
        BitfieldRem (&proc->tx_task->active, blk_rsp->block_idx);
        ++(proc->tx_task->block_list->n_valid_blocks);
    }

    /* g_debug ("[get block] rx_rate = %.6f\n", blk_rsp->rx_rate); */

    /* x = x * 7/8 + y/8  */
    if (proc->tx_bytes != 0)
        proc->tx_bytes = proc->tx_bytes - (proc->tx_bytes >> 3)
            + (blk_rsp->tx_bytes >> 3);
    else
        proc->tx_bytes = blk_rsp->tx_bytes;
    if (proc->tx_time != 0)
        proc->tx_time = proc->tx_time - (proc->tx_time >> 3)
            + (blk_rsp->tx_time >> 3);
    else
        proc->tx_time = blk_rsp->tx_time;

    if (proc->tx_time != 0)
        proc->avg_tx_rate = ((double)proc->tx_bytes) * 1000000 / proc->tx_time;

    /* g_debug ("[get block] avg_rx_rate = %.6f\n", proc->avg_rx_rate); */

    --(proc->pending_blocks);

    g_free (blk_rsp);
}

#define MASTER
#include "processors/blocktx-common-impl.h"

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileGetblockProc *proc = (SeafileGetblockProc *)processor;

    if (proc->tx_task->state != TASK_STATE_NORMAL) {
        g_debug ("Task not running, get-block proc exits.\n");
        ccnet_processor_done (processor, FALSE);
        return;
    }

    switch (processor->state) {
    case REQUEST_SENT:
        if (memcmp (code, SC_OK, 3) == 0) {
            send_block_list (processor);
            processor->state = BLOCKLIST_SENT;
            return;
        }
        break;
    case BLOCKLIST_SENT:
        if (memcmp (code, SC_BBITMAP, 3) == 0) {
            process_block_bitmap (processor, content, clen);
            return;
        }
        break;
    case GET_PORT:
        if (memcmp (code, SC_SEND_PORT, 3) == 0) {
            get_port (processor, content, clen);
            return;
        }
    }

    g_warning ("Bad response: %s %s.\n", code, code_msg);
    ccnet_processor_done (processor, FALSE);
}
