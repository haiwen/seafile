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
#include "getblock-v2-proc.h"

enum {
    REQUEST_SENT,
    BLOCKLIST_SENT,
    GET_PORT,
    READY,
};

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_GETBLOCK_V2_PROC, BlockProcPriv))

#define USE_PRIV \
    BlockProcPriv *priv = GET_PRIV(processor);

static int block_proc_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);
static void release_resource (CcnetProcessor *processor);
static void got_block_cb (CEvent *event, void *vprocessor);

G_DEFINE_TYPE (SeafileGetblockV2Proc, seafile_getblock_v2_proc, CCNET_TYPE_PROCESSOR)

#define GETBLOCK_PROC
#include "processors/blocktx-common-impl-v2.h"

static void
seafile_getblock_v2_proc_class_init (SeafileGetblockV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "getblock-v2-proc";
    proc_class->start = block_proc_start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (BlockProcPriv));
}

static void
seafile_getblock_v2_proc_init (SeafileGetblockV2Proc *processor)
{
}

static int
block_proc_start (CcnetProcessor *processor, int argc, char **argv)
{
    SeafileGetblockV2Proc *proc = (SeafileGetblockV2Proc *)processor;
    USE_PRIV;
    
    if (master_block_proc_start(processor, proc->tx_task,
                                "seafile-putblock-v2",
                                &proc->active,
                                &proc->block_bitmap) < 0) {
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    prepare_thread_data (processor, recv_blocks, got_block_cb,
                         proc->tx_task->repo_id);
    priv->tdata->task = proc->tx_task;

    return 0;
}

static void
release_resource (CcnetProcessor *processor)
{
    SeafileGetblockV2Proc *proc = (SeafileGetblockV2Proc *)processor;

    release_thread (processor);
    descruct_bitfield (&proc->block_bitmap, &proc->active, proc->tx_task);

    CCNET_PROCESSOR_CLASS(seafile_getblock_v2_proc_parent_class)->release_resource (processor);
}

int
seafile_getblock_v2_proc_get_block (SeafileGetblockV2Proc *proc,
                                 int block_idx)
{
    CcnetProcessor *processor = (CcnetProcessor *)proc;
    char *block_id;
    char buf[128];
    int len;

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
seafile_getblock_v2_proc_is_ready (SeafileGetblockV2Proc *proc)
{
    CcnetProcessor *processor = (CcnetProcessor *)proc;
    USE_PRIV;

    return (g_atomic_int_get(&priv->tdata->state) == READY);
}

static void
got_block_cb (CEvent *event, void *vprocessor)
{
    SeafileGetblockV2Proc *proc = vprocessor;
    BlockResponse *blk_rsp = event->data;

    if (blk_rsp->block_idx >= 0) {
        BitfieldAdd (&proc->tx_task->block_list->block_map, blk_rsp->block_idx);
        BitfieldRem (&proc->active, blk_rsp->block_idx);
        BitfieldRem (&proc->tx_task->active, blk_rsp->block_idx);
        ++(proc->tx_task->block_list->n_valid_blocks);
        --(proc->pending_blocks);
    }

    g_free (blk_rsp);
}

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileGetblockV2Proc *proc = (SeafileGetblockV2Proc *)processor;
    USE_PRIV;

    if (proc->tx_task->state != TASK_STATE_NORMAL) {
        g_debug ("Task not running, get-block proc exits.\n");
        ccnet_processor_done (processor, TRUE);
        return;
    }

    switch (priv->tdata->state) {
    case REQUEST_SENT:
        if (memcmp (code, SC_OK, 3) == 0) {
            send_block_list (processor);
            priv->tdata->state = BLOCKLIST_SENT;
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
    if (memcmp (code, SC_ACCESS_DENIED, 3) == 0)
        transfer_task_set_error (proc->tx_task, TASK_ERR_ACCESS_DENIED);
    ccnet_processor_done (processor, FALSE);
}
