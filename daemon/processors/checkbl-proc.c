/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * checkbl-proc start
 * --------------------------->
 *
 * OK
 * <--------------------------
 *
 * Block list segment 1
 * -------------------------->
 *
 * Non-exist block list
 * <-------------------------
 *
 * Block list segment 2
 * -------------------------->
 *
 * Non-exist block list
 * <-------------------------
 *
 * Block list end
 * ------------------------->
 * 
 */

#define SC_BLOCK_LIST "301"
#define SS_BLOCK_LIST "Block list"
#define SC_NEED_BLOCKS "302"
#define SS_NEED_BLOCKS "Needed blocks"
#define SC_BLOCK_LIST_END "303"
#define SS_BLOCK_LIST_END "Block list end"

#include "checkbl-proc.h"
#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

typedef struct  {
    int offset;
} SeafileCheckblProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_CHECKBL_PROC, SeafileCheckblProcPriv))

#define USE_PRIV \
    SeafileCheckblProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafileCheckblProc, seafile_checkbl_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (seafile_checkbl_proc_parent_class)->release_resource (processor);
}


static void
seafile_checkbl_proc_class_init (SeafileCheckblProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileCheckblProcPriv));
}

static void
seafile_checkbl_proc_init (SeafileCheckblProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    SeafileCheckblProc *proc = (SeafileCheckblProc *)processor;
    TransferTask *task = proc->task;
    GString *buf = g_string_new ("");

    if (!proc->send_session_token)
        g_string_printf (buf, "remote %s seafile-checkbl", processor->peer_id);
    else
        g_string_printf (buf, "remote %s seafile-checkbl %s",
                         processor->peer_id, task->session_token);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

#define BLOCK_LIST_SEGMENT_N_BLOCKS 120
#define BLOCK_LIST_SEGMENT_LEN 40 * 120

static void
send_block_list_segment (CcnetProcessor *processor, BlockList *block_list)
{
    USE_PRIV;
    int len, limit;
    char buf[BLOCK_LIST_SEGMENT_LEN];
    char *ptr;

    if (priv->offset == block_list->n_blocks) {
        ccnet_processor_send_update (processor, SC_BLOCK_LIST_END, SS_BLOCK_LIST_END,
                                     NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    len = MIN (block_list->n_blocks - priv->offset, BLOCK_LIST_SEGMENT_N_BLOCKS);
    limit = priv->offset + len;

    for (ptr = buf; priv->offset < limit; ++(priv->offset)) {
        char *block_id = g_ptr_array_index (block_list->block_ids, priv->offset);
        memcpy (ptr, block_id, 40);
        ptr += 40;
    }

    seaf_debug ("Send %d block ids in block list segment.\n", len);
    ccnet_processor_send_update (processor, SC_BLOCK_LIST, SS_BLOCK_LIST,
                                 buf, len * 40);
}

static void
process_needed_blocks (CcnetProcessor *processor, TransferTask *task,
                       char *content, int clen)
{
    if (clen == 0) {
        seaf_debug ("No block is needed on the server.\n");
        return;
    }

    if (clen % 40 != 0) {
        seaf_warning ("Bad block list length %d.\n", clen);
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    seaf_debug ("%d blocks are needed by the server.\n", clen/40);

    int offset = 0;
    while (offset < clen) {
        char *block_id = g_new (char, 41);
        memcpy (block_id, &content[offset], 40);
        block_id[40] = 0;
        offset += 40;
        g_queue_push_tail (task->block_ids, block_id);
    }
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileCheckblProc *proc = (SeafileCheckblProc *)processor;
    TransferTask *task = proc->task;

    if (memcmp (code, SC_OK, 3) == 0) {
        send_block_list_segment (processor, task->block_list);
    } else if (memcmp (code, SC_NEED_BLOCKS, 3) == 0) {
        process_needed_blocks (processor, task, content, clen);
        send_block_list_segment (processor, task->block_list);
    } else {
        seaf_warning ("Bad response: %s %s.\n", code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}
