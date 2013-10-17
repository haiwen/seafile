/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "seafile-session.h"
#include "checkbl-proc.h"
#include "log.h"

#define SC_BLOCK_LIST "301"
#define SS_BLOCK_LIST "Block list"
#define SC_NEED_BLOCKS "302"
#define SS_NEED_BLOCKS "Needed blocks"
#define SC_BLOCK_LIST_END "303"
#define SS_BLOCK_LIST_END "Block list end"

typedef struct  {
    gboolean processing;
    char *block_list;
    int len;
    GString *buf;
    gboolean success;
} SeafileCheckblProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_CHECKBL_PROC, SeafileCheckblProcPriv))

#define USE_PRIV \
    SeafileCheckblProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafileCheckblProc, seafile_checkbl_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    g_free (priv->block_list);
    if (priv->buf)
        g_string_free (priv->buf, TRUE);

    CCNET_PROCESSOR_CLASS (seafile_checkbl_proc_parent_class)->release_resource (processor);
}


static void
seafile_checkbl_proc_class_init (SeafileCheckblProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_update = handle_update;
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
    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
    return 0;
}

static void *
check_bl (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;

    priv->buf = g_string_new ("");
    int offset = 0;
    char block_id[41];
    while (offset < priv->len) {
        memcpy (block_id, &priv->block_list[offset], 40);
        block_id[40] = 0;

        if (!seaf_block_manager_block_exists(seaf->block_mgr, block_id))
            g_string_append (priv->buf, block_id);

        offset += 40;
    }

    priv->success = TRUE;
    return vprocessor;
}

static void
check_bl_done (void *result)
{
    CcnetProcessor *processor = result;
    USE_PRIV;

    if (priv->success) {
        ccnet_processor_send_response (processor, SC_NEED_BLOCKS, SS_NEED_BLOCKS,
                                       priv->buf->str, priv->buf->len);

        priv->processing = FALSE;
        g_free (priv->block_list);
        priv->block_list = NULL;
        g_string_free (priv->buf, TRUE);
        priv->buf = NULL;
        priv->success = FALSE;
    } else {
        ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    USE_PRIV;

    if (memcmp (code, SC_BLOCK_LIST, 3) == 0) {
        /* We can't process more than one block list segments at the same time. */
        if (priv->processing) {
            ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                           NULL, 0);
            ccnet_processor_done (processor, FALSE);
            return;
        }

        if (clen == 0 || clen % 40 != 0) {
            seaf_warning ("Bad block list length %d.\n", priv->len);
            ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                           NULL, 0);
            ccnet_processor_done (processor, FALSE);
            return;
        }

        priv->processing = TRUE;
        priv->block_list = g_memdup (content, clen);
        priv->len = clen;
        ccnet_processor_thread_create (processor, seaf->job_mgr,
                                       check_bl, check_bl_done, processor);
    } else if (memcmp (code, SC_BLOCK_LIST_END, 3) == 0) {
        ccnet_processor_done (processor, TRUE);
    } else {
        seaf_warning ("Bad update: %s %s.\n", code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}
