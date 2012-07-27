/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet/timer.h>
#include "seafile-session.h"
#include "heartbeat-proc.h"

/*
 * Block sizes update algorithm:
 *
 * 1. When heartbeat starts, it send the list of all current blocks to monitor;
 * 2. When a new block is sent to this chunk server, heartbeat will receive
 *    a signal from block manager. It will add the block metadata into
 *    priv->block_metadata_new queue. If more than 30 block metadata have been
 *    queued, heartbeat proc will send the list to monitor.
 * 3. On an idle chunk server, it may take long time to queue 30 blocks.
 *    To keep the monitor up-to-date, a flush timer is scheduled to flush
 *    block info to monitor every 30 seconds.
 */

#define FLUSH_INTERVAL_MSEC 30 * 1000

#define SC_BLOCK_INFO "301"
#define SS_BLOCK_INFO "Block info"

/*
    Master                        Slave

            seafile-heartbeat
       ----------------------------->
                  OK
      <-----------------------------

              Block Info
       ----------------------------->

              Block Info
       ----------------------------->
                  ...

 */

typedef struct  {
    GList *block_metadata_old;
    GList *block_metadata_new;
    int new_blocks;
    CcnetTimer *flush_timer;
} SeafileHeartbeatProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_HEARTBEAT_PROC, SeafileHeartbeatProcPriv))

#define USE_PRIV \
    SeafileHeartbeatProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafileHeartbeatProc, seafile_heartbeat_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void *collect_block_sizes (void *vprocessor);
static void collect_block_sizes_done (CcnetProcessor *processor,
                                      int status,
                                      char *message);
static void on_block_added (SeafBlockManager *block_mgr,
                            const char *block_id,
                            void *vprocessor);
static int flush_block_sizes (void *vprocessor);
static void free_md_list (GList *md_list);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    if (priv->block_metadata_old)
        free_md_list (priv->block_metadata_old);
    if (priv->block_metadata_new)
        free_md_list (priv->block_metadata_new);

    g_signal_handlers_disconnect_by_func (seaf->block_mgr, on_block_added, processor);
    ccnet_timer_free (&priv->flush_timer);

    CCNET_PROCESSOR_CLASS (seafile_heartbeat_proc_parent_class)->release_resource (processor);
}


static void
seafile_heartbeat_proc_class_init (SeafileHeartbeatProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "heartbeat-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->handle_thread_done = collect_block_sizes_done;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileHeartbeatProcPriv));
}

static void
seafile_heartbeat_proc_init (SeafileHeartbeatProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char buf[256];

    snprintf (buf, sizeof(buf), "remote %s seafile-heartbeat", 
              processor->peer_id);
    ccnet_processor_send_request (processor, buf);

    return 0;
}


static void
handle_response (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    USE_PRIV;
    int rc;

    if (strncmp (code, SC_OK, 3) == 0) {
        rc = ccnet_processor_thread_create (processor,
                                            collect_block_sizes,
                                            NULL);
        if (rc < 0) {
            g_warning ("[heartbeat] failed to create thread.\n");
            ccnet_processor_done (processor, FALSE);
        }

        g_signal_connect (seaf->block_mgr, "block-added",
                          (GCallback)on_block_added,
                          processor);

        priv->flush_timer = ccnet_timer_new (flush_block_sizes,
                                             processor,
                                             FLUSH_INTERVAL_MSEC);
    } else {
        g_warning ("[heartbeat] Bad response: %s %s\n", code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}

static void
send_block_sizes (CcnetProcessor *processor, GList *metadata)
{
    char buf[2048];
    char *ptr = buf;
    int count = 0, n;
    GList *md_list = metadata;
    BlockMetadata *md;

    while (md_list) {
        md = md_list->data;
        md_list = g_list_delete_link (md_list, md_list);

        n = snprintf (ptr, 60, "%s %u\n", md->id, md->size);
        ptr += n;

        if (++count == 30) {
            ccnet_processor_send_update (processor, 
                                         SC_BLOCK_INFO, SS_BLOCK_INFO, 
                                         buf, (ptr - buf) + 1);
            count = 0;
            ptr = buf;
        }
        g_free (md);
    }

    if (count) {
        ccnet_processor_send_update (processor, 
                                     SC_BLOCK_INFO, SS_BLOCK_INFO, 
                                     buf, (ptr - buf) + 1);
    }
}

static void *
collect_block_sizes (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    GList *metadata_list;
    USE_PRIV;

    metadata_list = seaf_block_manager_get_all_block_metadata (seaf->block_mgr);
    /* if (!metadata_list) { */
    /*     ccnet_processor_thread_done (processor, -1, NULL); */
    /*     return NULL; */
    /* } */

    priv->block_metadata_old = metadata_list;
    ccnet_processor_thread_done (processor, 0, NULL);
    return NULL;
}

static void 
collect_block_sizes_done (CcnetProcessor *processor,
                          int status,
                          char *message)
{
    USE_PRIV;

    if (status == 0) {
        g_message ("[hearbeat] collected block sizes on start.\n");
        send_block_sizes (processor, priv->block_metadata_old);
        priv->block_metadata_old = NULL;
    } else {
        g_warning ("Failed to collect block sizes.\n");
        ccnet_processor_done (processor, FALSE);
    }
}

static void 
on_block_added (SeafBlockManager *block_mgr,
                const char *block_id,
                void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    BlockMetadata *md;
    USE_PRIV;

    md = seaf_block_manager_stat_block (block_mgr, block_id);
    if (!md) {
        g_warning ("[heartbeat] Failed to stat block %s\n", block_id);
        return;
    }

    g_message ("Queue block %s, size is %u\n", block_id, md->size);

    priv->block_metadata_new = g_list_prepend (priv->block_metadata_new, md);
    if (++priv->new_blocks == 30) {
        send_block_sizes (processor, priv->block_metadata_new);
        priv->block_metadata_new = NULL;
        priv->new_blocks = 0;
    }
}

static int
flush_block_sizes (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;

    if (priv->new_blocks != 0) {
        g_message ("Flushing %u blocks to monitor.\n", priv->new_blocks);
        send_block_sizes (processor, priv->block_metadata_new);
        priv->block_metadata_new = NULL;
        priv->new_blocks = 0;
    }

    return 1;
}

static void 
free_md_list (GList *md_list)
{
    BlockMetadata *md;

    while (md_list) {
        md = md_list->data;
        md_list = g_list_delete_link (md_list, md_list);
        g_free (md);
    }
}
