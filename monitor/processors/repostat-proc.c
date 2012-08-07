/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <string.h>

#include "monitor.h"
#include "repostat-proc.h"

#define SC_BLOCK_LIST "301"
#define SS_BLOCK_LIST "Block list"
#define SC_BLOCK_LIST_END "302"
#define SS_BLOCK_LIST_END "Block list end"
#define SC_FINISHED "303"
#define SS_FINISHED "Finished"

#define SC_DB_ERROR "401"
#define SS_DB_ERROR "Database error"
#define SC_BAD_BL "402"
#define SS_BAD_BL "Bad block list format"

typedef struct  {
    char repo_id[41];
    char head[41];
    GPtrArray *block_ids;
    uint64_t repo_size;
    int is_accurate;
} SeafileRepostatProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_REPOSTAT_PROC, SeafileRepostatProcPriv))

#define USE_PRIV \
    SeafileRepostatProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafileRepostatProc, seafile_repostat_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);
static void process_block_list (CcnetProcessor *processor,
                                char *list,
                                int len);
static int start_compute (CcnetProcessor *processor);
static void computation_finished (CcnetProcessor *processor,
                                  int status,
                                  char *message);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    ccnet_processor_thread_cancel (processor);

    if (priv->block_ids)
        g_ptr_array_free (priv->block_ids, TRUE);

    CCNET_PROCESSOR_CLASS (seafile_repostat_proc_parent_class)->release_resource (processor);
}


static void
seafile_repostat_proc_class_init (SeafileRepostatProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->handle_thread_done = computation_finished;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileRepostatProcPriv));
}

static void
seafile_repostat_proc_init (SeafileRepostatProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;

    if (argc != 2 || strlen(argv[0]) != 36 || strlen(argv[1]) != 40) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (seaf_monitor_is_repo_size_uptodate (singleton_monitor,
                                            argv[0], argv[1])) {
        g_message ("repo size %s is up-to-date.\n", argv[0]);
        ccnet_processor_send_response (processor, SC_FINISHED, SS_FINISHED, NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return 0;
    }

    memcpy (priv->repo_id, argv[0], 41);
    memcpy (priv->head, argv[1], 41);
    priv->block_ids = g_ptr_array_new_with_free_func (g_free);
    priv->is_accurate = 1;

    ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);

    return 0;
}


static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    if (strncmp (code, SC_BLOCK_LIST, 3) == 0) {
        process_block_list (processor, content, clen);
    } else if (strncmp (code, SC_BLOCK_LIST_END, 3) == 0) {
        process_block_list (processor, content, clen);
        start_compute (processor);
    } else {
        g_warning ("[repo stat] Bad update: %s %s.\n", code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}

static void 
process_block_list (CcnetProcessor *processor, char *list, int len)
{
    USE_PRIV;
    char *block_id;
    int n_blocks;
    int i;

    if (len % 41 != 1 || list[len - 1] != '\0') {
        ccnet_processor_send_response (processor, SC_BAD_BL, SS_BAD_BL, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    n_blocks = len/41;

    block_id = list;
    for (i = 0; i < n_blocks; ++i) {
        block_id[40] = '\0';
        g_ptr_array_add (priv->block_ids, g_strdup(block_id));
        block_id += 41;
    }
}

static void *
compute_repo_size (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;
    uint32_t n_blocks, i;
    uint64_t repo_size = 0;
    char *block_id;
    uint32_t block_size;
    int status = 0;

    g_message ("Compute size of repo %s.\n", priv->repo_id);

    n_blocks = priv->block_ids->len;
    for (i = 0; i < n_blocks; ++i) {
        block_id = g_ptr_array_index (priv->block_ids, i);
        block_size = seaf_monitor_get_block_size (singleton_monitor, block_id);
        /*
         * If we cannot get accurate block size, use avg block size (1MB).
         */
        if (block_size == 0) {
            block_size = 1 << 20;
            priv->is_accurate = 0;
        }
        repo_size += block_size;
    }

    priv->repo_size = repo_size;
    ccnet_processor_thread_done (processor, status, NULL);

    return NULL;
}

static int 
start_compute (CcnetProcessor *processor)
{
    int rc;

    rc = ccnet_processor_thread_create (processor,
                                        compute_repo_size,
                                        NULL);
    if (rc < 0) {
        g_warning ("[repo stat] failed to create thread.\n");
        return -1;
    }

    return 0;
}

static void 
computation_finished (CcnetProcessor *processor,
                      int status,
                      char *message)
{
    USE_PRIV;

    g_ptr_array_free (priv->block_ids, TRUE);
    priv->block_ids = NULL;

    g_message ("Finished computing size of repo %s.\n", priv->repo_id);

    /* Store repo size into database.
     */
    if (seaf_monitor_set_repo_size (singleton_monitor, 
                                    priv->repo_id, 
                                    priv->repo_size,
                                    priv->is_accurate,
                                    priv->head) < 0) {
        ccnet_processor_send_response (processor,
                                       SC_DB_ERROR, SS_DB_ERROR,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }

    ccnet_processor_send_response (processor, SC_FINISHED, SS_FINISHED, NULL, 0);
    ccnet_processor_done (processor, TRUE);
}
