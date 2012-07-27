/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <string.h>

#include "seafile-session.h"
#include "repostat-proc.h"

#define SC_BLOCK_LIST "301"
#define SS_BLOCK_LIST "Block list"
#define SC_BLOCK_LIST_END "302"
#define SS_BLOCK_LIST_END "Block list end"
#define SC_FINISHED "303"
#define SS_FINISHED "Finished"

typedef struct  {
    char head[41];
    BlockList *bl;
} SeafileRepostatProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_REPOSTAT_PROC, SeafileRepostatProcPriv))

#define USE_PRIV \
    SeafileRepostatProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafileRepostatProc, seafile_repostat_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);
static int start_send_block_list (CcnetProcessor *processor);
static void collect_block_list_done (CcnetProcessor *processor,
                                     int status,
                                     char *message);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    ccnet_processor_thread_cancel (processor);

    if (priv->bl)
        block_list_free (priv->bl);

    CCNET_PROCESSOR_CLASS (seafile_repostat_proc_parent_class)->release_resource (processor);
}


static void
seafile_repostat_proc_class_init (SeafileRepostatProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "repostat-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->handle_thread_done = collect_block_list_done;
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
    SeafileRepostatProc *proc = (SeafileRepostatProc *)processor;
    USE_PRIV;
    SeafRepo *repo;
    char buf[256];

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, proc->repo_id);
    if (!repo) {
        g_warning ("Failed to get repo %s.\n", proc->repo_id);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    memcpy (priv->head, repo->head->commit_id, 41);

    snprintf (buf, sizeof(buf), "remote %s seafile-repostat %s %s",
              processor->peer_id, proc->repo_id, repo->head->commit_id);
    ccnet_processor_send_request (processor, buf);

    return 0;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    if (strncmp(code, SC_OK, 3) == 0) {
        if (start_send_block_list (processor) < 0) {
            ccnet_processor_done (processor, FALSE);
        }
    } else if (strncmp(code, SC_FINISHED, 3) == 0) {
        ccnet_processor_done (processor, TRUE);
    } else {
        g_warning ("[repo stat] Bad response: %s %s", code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}

static gboolean
load_blocklist (SeafCommit *commit, void *data, gboolean *stop)
{
    BlockList *bl = data;

    if (seaf_fs_manager_populate_blocklist (seaf->fs_mgr, commit->root_id, bl) < 0)
        return FALSE;
    return TRUE;
}

static void 
collect_block_list_done (CcnetProcessor *processor,
                         int status,
                         char *message)
{
    USE_PRIV;
    uint32_t i, count = 0;
    uint32_t n_blocks = priv->bl->n_blocks;
    char buf[2048];
    char *ptr = buf;

    if (status != 0) {
        g_warning ("[repo stat] Failed to populate blocklist.\n");
        ccnet_processor_done (processor, FALSE);
        return;
    }

    for (i = 0; i < n_blocks; ++i) {
        memcpy (ptr, g_ptr_array_index(priv->bl->block_ids, i), 40);
        ptr += 40;
        *ptr++ = '\n';

        if (++count == 48) {
            *ptr = '\0';
            ccnet_processor_send_update (processor, SC_BLOCK_LIST, SS_BLOCK_LIST,
                                         buf, 41 * count + 1);
            ptr = buf;
            count = 0;
        }
    }

    /* count may be 0. */
    *ptr = '\0';
    ccnet_processor_send_update (processor, SC_BLOCK_LIST_END, SS_BLOCK_LIST_END,
                                 buf, 41 * count + 1);

    block_list_free (priv->bl);
    priv->bl = NULL;
}

static void *
collect_block_list (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;
    BlockList *bl;

    bl = block_list_new ();
    if (!seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                   priv->head,
                                                   load_blocklist,
                                                   bl)) {
        block_list_free (bl);
        ccnet_processor_thread_done (processor, -1, NULL);
        return NULL;
    }

    priv->bl = bl;
    ccnet_processor_thread_done (processor, 0, NULL);

    return NULL;
}

static int
start_send_block_list (CcnetProcessor *processor)
{
    int rc;

    rc = ccnet_processor_thread_create (processor,
                                        collect_block_list,
                                        NULL);
    if (rc < 0) {
        g_warning ("[repo stat] failed to create thread.\n");
        return -1;
    }

    return 0;
}
