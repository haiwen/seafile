/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>
#include <ccnet.h>
#include "db.h"
#include "seafile-session.h"
#include "share-info.h"
#include "share-mgr.h"
#include "share-mgr-priv.h"
#include "put-sharedb-proc.h"

static int put_sharedb_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

typedef struct {
    char  *share_id;
    GList *sinfos;
    GList *ptr;
} PutSharedbPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_PUT_SHAREDB_PROC, PutSharedbPriv))

#define USE_PRIV \
    PutSharedbPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (PutSharedbProc, put_sharedb_proc, CCNET_TYPE_PROCESSOR)

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    if (priv->share_id)
        g_free (priv->share_id);

    CCNET_PROCESSOR_CLASS (put_sharedb_proc_parent_class)->release_resource(processor);
}


static void
put_sharedb_proc_class_init (PutSharedbProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "put-sharedb-proc";
    proc_class->start = put_sharedb_start;

    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof(PutSharedbPriv));
}

static void
put_sharedb_proc_init (PutSharedbProc *processor)
{
}

/* return TRUE if more info to send, FALSE otherwise */
static gboolean
send_share_info (CcnetProcessor *processor)
{
    USE_PRIV;

    if (!priv->ptr)
        return FALSE;
        
    SeafShareInfo *info = priv->ptr->data;
    char *s = seaf_share_info_to_json(info);

    ccnet_processor_send_response (processor, "301", "ShareInfo",
                                   s, strlen(s)+1);
    priv->ptr = priv->ptr->next;
    return TRUE;
}

static void
prepare_put_share_db (CcnetProcessor *processor)
{
    USE_PRIV;
    
    priv->sinfos = seaf_share_manager_get_group_share_info (
        seaf->share_mgr, priv->share_id);
    priv->ptr = priv->sinfos;
}

static int
put_sharedb_start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;

    if (argc != 1) {
        ccnet_processor_send_response (processor, "401", "Bad arguments",
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    priv->share_id = g_strdup(argv[0]);

    prepare_put_share_db (processor);
    if (!priv->sinfos) {
        /* we do not have any items to send to peer */
        ccnet_processor_send_response (processor, "302", "END", NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return 0;
    }

    send_share_info(processor);
    
    return 0;
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{

    if (memcmp (code, "200", 3) != 0) {
        g_warning ("[send-sharedb] received bad respones %s: %s\n", 
                   code, code_msg);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    
    if (send_share_info(processor) == FALSE) {
        ccnet_processor_send_response (processor, "302", "END", NULL, 0);
        ccnet_processor_done (processor, TRUE);
    }

    return;
}
