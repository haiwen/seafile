/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>
#include <sys/stat.h>

#include <ccnet.h>
#include "utils.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "fs-mgr.h"
#include "processors/objecttx-common.h"
#include "putfs-proc.h"

typedef struct  {
    guint32     reader_id;
    gboolean    registered;

    /* Used for getting repo info */
    char        repo_id[37];
    char        store_id[37];
    int         repo_version;
    gboolean    success;
} PutfsProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_PUTFS_PROC, PutfsProcPriv))

#define USE_PRIV \
    PutfsProcPriv *priv = GET_PRIV(processor);

G_DEFINE_TYPE (SeafilePutfsProc, seafile_putfs_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);
static void
read_done_cb (OSAsyncResult *res, void *cb_data);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    if (priv->registered)
        seaf_obj_store_unregister_async_read (seaf->fs_mgr->obj_store,
                                              priv->reader_id);

    CCNET_PROCESSOR_CLASS (seafile_putfs_proc_parent_class)->release_resource (processor);
}


static void
seafile_putfs_proc_class_init (SeafilePutfsProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "putfs-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (PutfsProcPriv));
}

static void
seafile_putfs_proc_init (SeafilePutfsProc *processor)
{
}

static void *
get_repo_info_thread (void *data)
{
    CcnetProcessor *processor = data;
    USE_PRIV;
    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, priv->repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", priv->repo_id);
        priv->success = FALSE;
        return data;
    }

    memcpy (priv->store_id, repo->store_id, 36);
    priv->repo_version = repo->version;
    priv->success = TRUE;

    seaf_repo_unref (repo);
    return data;
}

static void
get_repo_info_done (void *data)
{
    CcnetProcessor *processor = data;
    USE_PRIV;

    if (priv->success) {
        priv->registered = TRUE;
        priv->reader_id =
            seaf_obj_store_register_async_read (seaf->fs_mgr->obj_store,
                                                priv->store_id,
                                                priv->repo_version,
                                                read_done_cb,
                                                processor);

        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
    } else {
        ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char *session_token;
    char repo_id[37];
    USE_PRIV;

    if (argc != 1) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    session_token = argv[0];
    if (seaf_token_manager_verify_token (seaf->token_mgr,
                                         NULL,
                                         processor->peer_id,
                                         session_token, repo_id) < 0) {
        ccnet_processor_send_response (processor, 
                                       SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    memcpy (priv->repo_id, repo_id, 36);
    ccnet_processor_thread_create (processor,
                                   seaf->job_mgr,
                                   get_repo_info_thread,
                                   get_repo_info_done,
                                   processor);

    return 0;
}

static void
read_done_cb (OSAsyncResult *res, void *cb_data)
{
    CcnetProcessor *processor = cb_data;
    ObjectPack *pack = NULL;
    int pack_size;

    if (!res->success) {
        seaf_warning ("[putfs] Failed to read %s.\n", res->obj_id);
        ccnet_processor_send_response (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    pack_size = sizeof(ObjectPack) + res->len;
    pack = malloc (pack_size);
    memcpy (pack->id, res->obj_id, 41);
    memcpy (pack->object, res->data, res->len);

    if (pack_size <= MAX_OBJ_SEG_SIZE) {
        ccnet_processor_send_response (processor, SC_OBJECT, SS_OBJECT,
                                     (char *)pack, pack_size);
    } else {
        int offset, n;

        offset = 0;
        while (offset < pack_size) {
            n = MIN(pack_size - offset, MAX_OBJ_SEG_SIZE);

            if (offset + n < pack_size) {
                ccnet_processor_send_response (processor,
                                             SC_OBJ_SEG, SS_OBJ_SEG,
                                             (char *)pack + offset, n);
            } else {
                ccnet_processor_send_response (processor,
                                             SC_OBJ_SEG_END, SS_OBJ_SEG_END,
                                             (char *)pack + offset, n);
            }
            seaf_debug ("[putfs] Sent object %s segment<total = %d, offset = %d, n = %d>\n",
                        res->obj_id, pack_size, offset, n);
            offset += n;
        }
    }

    free (pack);

    seaf_debug ("Send fs object %.8s.\n", res->obj_id);
}

static gboolean
send_fs_object (CcnetProcessor *processor, char *object_id)
{
    USE_PRIV;

    if (seaf_obj_store_async_read (seaf->fs_mgr->obj_store,
                                   priv->reader_id,
                                   object_id) < 0) {
        seaf_warning ("[putfs] Failed to start async read of %s.\n", object_id);
        ccnet_processor_send_response (processor, SC_BAD_OBJECT, SS_BAD_OBJECT,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return FALSE;
    }

    return TRUE;
}

static void
send_fs_objects (CcnetProcessor *processor, char *content, int clen)
{
    char *object_id;
    int n_objects;
    int i;

    if (clen % 41 != 1 || content[clen-1] != '\0') {
        seaf_warning ("[putfs] Bad fs object list.\n");
        ccnet_processor_send_response (processor, SC_BAD_OL, SS_BAD_OL, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    n_objects = clen/41;

    object_id = content;
    for (i = 0; i < n_objects; ++i) {
        object_id[40] = '\0';
        if (send_fs_object (processor, object_id) == FALSE)
            return;
        object_id += 41;
    }
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    if (strncmp(code, SC_GET_OBJECT, 3) == 0) {
        send_fs_objects (processor, content, clen);
    } else if (strncmp(code, SC_END, 3) == 0) {
        ccnet_processor_done (processor, TRUE);     
    } else {
        seaf_warning ("[putfs] Bad update: %s %s\n", code, code_msg);
        ccnet_processor_send_response (processor,
                                       SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }
}
