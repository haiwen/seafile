/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <ccnet.h>
#include "utils.h"

#include "seafile-session.h"
#include "fs-mgr.h"
#include "processors/objecttx-common.h"
#include "recvfs-v2-proc.h"
#include "seaf-utils.h"

enum {
    CHECK_OBJECT_LIST = 0,
    RECV_OBJECTS,
};

typedef struct  {
    char *obj_seg;
    int obj_seg_len;

    gboolean registered;
    guint32  writer_id;

    /* Used for getting repo info */
    char        repo_id[37];
    char        store_id[37];
    int         repo_version;
    gboolean    success;

    /* Used to check object list */
    char *recv_objs;
    int recv_len;
    GList *needed_objs;
    int n_needed;

    int total_needed;
    int n_saved;
} SeafileRecvfsProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_RECVFS_V2_PROC, SeafileRecvfsProcPriv))

#define USE_PRIV \
    SeafileRecvfsProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafileRecvfsV2Proc, seafile_recvfs_v2_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    g_free (priv->obj_seg);
    
    if (priv->registered) {
        seaf_obj_store_unregister_async_write (seaf->fs_mgr->obj_store,
                                               priv->writer_id);
    }

    g_free (priv->recv_objs);
    string_list_free (priv->needed_objs);

    CCNET_PROCESSOR_CLASS (seafile_recvfs_v2_proc_parent_class)->release_resource (processor);
}

static void
seafile_recvfs_v2_proc_class_init (SeafileRecvfsV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "recvfs-v2-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileRecvfsProcPriv));
}

static void
seafile_recvfs_v2_proc_init (SeafileRecvfsV2Proc *processor)
{
}

static void
on_fs_write (OSAsyncResult *res, void *cb_data);

static void
register_async_io (CcnetProcessor *processor)
{
    USE_PRIV;

    priv->registered = TRUE;
    priv->writer_id = seaf_obj_store_register_async_write (seaf->fs_mgr->obj_store,
                                                           priv->store_id,
                                                           priv->repo_version,
                                                           on_fs_write,
                                                           processor);
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
        ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        register_async_io (processor);
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
                                         session_token, priv->repo_id) == 0) {
        ccnet_processor_thread_create (processor,
                                       seaf->job_mgr,
                                       get_repo_info_thread,
                                       get_repo_info_done,
                                       processor);
        return 0;
    } else {
        ccnet_processor_send_response (processor, 
                                       SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
}

static void
on_fs_write (OSAsyncResult *res, void *cb_data)
{
    CcnetProcessor *processor = cb_data;
    USE_PRIV;

    if (!res->success) {
        seaf_warning ("[recvfs] Failed to write %s.\n", res->obj_id);
        ccnet_processor_send_response (processor, SC_BAD_OBJECT, SS_BAD_OBJECT,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    seaf_debug ("[recvfs] Wrote fs object %s.\n", res->obj_id);

    if (++(priv->n_saved) == priv->total_needed) {
        seaf_debug ("All objects saved. Done.\n");
        ccnet_processor_send_response (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
    }
}

static int
save_fs_object (CcnetProcessor *processor, ObjectPack *pack, int len)
{
    USE_PRIV;

    return seaf_obj_store_async_write (seaf->fs_mgr->obj_store,
                                       priv->writer_id,
                                       pack->id,
                                       pack->object,
                                       len - 41,
                                       FALSE);
}

static int
recv_fs_object (CcnetProcessor *processor, char *content, int clen)
{
    ObjectPack *pack = (ObjectPack *)content;
    /* SeafFSObject *fs_obj = NULL; */

    if (clen < sizeof(ObjectPack)) {
        seaf_warning ("invalid object id.\n");
        goto bad;
    }

    seaf_debug ("[recvfs] Recv fs object %.8s.\n", pack->id);

    /* Check object integrity by parsing it. */
    /* fs_obj = seaf_fs_object_from_data(pack->id, */
    /*                                   pack->object, clen - sizeof(ObjectPack), */
    /*                                   (priv->repo_version > 0)); */
    /* if (!fs_obj) { */
    /*     seaf_warning ("Bad fs object %s.\n", pack->id); */
    /*     goto bad; */
    /* } */

    /* seaf_fs_object_free (fs_obj); */

    if (save_fs_object (processor, pack, clen) < 0) {
        goto bad;
    }

    return 0;

bad:
    ccnet_processor_send_response (processor, SC_BAD_OBJECT,
                                   SS_BAD_OBJECT, NULL, 0);
    seaf_warning ("[recvfs] Bad fs object received.\n");
    ccnet_processor_done (processor, FALSE);

    /* seaf_fs_object_free (fs_obj); */

    return -1;
}

static void
recv_fs_object_seg (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;

    /* Append the received object segment to the end */
    priv->obj_seg = g_realloc (priv->obj_seg, priv->obj_seg_len + clen);
    memcpy (priv->obj_seg + priv->obj_seg_len, content, clen);

    seaf_debug ("[recvfs] Get obj seg: <id= %40s, offset= %d, lenth= %d>\n",
                priv->obj_seg, priv->obj_seg_len, clen);

    priv->obj_seg_len += clen;
}

static void
process_fs_object_seg (CcnetProcessor *processor)
{
    USE_PRIV;

    if (recv_fs_object (processor, priv->obj_seg, priv->obj_seg_len) == 0) {
        g_free (priv->obj_seg);
        priv->obj_seg = NULL;
        priv->obj_seg_len = 0;
    }
}

static void *
process_object_list (void *data)
{
    CcnetProcessor *processor = data;
    USE_PRIV;
    int n, i;
    char *p;
    char *obj_id;

    n = priv->recv_len/40;
    p = priv->recv_objs;

    for (i = 0; i < n; ++i) {
        obj_id = g_strndup (p, 40);

        if (!seaf_obj_store_obj_exists (seaf->fs_mgr->obj_store,
                                        priv->store_id, priv->repo_version,
                                        obj_id))
        {
            priv->needed_objs = g_list_prepend (priv->needed_objs, obj_id);
            ++(priv->n_needed);
            ++(priv->total_needed);
        } else
            g_free (obj_id);
        p += 40;
    }

    g_free (priv->recv_objs);
    priv->recv_objs = NULL;

    return data;
}

static void
process_object_list_done (void *data)
{
    CcnetProcessor *processor = data;
    USE_PRIV;

    if (priv->n_needed == 0) {
        ccnet_processor_send_response (processor,
                                       SC_OBJ_LIST_SEG, SS_OBJ_LIST_SEG,
                                       NULL, 0);
        return;
    }

    char *buf = g_malloc (priv->n_needed * 40);
    char *p;
    char *obj_id;
    GList *ptr;

    p = buf;
    for (ptr = priv->needed_objs; ptr; ptr = ptr->next) {
        obj_id = ptr->data;
        memcpy (p, obj_id, 40);
        p += 40;
    }

    ccnet_processor_send_response (processor,
                                   SC_OBJ_LIST_SEG, SS_OBJ_LIST_SEG,
                                   buf, priv->n_needed * 40);
    g_free (buf);
    string_list_free (priv->needed_objs);
    priv->needed_objs = NULL;
    priv->n_needed = 0;
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    USE_PRIV;

    switch (processor->state) {
    case CHECK_OBJECT_LIST:
        if (strncmp (code, SC_OBJ_LIST_SEG, 3) == 0) {
            if (clen % 40 != 0) {
                seaf_warning ("Invalid object list segment length %d.\n", clen);
                ccnet_processor_send_response (processor,
                                               SC_SHUTDOWN, SS_SHUTDOWN,
                                               NULL, 0);
                ccnet_processor_done (processor, FALSE);
                return;
            }

            priv->recv_objs = g_memdup(content, clen);
            priv->recv_len = clen;
            ccnet_processor_thread_create (processor, seaf->job_mgr,
                                           process_object_list,
                                           process_object_list_done,
                                           processor);
        } else if (strncmp (code, SC_OBJ_LIST_SEG_END, 3) == 0) {
            if (priv->total_needed == 0) {
                seaf_debug ("No objects are needed. Done.\n");
                ccnet_processor_send_response (processor, SC_END, SS_END, NULL, 0);
                ccnet_processor_done (processor, TRUE);
                return;
            }
            processor->state = RECV_OBJECTS;
        } else if (strncmp (code, SC_END, 3) == 0) {
            /* The client finds nothing to upload. */
            ccnet_processor_done (processor, TRUE);
        } else {
            seaf_warning ("Bad update: %s %s\n", code, code_msg);
            ccnet_processor_send_response (processor,
                                           SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                           NULL, 0);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    case RECV_OBJECTS:
        if (strncmp(code, SC_OBJ_SEG, 3) == 0) {
            recv_fs_object_seg (processor, content, clen);
        } else if (strncmp(code, SC_OBJ_SEG_END, 3) == 0) {
            recv_fs_object_seg (processor, content, clen);
            process_fs_object_seg (processor);
        } else if (strncmp(code, SC_OBJECT, 3) == 0) {
            recv_fs_object (processor, content, clen);
        } else {
            seaf_warning ("Bad update: %s %s\n", code, code_msg);
            ccnet_processor_send_response (processor,
                                           SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                           NULL, 0);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    default:
        g_return_if_reached ();
    }
}
