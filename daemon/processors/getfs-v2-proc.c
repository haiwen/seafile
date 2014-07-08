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
#include "getfs-v2-proc.h"
#include "seaf-utils.h"

/*
 * putfs-v2-proc server-head-id [client-head-id]
 * ------------------------------>
 * OK
 * <-----------------------------
 *
 * The server uses diff to calculate objects to put
 * 
 * SC_OBJ_LIST_SEG
 * <-----------------------------
 * ......
 * SC_OBJ_LIST_SEG_END
 * <-----------------------------
 *
 * The client calculates the list of objects to get
 * 
 * SC_OBJ_LIST_SEG
 * ----------------------------->
 * ......
 * SC_OBJ
 * <----------------------------
 * ......
 * SC_END
 * ----------------------------->
 *
 * After all objects are written to disk, the client ends the protocol
 */

enum {
    INIT = 0,
    CHECK_OBJECT_LIST,
    GET_OBJECTS,
};

typedef struct  {
    char *obj_seg;
    int obj_seg_len;

    gboolean registered;
    guint32  writer_id;

    /* Used to check object list */
    GList *recv_objs;
    GList *needed_objs;

    int n_pending;
    int n_saved;
} SeafileGetfsProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_GETFS_V2_PROC, SeafileGetfsProcPriv))

#define USE_PRIV \
    SeafileGetfsProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafileGetfsV2Proc, seafile_getfs_v2_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
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

    string_list_free (priv->recv_objs);
    string_list_free (priv->needed_objs);

    CCNET_PROCESSOR_CLASS (seafile_getfs_v2_proc_parent_class)->release_resource (processor);
}

static void
seafile_getfs_v2_proc_class_init (SeafileGetfsV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "getfs-v2-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileGetfsProcPriv));
}

static void
seafile_getfs_v2_proc_init (SeafileGetfsV2Proc *processor)
{
}

static void
on_fs_write (OSAsyncResult *res, void *cb_data);

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    GString *buf;
    SeafileGetfsV2Proc *proc = (SeafileGetfsV2Proc *)processor;
    TransferTask *task = proc->tx_task;

    buf = g_string_new (NULL);
    if (!task->is_clone) {
        SeafBranch *master = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                             task->repo_id,
                                                             "master");
        if (!master) {
            seaf_warning ("Master branch not found for repo %s.\n", task->repo_id);
            g_string_free (buf, TRUE);
            ccnet_processor_done (processor, FALSE);
            return -1;
        }

        g_string_printf (buf, "remote %s seafile-putfs-v2 %s %s %s",
                         processor->peer_id, task->session_token,
                         task->head, master->commit_id);

        seaf_branch_unref (master);
    } else
        g_string_printf (buf, "remote %s seafile-putfs-v2 %s %s",
                         processor->peer_id, task->session_token,
                         task->head);

    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    priv->registered = TRUE;
    priv->writer_id = seaf_obj_store_register_async_write (seaf->fs_mgr->obj_store,
                                                           task->repo_id,
                                                           task->repo_version,
                                                           on_fs_write,
                                                           processor);
    return 0;
}

static void
send_object_list_segment (CcnetProcessor *processor);

static void
on_fs_write (OSAsyncResult *res, void *cb_data)
{
    CcnetProcessor *processor = cb_data;
    USE_PRIV;

    if (!res->success) {
        g_warning ("[getfs] Failed to write %s.\n", res->obj_id);
        ccnet_processor_send_update (processor, SC_BAD_OBJECT, SS_BAD_OBJECT,
                                     NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    seaf_debug ("[getfs] Wrote fs object %s.\n", res->obj_id);

    if (++(priv->n_saved) == priv->n_pending)
        send_object_list_segment (processor);
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
        g_warning ("invalid object id.\n");
        goto bad;
    }

    seaf_debug ("[getfs] Recv fs object %.8s.\n", pack->id);

    /* Check object integrity by parsing it. */
    /* fs_obj = seaf_fs_object_from_data(pack->id, */
    /*                                   pack->object, clen - sizeof(ObjectPack), */
    /*                                   (priv->repo_version > 0)); */
    /* if (!fs_obj) { */
    /*     g_warning ("Bad fs object %s.\n", pack->id); */
    /*     goto bad; */
    /* } */

    /* seaf_fs_object_free (fs_obj); */

    if (save_fs_object (processor, pack, clen) < 0) {
        goto bad;
    }

    return 0;

bad:
    ccnet_processor_send_update (processor, SC_BAD_OBJECT,
                                   SS_BAD_OBJECT, NULL, 0);
    g_warning ("[getfs] Bad fs object received.\n");
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

    seaf_debug ("[getfs] Get obj seg: <id= %40s, offset= %d, lenth= %d>\n",
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
calculate_needed_object_list (void *data)
{
    CcnetProcessor *processor = data;
    USE_PRIV;
    SeafileGetfsV2Proc *proc = (SeafileGetfsV2Proc *)processor;
    TransferTask *task = proc->tx_task;
    GList *ptr;
    char *obj_id;

    for (ptr = priv->recv_objs; ptr; ptr = ptr->next) {
        obj_id = ptr->data;

        if (!seaf_obj_store_obj_exists (seaf->fs_mgr->obj_store,
                                        task->repo_id, task->repo_version,
                                        obj_id))
            priv->needed_objs = g_list_prepend (priv->needed_objs, obj_id);
        else
            g_free (obj_id);
    }

    g_list_free (priv->recv_objs);
    priv->recv_objs = NULL;

    return data;
}

#define OBJECT_LIST_SEGMENT_N 1000
#define OBJECT_LIST_SEGMENT_LEN 40 * 1000

static void
send_object_list_segment (CcnetProcessor *processor)
{
    USE_PRIV;
    char buf[OBJECT_LIST_SEGMENT_LEN];

    if (priv->needed_objs == NULL) {
        seaf_debug ("All objects saved. Done.\n");
        ccnet_processor_send_update (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    priv->n_pending = 0;
    priv->n_saved = 0;

    int i = 0;
    char *p = buf;
    char *obj_id;
    while (priv->needed_objs != NULL) {
        obj_id = priv->needed_objs->data;
        priv->needed_objs = g_list_delete_link (priv->needed_objs,
                                                priv->needed_objs);

        memcpy (p, obj_id, 40);
        p += 40;
        g_free (obj_id);
        if (++i == OBJECT_LIST_SEGMENT_N)
            break;
    }

    if (i > 0) {
        seaf_debug ("Send %d object ids.\n", i);
        priv->n_pending = i;
        ccnet_processor_send_update (processor,
                                     SC_OBJ_LIST_SEG, SS_OBJ_LIST_SEG,
                                     buf, i * 40);
    }
}

static void
calculate_needed_object_list_done (void *data)
{
    CcnetProcessor *processor = data;
    send_object_list_segment (processor);
    processor->state = GET_OBJECTS;
}

static void
process_recv_object_list (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;
    int n, i;
    char *p;
    char *obj_id;

    n = clen/40;
    p = content;

    seaf_debug ("Recv %d object ids.\n", n);

    for (i = 0; i < n; ++i) {
        obj_id = g_strndup (p, 40);
        priv->recv_objs = g_list_prepend (priv->recv_objs, obj_id);
        p += 40;
    }
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    switch (processor->state) {
    case INIT:
        if (strncmp (code, SC_OK, 3) == 0)
            processor->state = CHECK_OBJECT_LIST;
        else {
            seaf_warning ("Bad response: %s %s\n", code, code_msg);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    case CHECK_OBJECT_LIST:
        if (strncmp (code, SC_OBJ_LIST_SEG, 3) == 0) {
            if (clen % 40 != 0) {
                seaf_warning ("Invalid object list segment length %d.\n", clen);
                ccnet_processor_send_update (processor,
                                             SC_SHUTDOWN, SS_SHUTDOWN,
                                             NULL, 0);
                ccnet_processor_done (processor, FALSE);
                return;
            }

            process_recv_object_list (processor, content, clen);

        } else if (strncmp (code, SC_OBJ_LIST_SEG_END, 3) == 0) {

            ccnet_processor_thread_create (processor, seaf->job_mgr,
                                           calculate_needed_object_list,
                                           calculate_needed_object_list_done,
                                           processor);

        } else if (strncmp (code, SC_END, 3) == 0) {
            /* The server finds nothing to put. */
            ccnet_processor_done (processor, TRUE);
        } else {
            seaf_warning ("Bad response: %s %s\n", code, code_msg);
            ccnet_processor_send_update (processor,
                                         SC_BAD_RESPONSE_CODE, SS_BAD_RESPONSE_CODE,
                                         NULL, 0);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    case GET_OBJECTS:
        if (strncmp(code, SC_OBJ_SEG, 3) == 0) {
            recv_fs_object_seg (processor, content, clen);
        } else if (strncmp(code, SC_OBJ_SEG_END, 3) == 0) {
            recv_fs_object_seg (processor, content, clen);
            process_fs_object_seg (processor);
        } else if (strncmp(code, SC_OBJECT, 3) == 0) {
            recv_fs_object (processor, content, clen);
        } else {
            seaf_warning ("Bad response: %s %s\n", code, code_msg);
            ccnet_processor_send_update (processor,
                                           SC_BAD_RESPONSE_CODE, SS_BAD_RESPONSE_CODE,
                                           NULL, 0);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    default:
        g_return_if_reached ();
    }
}
