/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>

#include <ccnet.h>
#include "utils.h"
#include "seaf-utils.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "fs-mgr.h"
#include "processors/objecttx-common.h"
#include "getfs-proc.h"
#include "transfer-mgr.h"

#define CHECK_INTERVAL 100      /* 100ms */
#define MAX_NUM_BATCH  64
#define MAX_NUM_UNREVD     256

enum {
    REQUEST_SENT,
    FETCH_OBJECT
};

typedef struct  {
    GQueue *inspect_queue;      /* objects to check exists */
    int pending_objects;
    char root_id[41];
    char buf[4096];
    char *bufptr;
    int  n_batch;
    GHashTable  *fs_objects;

    char *obj_seg;
    int  obj_seg_len;
} SeafileGetfsProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_GETFS_PROC, SeafileGetfsProcPriv))

#define USE_PRIV \
    SeafileGetfsProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafileGetfsProc, seafile_getfs_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;
    g_queue_free (priv->inspect_queue);
    g_hash_table_destroy (priv->fs_objects);
    g_free (priv->obj_seg);

    CCNET_PROCESSOR_CLASS (seafile_getfs_proc_parent_class)->release_resource (processor);
}

static void
seafile_getfs_proc_class_init (SeafileGetfsProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "getfs-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileGetfsProcPriv));
}

static void
seafile_getfs_proc_init (SeafileGetfsProc *processor)
{
}

inline static void
request_object_batch_begin (SeafileGetfsProcPriv *priv)
{
    priv->bufptr = priv->buf;
    priv->n_batch = 0;
}

inline static void
request_object_batch_flush (CcnetProcessor *processor,
                            SeafileGetfsProcPriv *priv)
{
    if (priv->bufptr == priv->buf)
        return;
    *priv->bufptr = '\0';       /* add ending '\0' */
    priv->bufptr++;

    ccnet_processor_send_update (processor, SC_GET_OBJECT, SS_GET_OBJECT,
                                 priv->buf, priv->bufptr - priv->buf);

    /* Clean state */
    priv->n_batch = 0;
    priv->bufptr = priv->buf;
}

inline static void
request_object_batch (CcnetProcessor *processor, 
                      SeafileGetfsProcPriv *priv,
                      const char *id)
{
    if (g_hash_table_lookup(priv->fs_objects, id))
        return;

    memcpy (priv->bufptr, id, 40);
    priv->bufptr += 40;
    *priv->bufptr = '\n';
    priv->bufptr++;

    g_hash_table_insert (priv->fs_objects, g_strdup(id), (gpointer)1);
    if (++priv->n_batch == MAX_NUM_BATCH)
        request_object_batch_flush (processor, priv);
    ++priv->pending_objects;
}

static void
check_seafdir (CcnetProcessor *processor, SeafDir *dir)
{
    USE_PRIV;
    GList *ptr;
    SeafDirent *dent;

    for (ptr = dir->entries; ptr; ptr = ptr->next) {
        dent = ptr->data;
        if (!seaf_fs_manager_object_exists(seaf->fs_mgr, dent->id)) {
            request_object_batch (processor, priv, dent->id);
            continue;
        }
        if (S_ISDIR(dent->mode)) {
            g_queue_push_tail (priv->inspect_queue, g_strdup(dent->id));
        }
        /* TODO: check seafile object integrity. */
    }
}

static int
check_object (CcnetProcessor *processor)
{
    USE_PRIV;
    char *obj_id;
    SeafDir *dir;
    static int i = 0;

    request_object_batch_begin(priv);

    /* process inspect queue */
    /* Note: All files in a directory must be checked in an iteration,
     * so we may send out more items than REQUEST_THRESHOLD */
    while (g_hash_table_size (priv->fs_objects) < MAX_NUM_UNREVD) {
        obj_id = (char *) g_queue_pop_head (priv->inspect_queue);
        if (obj_id == NULL)
            break;
        if (!seaf_fs_manager_object_exists(seaf->fs_mgr, obj_id)) {
            request_object_batch (processor, priv, obj_id);
        } else {
            dir = seaf_fs_manager_get_seafdir (seaf->fs_mgr, obj_id);
            if (!dir) {
                /* corrupt dir object */
                request_object_batch (processor, priv, obj_id);
            } else {
                check_seafdir(processor, dir);
                seaf_dir_free (dir);
            }
        }
        g_free (obj_id);        /* free the memory */
    }

    request_object_batch_flush (processor, priv);

    /* check end condition */
    if (i%10 == 0)
        seaf_debug ("[getfs] pending objects num: %d\n", priv->pending_objects);
    ++i;

    if (priv->pending_objects == 0 && g_queue_is_empty(priv->inspect_queue)) {
        ccnet_processor_send_update (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return FALSE;
    } else
        return TRUE;
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    TransferTask *task = ((SeafileGetfsProc *)processor)->tx_task;
    GString *buf = g_string_new (NULL);

    if (task->session_token)
        g_string_printf (buf, "remote %s seafile-putfs %s", 
                         processor->peer_id, task->session_token);
    else
        g_string_printf (buf, "remote %s seafile-putfs", 
                         processor->peer_id);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    processor->state = REQUEST_SENT;
    priv->inspect_queue = g_queue_new ();
    priv->fs_objects = g_hash_table_new_full (g_str_hash, g_str_equal,
                                              g_free, NULL);

    return 0;
}

static int
save_fs_object (ObjectPack *pack, int len)
{
    return seaf_obj_store_write_obj (seaf->fs_mgr->obj_store,
                                     pack->id,
                                     pack->object,
                                     len - 41);
}

static int
recv_fs_object (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;
    ObjectPack *pack = (ObjectPack *)content;
    uint32_t type;
    /* TransferTask *task = ((SeafileGetfsProc *)processor)->tx_task; */

    if (clen < sizeof(ObjectPack)) {
        g_warning ("[getfs] invalid object id.\n");
        goto bad;
    }

    --priv->pending_objects;

    type = seaf_metadata_type_from_data(pack->object, clen);
    if (type == SEAF_METADATA_TYPE_DIR) {
        SeafDir *dir;
        dir = seaf_dir_from_data (pack->id, pack->object, clen - 41);
        if (!dir) {
            g_warning ("[getfs] Bad directory object %s.\n", pack->id);
            goto bad;
        }
        g_queue_push_tail (priv->inspect_queue, g_strdup(dir->dir_id));
        seaf_dir_free (dir);
    } else if (type == SEAF_METADATA_TYPE_FILE) {
        /* TODO: check seafile format. */
#if 0
        int ret = seafile_check_data_format (pack->object, clen - 41);
        if (ret < 0) {
            goto bad;
        }
#endif
    } else {
        g_warning ("[getfs] Invalid object type.\n");
        goto bad;
    }

    if (save_fs_object (pack, clen) < 0) {
        goto bad;
    }

    g_hash_table_remove (priv->fs_objects, pack->id);
    return 0;

bad:
    g_warning ("Bad fs object received.\n");
    transfer_task_set_error (((SeafileGetfsProc *)processor)->tx_task,
                             TASK_ERR_DOWNLOAD_FS);
    ccnet_processor_send_update (processor, SC_BAD_OBJECT, SS_BAD_OBJECT,
                                 NULL, 0);
    ccnet_processor_done (processor, FALSE);
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

static void
load_fsroot_list (CcnetProcessor *processor)
{
    USE_PRIV;
    SeafileGetfsProc *proc = (SeafileGetfsProc *) processor;
    ObjectList *ol = proc->tx_task->fs_roots;
    int i;
    int ollen = object_list_length (ol);

    for (i = 0; i < ollen; i++) {
        g_queue_push_tail (priv->inspect_queue,
                           g_strdup(g_ptr_array_index(ol->obj_ids, i)));
    }
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileGetfsProc *proc = (SeafileGetfsProc *)processor;
    TransferTask *task = proc->tx_task;

    switch (processor->state) {
    case REQUEST_SENT:
        if (strncmp(code, SC_OK, 3) == 0) {
            load_fsroot_list (processor);
            processor->timer = ccnet_timer_new (
                (TimerCB)check_object, processor, CHECK_INTERVAL);
            processor->state = FETCH_OBJECT;
            return;
        }
        break;
    case FETCH_OBJECT:
        if (strncmp(code, SC_OBJ_SEG, 3) == 0) {
            recv_fs_object_seg (processor, content, clen);
            return;

        } else if (strncmp(code, SC_OBJ_SEG_END, 3) == 0) {
            recv_fs_object_seg (processor, content, clen);
            process_fs_object_seg (processor);
            return;
            
        } else if (strncmp(code, SC_OBJECT, 3) == 0) {
            recv_fs_object (processor, content, clen);
            return;
        }
        break;
    default:
        g_return_if_reached ();
    }

    g_warning ("Bad response: %s %s.\n", code, code_msg);
    if (memcmp (code, SC_ACCESS_DENIED, 3) == 0)
        transfer_task_set_error (task, TASK_ERR_ACCESS_DENIED);
    ccnet_processor_done (processor, FALSE);
}
