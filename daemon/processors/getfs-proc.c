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

/*
 * Implementation Notes:
 *
 * Checking and writing of fs objects are completely asynchronous in this processor.
 * - FS object checking is done by a worker thread.
 * - Writing of received fs objects is done with the async obj-store API.
 *
 * At the beginning, all root object id is put into inspect queue. And then
 * We start a worker thread to check the first object in the inspect queue.
 *
 * After the worker thread is done, we send object requests in the main thread.
 * And then we start a worker to check the next object in the inspect queue.
 *
 * After an object is received and store asynchronously into disk, and if the object
 * is a directory, we put it into the inspect queue. And then we start a worker
 * to check the next object in the inspect queue, if no worker is running.
 * This means only 1 worker can be running at the same time. Because we use thread
 * pool, there will be no performance problem of creating threads.
 *
 * The end condition is checked after:
 * - worker thread is done
 * - an object is written
 * The end condition is
 * - inspect queue is empty, and
 * - no object request is pending, and
 * - no worker is running
 */

#define MAX_NUM_BATCH  64

enum {
    REQUEST_SENT,
    FETCH_OBJECT
};

typedef struct ThreadData {
    gint refcnt;
    CcnetProcessor *processor;
    gboolean is_clone;
    int cmd_pipe;
    uint32_t cevent_id;
    char root_id[41];
    GHashTable  *fs_objects;
    GList *fetch_objs;
    char repo_id[37];
    int repo_version;
} ThreadData;

typedef struct  {
    gboolean worker_checking;
    gboolean worker_started;
    GQueue *inspect_queue;      /* objects to check exists */
    int pending_objects;
    guint32 writer_id;

    /* Used by worker thread */
    int cmd_pipe[2];
    uint32_t cevent_id;
    ThreadData *tdata;

    char buf[4096];
    char *bufptr;
    int  n_batch;

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
thread_data_ref (ThreadData *tdata)
{
    g_atomic_int_inc (&tdata->refcnt);
}

static void
thread_data_unref (ThreadData *tdata)
{
    if (g_atomic_int_dec_and_test (&tdata->refcnt)) {
        if (tdata->fetch_objs)
            string_list_free (tdata->fetch_objs);
        if (tdata->fs_objects)
            g_hash_table_destroy (tdata->fs_objects);
        g_free (tdata);
    }
}

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;
    g_queue_free (priv->inspect_queue);
    g_free (priv->obj_seg);    
    seaf_obj_store_unregister_async_write (seaf->fs_mgr->obj_store, priv->writer_id);

    if (priv->worker_started) {
        /* The worker thread will notice the command pipe has been closed and exits.
         */
        pipeclose (priv->cmd_pipe[1]);
        cevent_manager_unregister (seaf->ev_mgr, priv->cevent_id);
        thread_data_unref (priv->tdata);
    }

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
    memcpy (priv->bufptr, id, 40);
    priv->bufptr += 40;
    *priv->bufptr = '\n';
    priv->bufptr++;

    if (++priv->n_batch == MAX_NUM_BATCH)
        request_object_batch_flush (processor, priv);
    ++priv->pending_objects;
}

/*
 * Recursively check fs tree rooted at @dir_id. This function returns when
 * all non-existent or invalid objects have been put into data->fetch_objs.
 */
static void
check_seafdir (ThreadData *tdata, const char *dir_id)
{
    SeafDir *dir = NULL;
    GList *ptr;
    SeafDirent *dent;

    if (!seaf_fs_manager_object_exists(seaf->fs_mgr,
                                       tdata->repo_id,
                                       tdata->repo_version,
                                       dir_id)) {
        tdata->fetch_objs = g_list_prepend (tdata->fetch_objs, g_strdup(dir_id));
        return;
    }

    dir = seaf_fs_manager_get_seafdir (seaf->fs_mgr,
                                       tdata->repo_id,
                                       tdata->repo_version,
                                       dir_id);
    if (!dir) {
        /* corrupt dir object */
        tdata->fetch_objs = g_list_prepend (tdata->fetch_objs, g_strdup(dir_id));
        return;
    }

    for (ptr = dir->entries; ptr; ptr = ptr->next) {
        dent = ptr->data;

        /* Don't check objects that have been checked before. */
        if (g_hash_table_lookup (tdata->fs_objects, dent->id))
            continue;

        g_hash_table_insert (tdata->fs_objects, g_strdup(dent->id), (gpointer)1);

        if (!seaf_fs_manager_object_exists(seaf->fs_mgr,
                                           tdata->repo_id,
                                           tdata->repo_version,
                                           dent->id)) {
            tdata->fetch_objs = g_list_prepend (tdata->fetch_objs, g_strdup(dent->id));
            continue;
        }

        if (S_ISDIR(dent->mode)) {
            check_seafdir (tdata, dent->id);
        } else if (S_ISREG (dent->mode) && tdata->is_clone) {
            /* Only check seafile object integrity when clone.
             * This is for the purpose of recovery.
             * In ordinary sync, checking every file object's integrity would
             * take too much CPU time.
             */
            gboolean ok;
            gboolean err = FALSE;
            ok = seaf_fs_manager_verify_seafile (seaf->fs_mgr,
                                                 tdata->repo_id,
                                                 tdata->repo_version,
                                                 dent->id, TRUE, &err);
            if (!ok && !err) {
                seaf_warning ("File object %.8s is corrupt, recover from server.\n",
                              dent->id);
                tdata->fetch_objs = g_list_prepend (tdata->fetch_objs, g_strdup(dent->id));
            }
        }
    }

    seaf_dir_free (dir);
}

static gboolean
check_end_condition (SeafileGetfsProcPriv *priv)
{
    return (g_queue_get_length (priv->inspect_queue) == 0 &&
            priv->pending_objects == 0 &&
            !priv->worker_checking);
}

static int
check_fs_tree_from (ThreadData *tdata, const char *root_id);

static void
end_or_check_next_dir (CcnetProcessor *processor, SeafileGetfsProcPriv *priv)
{
    if (check_end_condition (priv)) {
        seaf_debug ("Get fs end.\n");
        ccnet_processor_send_update (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    if (priv->worker_checking) {
        return;
    }

    /* Trigger checking the next dir. */
    char *next_dir_id = g_queue_pop_head (priv->inspect_queue);
    if (next_dir_id) {
        if (check_fs_tree_from (priv->tdata, next_dir_id) < 0) {
            transfer_task_set_error (((SeafileGetfsProc *)processor)->tx_task,
                                     TASK_ERR_DOWNLOAD_FS);
            ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN, NULL, 0);
            ccnet_processor_done (processor, FALSE);
        }
        g_free (next_dir_id);
    }
}

static void *
check_objects_thread (void *vdata)
{
    ThreadData *tdata = vdata;
    int cmd;

    /* Hold one reference for worker thread. */
    thread_data_ref (tdata);

    while (1) {
        int n = piperead (tdata->cmd_pipe, &cmd, sizeof(cmd));
        if (n < 0) {
            seaf_warning ("Failed to read commnd pipe: %s.\n", strerror(errno));
            goto out;
        }
        if (n == 0) {
            seaf_message ("Getfs proc is done, worker thread exits.\n");
            goto out;
        }

        check_seafdir (tdata, tdata->root_id);

        cevent_manager_add_event (seaf->ev_mgr, tdata->cevent_id, tdata);
    }

out:
    pipeclose (tdata->cmd_pipe);
    thread_data_unref (tdata);
    return vdata;
}

static void
check_objects_done (CEvent *event, void *unused)
{
    ThreadData *tdata = event->data;
    CcnetProcessor *processor = tdata->processor;
    USE_PRIV;
    GList *ptr;
    char *obj_id;

    priv->worker_checking = FALSE;

    request_object_batch_begin (priv);
    for (ptr = tdata->fetch_objs; ptr; ptr = ptr->next) {
        obj_id = ptr->data;
        request_object_batch (processor, priv, obj_id);
        g_free (obj_id);
    }
    request_object_batch_flush (processor, priv);
    g_list_free (tdata->fetch_objs);
    tdata->fetch_objs = NULL;

    end_or_check_next_dir (processor, priv);
}

static int
check_fs_tree_from (ThreadData *tdata, const char *root_id)
{
    CcnetProcessor *processor = tdata->processor;
    USE_PRIV;

    memcpy (tdata->root_id, root_id, 40);
    tdata->fetch_objs = NULL;

    int cmd = 1;
    pipewrite (priv->cmd_pipe[1], &cmd, sizeof(cmd));

    priv->worker_checking = TRUE;
    return 0;
}

static void
fs_object_write_cb (OSAsyncResult *res, void *data)
{
    CcnetProcessor *processor = data;
    TransferTask *task = ((SeafileGetfsProc *)processor)->tx_task;
    USE_PRIV;

    if (!res->success) {
        seaf_warning ("Failed to write object %.8s.\n", res->obj_id);
        transfer_task_set_error (task, TASK_ERR_DOWNLOAD_FS);
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    seaf_debug ("Written object %.8s.\n", res->obj_id);

    --(priv->pending_objects);

    int type = seaf_metadata_type_from_data (res->obj_id, res->data, res->len,
                                             (task->repo_version > 0));
    if (type == SEAF_METADATA_TYPE_DIR)
        g_queue_push_tail (priv->inspect_queue, g_strdup(res->obj_id));

    end_or_check_next_dir (processor, priv);
}

static int
save_fs_object (SeafileGetfsProcPriv *priv, ObjectPack *pack, int len)
{
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
    USE_PRIV;
    ObjectPack *pack = (ObjectPack *)content;
    /* TransferTask *task = ((SeafileGetfsProc *)processor)->tx_task; */

    if (clen < sizeof(ObjectPack)) {
        g_warning ("[getfs] invalid object id.\n");
        goto bad;
    }

    /* TODO: check fs object integrity. */

    if (save_fs_object (priv, pack, clen) < 0) {
        goto bad;
    }

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

    seaf_debug ("Get obj seg: <id= %40s, offset= %d, lenth= %d>\n",
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

static int
start_worker_thread (CcnetProcessor *processor)
{
    SeafileGetfsProc *proc = (SeafileGetfsProc *)processor;
    USE_PRIV;
    ThreadData *tdata;

    if (ccnet_pipe (priv->cmd_pipe) < 0)
        return -1;
    priv->cevent_id = cevent_manager_register (seaf->ev_mgr,
                                               check_objects_done,
                                               processor);

    tdata = g_new0 (ThreadData, 1);
    tdata->cmd_pipe = priv->cmd_pipe[0];
    tdata->cevent_id = priv->cevent_id;
    tdata->processor = processor;
    tdata->is_clone = proc->tx_task->is_clone;
    tdata->fs_objects = g_hash_table_new_full (g_str_hash, g_str_equal,
                                               g_free, NULL);
    memcpy (tdata->repo_id, proc->tx_task->repo_id, 36);
    tdata->repo_version = proc->tx_task->repo_version;

    /* Hold one reference for the main thread. */
    thread_data_ref (tdata);

    priv->tdata = tdata;

    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    check_objects_thread,
                                    NULL,
                                    tdata);
    priv->worker_started = TRUE;

    return 0;
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

    /* Kick start fs object checking. */
    end_or_check_next_dir (processor, priv);
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
            if (start_worker_thread (processor) < 0) {
                ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                             NULL, 0);
                ccnet_processor_done (processor, FALSE);
                return;
            }
            load_fsroot_list (processor);
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

    priv->writer_id = seaf_obj_store_register_async_write (seaf->fs_mgr->obj_store,
                                                           task->repo_id,
                                                           task->repo_version,
                                                           fs_object_write_cb,
                                                           processor);

    return 0;
}
