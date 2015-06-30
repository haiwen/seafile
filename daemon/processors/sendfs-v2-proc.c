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
#include "sendfs-v2-proc.h"

#include "diff-simple.h"

/*
 * recvfs-v2-proc
 * ------------------------------>
 *
 * OK
 * <-----------------------------
 *
 * Calculate send object list
 *
 * SC_OBJ_LIST_SEG
 * ----------------------------->
 * SC_OBJ_LIST_SEG
 * <----------------------------
 * ......
 * SC_OBJ_LIST_SEG_END
 * ----------------------------->
 *
 * SC_OBJ
 * ----------------------------->
 * ......
 * After all objects are saved to disk, the server ends the protocol.
 * SC_END
 * <----------------------------
 */

enum {
    INIT = 0,
    CHECK_OBJECT_LIST,
    SEND_OBJECTS,
};

typedef struct {
    GList *send_obj_list;
    GList *recv_obj_list;

    guint32 reader_id;

    gboolean calc_success;
} SeafileSendfsProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_SENDFS_V2_PROC, SeafileSendfsProcPriv))

#define USE_PRIV \
    SeafileSendfsProcPriv *priv = GET_PRIV(processor);

G_DEFINE_TYPE (SeafileSendfsV2Proc, seafile_sendfs_v2_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    string_list_free (priv->send_obj_list);
    string_list_free (priv->recv_obj_list);

    seaf_obj_store_unregister_async_read (seaf->fs_mgr->obj_store,
                                          priv->reader_id);

    CCNET_PROCESSOR_CLASS (seafile_sendfs_v2_proc_parent_class)->release_resource (processor);
}


static void
seafile_sendfs_v2_proc_class_init (SeafileSendfsV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "sendfs-v2-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof(SeafileSendfsProcPriv));
}

static void
seafile_sendfs_v2_proc_init (SeafileSendfsV2Proc *processor)
{
}

static void
fs_object_read_cb (OSAsyncResult *res, void *data);

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    GString *buf;
    SeafileSendfsV2Proc *proc = (SeafileSendfsV2Proc *)processor;
    TransferTask *task = proc->tx_task;

    buf = g_string_new (NULL);
    g_string_printf (buf, "remote %s seafile-recvfs-v2 %s", 
                     processor->peer_id, task->session_token);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    priv->reader_id = seaf_obj_store_register_async_read (seaf->fs_mgr->obj_store,
                                                          task->repo_id,
                                                          task->repo_version,
                                                          fs_object_read_cb,
                                                          processor);

    return 0;
}

/* Calculate send object list */

typedef struct {
    GList **pret;
    GHashTable *checked_objs;
} CalcData;

inline static gboolean
dirent_same (SeafDirent *denta, SeafDirent *dentb)
{
    return (strcmp (dentb->id, denta->id) == 0 && denta->mode == dentb->mode);
}

static int
collect_file_ids (int n, const char *basedir, SeafDirent *files[], void *vdata)
{
    SeafDirent *file1 = files[0];
    SeafDirent *file2 = files[1];
    CalcData *data = vdata;
    GList **pret = data->pret;
    int dummy;

    if (!file1 || strcmp (file1->id, EMPTY_SHA1) == 0)
        return 0;

    if (g_hash_table_lookup (data->checked_objs, file1->id))
        return 0;

    if (!file2 || !dirent_same (file1, file2)) {
        *pret = g_list_prepend (*pret, g_strdup(file1->id));
        g_hash_table_insert (data->checked_objs, g_strdup(file1->id), &dummy);
    }

    return 0;
}

static int
collect_dir_ids (int n, const char *basedir, SeafDirent *dirs[], void *vdata,
                 gboolean *recurse)
{
    SeafDirent *dir1 = dirs[0];
    SeafDirent *dir2 = dirs[1];
    CalcData *data = vdata;
    GList **pret = data->pret;
    int dummy;

    if (!dir1 || strcmp (dir1->id, EMPTY_SHA1) == 0)
        return 0;

    if (g_hash_table_lookup (data->checked_objs, dir1->id))
        return 0;

    if (!dir2 || !dirent_same (dir1, dir2)) {
        *pret = g_list_prepend (*pret, g_strdup(dir1->id));
        g_hash_table_insert (data->checked_objs, g_strdup(dir1->id), &dummy);
    }

    return 0;
}

static void *
calculate_send_object_list (void *vdata)
{
    CcnetProcessor *processor = vdata;
    USE_PRIV;
    SeafileSendfsV2Proc *proc = (SeafileSendfsV2Proc *)processor;
    TransferTask *task = proc->tx_task;

    SeafBranch *local = NULL, *master = NULL;
    local = seaf_branch_manager_get_branch (seaf->branch_mgr, task->repo_id, "local");
    if (!local) {
        seaf_warning ("Branch local not found for repo %.8s.\n", task->repo_id);
        priv->calc_success = FALSE;
        goto out;
    }
    master = seaf_branch_manager_get_branch (seaf->branch_mgr, task->repo_id, "master");
    if (!master) {
        seaf_warning ("Branch master not found for repo %.8s.\n", task->repo_id);
        priv->calc_success = FALSE;
        goto out;
    }

    SeafCommit *local_head = NULL, *master_head = NULL;
    local_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id, task->repo_version,
                                                 local->commit_id);
    if (!local_head) {
        seaf_warning ("Local head commit not found for repo %.8s.\n",
                      task->repo_id);
        priv->calc_success = FALSE;
        goto out;
    }
    master_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 task->repo_id, task->repo_version,
                                                 master->commit_id);
    if (!master_head) {
        seaf_warning ("Master head commit not found for repo %.8s.\n",
                      task->repo_id);
        priv->calc_success = FALSE;
        goto out;
    }

    /* Diff won't traverse the root object itself. */
    if (strcmp (local_head->root_id, master_head->root_id) != 0 &&
        strcmp (local_head->root_id, EMPTY_SHA1) != 0)
        priv->send_obj_list = g_list_prepend (priv->send_obj_list,
                                              g_strdup(local_head->root_id));

    CalcData *data = g_new0(CalcData, 1);
    data->pret = &priv->send_obj_list;
    data->checked_objs = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, NULL);

    DiffOptions opts;
    memset (&opts, 0, sizeof(opts));
    memcpy (opts.store_id, task->repo_id, 36);
    opts.version = task->repo_version;
    opts.file_cb = collect_file_ids;
    opts.dir_cb = collect_dir_ids;
    opts.data = data;

    const char *trees[2];
    trees[0] = local_head->root_id;
    trees[1] = master_head->root_id;
    if (diff_trees (2, trees, &opts) < 0) {
        seaf_warning ("Failed to diff local and master head for repo %.8s.\n",
                      task->repo_id);
        priv->calc_success = FALSE;
    }

    g_hash_table_destroy (data->checked_objs);
    g_free (data);

    priv->calc_success = TRUE;

out:
    seaf_branch_unref (local);
    seaf_branch_unref (master);
    seaf_commit_unref (local_head);
    seaf_commit_unref (master_head);
    return vdata;
}

static void
send_object_list_segment (CcnetProcessor *processor);

static void
calculate_send_object_list_done (void *vdata)
{
    CcnetProcessor *processor = vdata;
    USE_PRIV;

    if (!priv->calc_success) {
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    if (priv->send_obj_list == NULL) {
        seaf_message ("No fs objects to upload. Done.\n");
        ccnet_processor_send_update (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    send_object_list_segment (processor);
}

/* Check object list. */

#define OBJECT_LIST_SEGMENT_N 1000
#define OBJECT_LIST_SEGMENT_LEN 40 * 1000

static void
send_next_object (CcnetProcessor *processor);

static void
send_object_list_segment (CcnetProcessor *processor)
{
    USE_PRIV;
    char buf[OBJECT_LIST_SEGMENT_LEN];

    if (priv->send_obj_list == NULL) {
        seaf_debug ("Check object list end.\n");

        ccnet_processor_send_update (processor,
                                     SC_OBJ_LIST_SEG_END, SS_OBJ_LIST_SEG_END,
                                     NULL, 0);

        send_next_object (processor);
        processor->state = SEND_OBJECTS;
        return;
    }

    int i = 0;
    char *p = buf;
    char *obj_id;
    while (priv->send_obj_list != NULL) {
        obj_id = priv->send_obj_list->data;
        priv->send_obj_list = g_list_delete_link (priv->send_obj_list,
                                                  priv->send_obj_list);

        memcpy (p, obj_id, 40);
        p += 40;
        g_free (obj_id);
        if (++i == OBJECT_LIST_SEGMENT_N)
            break;
    }

    if (i > 0) {
        seaf_debug ("Send %d object ids.\n", i);
        ccnet_processor_send_update (processor,
                                     SC_OBJ_LIST_SEG, SS_OBJ_LIST_SEG,
                                     buf, i * 40);
    }
}

static void
process_object_list_segment (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;
    int n, i;
    char *p;

    if (clen % 40 != 0) {
        seaf_warning ("Invalid object list segment length %d.\n", clen);
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    n = clen/40;
    p = content;

    seaf_debug ("%d objects are needed by the server.\n", n);

    for (i = 0; i < n; ++i) {
        priv->recv_obj_list = g_list_prepend (priv->recv_obj_list, g_strndup (p, 40));
        p += 40;
    }
}

/* Send objects */

static void
send_fs_object (CcnetProcessor *processor,
                const char *object_id, char *data, int len)
{
    ObjectPack *pack = NULL;
    int pack_size;

    pack_size = sizeof(ObjectPack) + len;
    pack = malloc (pack_size);
    memcpy (pack->id, object_id, 41);
    memcpy (pack->object, data, len);

    if (pack_size <= MAX_OBJ_SEG_SIZE) {
        ccnet_processor_send_update (processor, SC_OBJECT, SS_OBJECT,
                                     (char *)pack, pack_size);
    } else {
        int offset, n;

        offset = 0;
        while (offset < pack_size) {
            n = MIN(pack_size - offset, MAX_OBJ_SEG_SIZE);

            if (offset + n < pack_size) {
                ccnet_processor_send_update (processor,
                                             SC_OBJ_SEG, SS_OBJ_SEG,
                                             (char *)pack + offset, n);
            } else {
                ccnet_processor_send_update (processor,
                                             SC_OBJ_SEG_END, SS_OBJ_SEG_END,
                                             (char *)pack + offset, n);
            }

            seaf_debug ("Sent object %s segment<total = %d, offset = %d, n = %d>\n",
                        object_id, pack_size, offset, n);

            offset += n;
        }
    }

    seaf_debug ("Send fs object %.8s.\n", object_id);

    free (pack);
}

static void
fs_object_read_cb (OSAsyncResult *res, void *data)
{
    CcnetProcessor *processor = data;

    if (!res->success) {
        seaf_warning ("Failed to read fs object %.8s.\n", res->obj_id);
        ccnet_processor_send_update (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                     res->obj_id, 41);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    send_fs_object (processor, res->obj_id, res->data, res->len);

    send_next_object (processor);
}

static void
read_fs_object (CcnetProcessor *processor, const char *obj_id)
{
    USE_PRIV;

    seaf_obj_store_async_read (seaf->fs_mgr->obj_store,
                               priv->reader_id,
                               obj_id);
}

static void
send_next_object (CcnetProcessor *processor)
{
    USE_PRIV;
    char *object_id;

    if (priv->recv_obj_list == NULL) {
        seaf_debug ("Send fs objects end.\n");
        return;
    }

    object_id = priv->recv_obj_list->data;
    priv->recv_obj_list = g_list_delete_link (priv->recv_obj_list,
                                              priv->recv_obj_list);

    read_fs_object (processor, object_id);
    g_free (object_id);
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileSendfsV2Proc *proc = (SeafileSendfsV2Proc *)processor;
    TransferTask *task = proc->tx_task;

    switch (processor->state) {
    case INIT:
        if (strncmp(code, SC_OK, 3) == 0) {
            ccnet_processor_thread_create (processor, seaf->job_mgr,
                                           calculate_send_object_list,
                                           calculate_send_object_list_done,
                                           processor);
            processor->state = CHECK_OBJECT_LIST;
            return;
        }
        break;
    case CHECK_OBJECT_LIST:
        if (strncmp (code, SC_OBJ_LIST_SEG, 3) == 0) {
            process_object_list_segment (processor, content, clen);
            send_object_list_segment (processor);
            return;
        }
        break;
    case SEND_OBJECTS:
        if (strncmp (code, SC_END, 3) == 0) {
            seaf_debug ("All objects received. Done.\n");
            ccnet_processor_done (processor, TRUE);
            return;
        }
        break;
    default:
        g_return_if_reached ();
    }

    seaf_warning ("Bad response: %s %s.\n", code, code_msg);
    if (memcmp (code, SC_ACCESS_DENIED, 3) == 0)
        transfer_task_set_error (task, TASK_ERR_ACCESS_DENIED);
    ccnet_processor_done (processor, FALSE);
}
