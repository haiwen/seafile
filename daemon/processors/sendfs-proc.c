/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */


/*
 * file system synchronization algorithm:
 * 
 * Begins with the root directory object,
 *
 *                           seafile-recvfs
 * S(INIT -> SEND_ROOT) --------------------------------->  T
 *                               OK
 * S(SEND_ROOT) <---------------------------  T
 *                    FS_ROOT
 * S(SEND_ROOT) ---------------------------->  T
 *                    OK
 * S(SEND_ROOT) <----------------------------  T
 *                                     FS Root, FS Root End
 * S(SEND_ROOT -> SEND_OBJECT) ---------------------------->  T
 *
 *                      Get Object
 * S(SEND_OBJECT) <----------------------------  T
 *                       Object
 * S(SEND_OBJECT) ---------------------------->  T
 *      .
 *      .
 *      .
 *                           END
 * S(SEND_OBJECT)  <---------------------------  T
 */

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
#include "sendfs-proc.h"

enum {
    INIT,
    SEND_ROOT,
    SEND_OBJECT
};

G_DEFINE_TYPE (SeafileSendfsProc, seafile_sendfs_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */

    CCNET_PROCESSOR_CLASS (seafile_sendfs_proc_parent_class)->release_resource (processor);
}


static void
seafile_sendfs_proc_class_init (SeafileSendfsProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "sendfs-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_sendfs_proc_init (SeafileSendfsProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    GString *buf;
    SeafileSendfsProc *proc = (SeafileSendfsProc *)processor;
    TransferTask *task = proc->tx_task;

    buf = g_string_new (NULL);
    g_string_printf (buf, "remote %s seafile-recvfs %s", 
                     processor->peer_id, task->session_token);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    processor->state = SEND_ROOT;
    proc->last_idx = 0;

    return 0;
}

static gboolean
send_fs_object (CcnetProcessor *processor, char *object_id)
{
    char *data;
    int len;
    ObjectPack *pack = NULL;
    int pack_size;

    if (seaf_obj_store_read_obj (seaf->fs_mgr->obj_store,
                                 object_id, (void**)&data, &len) < 0) {
        g_warning ("Failed to read fs object %s.\n", object_id);
        goto fail;
    }

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

    g_free (data);
    free (pack);
    return TRUE;

fail:
    ccnet_processor_send_update (processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                 object_id, 41);
    ccnet_processor_done (processor, FALSE);
    return FALSE;
}

static void
send_fs_objects (CcnetProcessor *processor, char *content, int clen)
{
    char *object_id;
    int n_objects;
    int i;

    if (clen % 41 != 1 || content[clen-1] != '\0') {
        g_warning ("Bad fs object list.\n");
        ccnet_processor_send_update (processor, SC_BAD_OL, SS_BAD_OL, NULL, 0);
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
send_fs_roots (CcnetProcessor *processor)
{
    SeafileSendfsProc *proc = (SeafileSendfsProc *)processor;
    char buf[2096];
    char *ptr = buf;
    int i, count = 0;
    ObjectList *ol = proc->tx_task->fs_roots;
    int ollen = object_list_length (ol);

    if (proc->last_idx == ollen) {
        ccnet_processor_send_update (processor, SC_ROOT_END, SS_ROOT_END,
                                     NULL, 0);
        processor->state = SEND_OBJECT;
        return;
    }

    for (i = proc->last_idx; i < ollen; i++) {
        memcpy (ptr, g_ptr_array_index(ol->obj_ids, i), 40);
        ptr += 40;
        *ptr++ = '\n';
        
        if (++count == 48)
            break;
    }

    ccnet_processor_send_update (processor, SC_ROOT, SS_ROOT,
                                 buf, 41 * count);
    proc->last_idx = i;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileSendfsProc *proc = (SeafileSendfsProc *)processor;
    TransferTask *task = proc->tx_task;

    switch (processor->state) {
    case SEND_ROOT:
        if (strncmp(code, SC_OK, 3) == 0) {
            send_fs_roots (processor);
            return;
        }
        break;
    case SEND_OBJECT:
        if (strncmp(code, SC_GET_OBJECT, 3) == 0) {
            send_fs_objects (processor, content, clen);
            return;
        } else if (strncmp(code, SC_END, 3) == 0) {
            seaf_debug ("Send fs objects end.\n");
            ccnet_processor_done (processor, TRUE);
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
