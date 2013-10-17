/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, 
 * Boston, MA 02111-1307, USA.
 */

#include "common.h"

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "sendcommit-proc.h"
#include "processors/objecttx-common.h"

/*
              seafile-recvcommit
  INIT      --------------------->
                 200 OK
  INIT     <---------------------
                
                 Object IDs
  SEND_OBJ  ---------------------->
                  End
  SEND_OBJ  ---------------------->

                 Get Object
  SEND_OBJ <-----------------------
                  Object
  SEND_OBJ  ----------------------->

                   ...

                    End
           <-----------------------
 */

enum {
    INIT,
    SEND_OBJECT
};

static int send_commit_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);


G_DEFINE_TYPE (SeafileSendcommitProc, seafile_sendcommit_proc, CCNET_TYPE_PROCESSOR)

static void
seafile_sendcommit_proc_class_init (SeafileSendcommitProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "sendcommit-proc";
    proc_class->start = send_commit_start;
    proc_class->handle_response = handle_response;
}

static void
seafile_sendcommit_proc_init (SeafileSendcommitProc *processor)
{
}

static gboolean
commit_collector (SeafCommit *commit, void *data, gboolean *stop)
{
    ObjectList *ol = data;

    object_list_insert (ol, commit->commit_id);

    return TRUE;
}

static int
send_commit_start (CcnetProcessor *processor, int argc, char **argv)
{
    GString *buf;
    int ret;
    TransferTask *task = ((SeafileSendcommitProc *)processor)->tx_task;
    
    ObjectList *ol = object_list_new ();
    ret = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                    task->head,
                                                    commit_collector,
                                                    ol, FALSE);
    if (ret == FALSE) {
        object_list_free (ol);
        g_warning ("[sendcommit] Load commits error\n");
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
    g_return_val_if_fail (object_list_length(ol) != 0, -1);
    task->commits = ol;

    /* Send to_branch to the relay. */
    buf = g_string_new (NULL);
    g_string_printf (buf, "remote %s seafile-recvcommit %s %s",
                     processor->peer_id, task->to_branch, task->session_token);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    processor->state = INIT;

    return 0;
}

static gboolean
send_commit (CcnetProcessor *processor, char *object_id)
{
    char *data;
    int len;
    ObjectPack *pack = NULL;
    int pack_size;

    if (seaf_obj_store_read_obj (seaf->commit_mgr->obj_store,
                                 object_id, (void**)&data, &len) < 0) {
        g_warning ("Failed to read commit %s.\n", object_id);
        goto fail;
    }

    pack_size = sizeof(ObjectPack) + len;
    pack = malloc (pack_size);
    memcpy (pack->id, object_id, 41);
    memcpy (pack->object, data, len);

    ccnet_processor_send_update (processor, SC_OBJECT, SS_OBJECT,
                                 (char *)pack, pack_size);

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
send_commits (CcnetProcessor *processor, char *content, int clen)
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
        if (send_commit (processor, object_id) == FALSE)
            return;
        object_id += 41;
    }
}

static void
send_commit_ids (CcnetProcessor *processor)
{
    SeafileSendcommitProc *proc = (SeafileSendcommitProc *)processor;
    char buf[2048];
    char *ptr = buf;
    int i, count = 0;
    ObjectList *ol = proc->tx_task->commits;
    int ollen = object_list_length (ol);

    for (i = 0; i < ollen; i++) {
        memcpy (ptr, g_ptr_array_index(ol->obj_ids, i), 40);
        ptr += 40;
        *ptr++ = '\n';

        if (++count == 48) {
            *ptr = '\0';
            ccnet_processor_send_update (processor, SC_COMMIT_IDS, 
                                         SS_COMMIT_IDS, buf, 41 * count + 1);
            ptr = buf;
            count = 0;
        }
    }

    if (count) {
        *ptr = '\0';
        ccnet_processor_send_update (processor, SC_COMMIT_IDS, 
                                     SS_COMMIT_IDS, buf, 41 * count + 1);
    }

    object_list_free (ol);
    ccnet_processor_send_update (processor, SC_END, SS_END, NULL, 0);

    processor->state = SEND_OBJECT;
}

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileSendcommitProc *proc = (SeafileSendcommitProc *)processor;
    TransferTask *task = proc->tx_task;
    if (task->state != TASK_STATE_NORMAL) {
        /* TODO: not tested yet */
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                     NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    switch (processor->state) {
    case INIT:
        if (memcmp (code, SC_OK, 3) == 0)
            send_commit_ids (processor);
        else {
            g_warning ("Bad response: %s %s.\n", code, code_msg);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    case SEND_OBJECT:
        if (strncmp(code, SC_GET_OBJECT, 3) == 0) {
            send_commits (processor, content, clen);
        } else if (strncmp(code, SC_END, 3) == 0) {
            ccnet_processor_done (processor, TRUE);
        } else {
            g_warning ("[sendcommit] Bad response in state SEND_OBJECT: %s %s\n",
                       code, code_msg);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    default:
        g_return_if_reached ();
    }
}
