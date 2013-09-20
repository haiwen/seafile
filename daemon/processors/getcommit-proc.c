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

#include <ccnet.h>
#include "net.h"
#include "utils.h"
#include "seaf-utils.h"

#include "seafile-session.h"
#include "repo-mgr.h"
#include "commit-mgr.h"
#include "getcommit-proc.h"
#include "processors/objecttx-common.h"


/*
              seafile-putcommit <HEAD>
  RECV_IDS   -------------------------->
                 Object IDs
  RECV_IDS  <--------------------------
                 End
  RECV_IDS  <--------------------------

                 Get Object
  FETCH_OBJ  ------------------------->
                  Object
  FETCH_OBJ <-------------------------

                   ...

                    End
  FETCH_OBJ  -------------------------->
 */

enum {
    INIT,
    RECV_IDS,
    FETCH_OBJECT
};


typedef struct  {
    char        object_path[SEAF_PATH_MAX];
    char        tmp_object_path[SEAF_PATH_MAX];
    char        buf[4096];
    char       *bufptr;
    int         pending_objects;
} SeafileGetcommitProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_GETCOMMIT_PROC, SeafileGetcommitProcPriv))

#define USE_PRIV \
    SeafileGetcommitProcPriv *priv = GET_PRIV(processor);

static int get_commit_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

G_DEFINE_TYPE (SeafileGetcommitProc, seafile_getcommit_proc, CCNET_TYPE_PROCESSOR)


static void
seafile_getcommit_proc_class_init (SeafileGetcommitProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "getcommit-proc";
    proc_class->start = get_commit_start;
    proc_class->handle_response = handle_response;

    g_type_class_add_private (klass, sizeof (SeafileGetcommitProcPriv));
}

static void
seafile_getcommit_proc_init (SeafileGetcommitProc *processor)
{
}


static int
get_commit_start (CcnetProcessor *processor, int argc, char **argv)
{
    GString *buf = g_string_new (NULL);
    TransferTask *task = ((SeafileGetcommitProc *)processor)->tx_task;

    if (task->session_token)
        g_string_printf (buf, "remote %s seafile-putcommit %s %s",
                         processor->peer_id, task->head, task->session_token);
    else
        g_string_printf (buf, "remote %s seafile-putcommit %s",
                         processor->peer_id, task->head);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}


inline static void
request_object_batch_begin (SeafileGetcommitProcPriv *priv)
{
    priv->bufptr = priv->buf;
}

inline static void
request_object_batch (SeafileGetcommitProcPriv *priv, const char *id)
{
    memcpy (priv->bufptr, id, 40);
    priv->bufptr += 40;
    *priv->bufptr = '\n';
    priv->bufptr++;

    ++priv->pending_objects;
}

inline static void
request_object_batch_flush (CcnetProcessor *processor,
                            SeafileGetcommitProcPriv *priv)
{
    if (priv->bufptr == priv->buf)
        return;
    *priv->bufptr = '\0';       /* add ending '\0' */
    priv->bufptr++;
    ccnet_processor_send_update (processor, SC_GET_OBJECT, SS_GET_OBJECT,
                                   priv->buf, priv->bufptr - priv->buf);
    g_debug ("[getcommit] Request more objects:\n%s", priv->buf);
}

static void
check_commit (CcnetProcessor *processor, const char *commit_id)
{
    USE_PRIV;

    if (!seaf_commit_manager_commit_exists (seaf->commit_mgr, commit_id)) {
        request_object_batch (priv, commit_id);
    }
}

static int
save_commit (ObjectPack *pack, int len)
{
    return seaf_obj_store_write_obj (seaf->commit_mgr->obj_store,
                                     pack->id,
                                     pack->object,
                                     len - 41);
}

static void
receive_commit (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;
    ObjectPack *pack = (ObjectPack *)content;

    if (clen < sizeof(ObjectPack)) {
        g_warning ("[getcommit] invalid object id.\n");
        goto bad;
    }

    g_debug ("[getcommit] recv commit object %s\n", pack->id);
    --priv->pending_objects;

    if (save_commit (pack, clen) < 0) {
        goto bad;
    }

    if (priv->pending_objects == 0) {
        g_debug ("[getcommit] Receive commit completed.\n");
        ccnet_processor_send_update (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
    }

    return;

bad:
    ccnet_processor_send_update (processor, SC_BAD_OBJECT,
                                   SS_BAD_OBJECT, NULL, 0);
    g_warning ("[getcommit] Bad commit object received.\n");
    transfer_task_set_error (((SeafileGetcommitProc *)processor)->tx_task,
                             TASK_ERR_DOWNLOAD_COMMIT);
    ccnet_processor_done (processor, FALSE);
}


static void
process_commit_list (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;
    char *object_id;
    int n_objects;
    int i;

    if (clen % 41 != 1 || content[clen-1] != '\0') {
        g_warning ("[getcommit] Bad commit id list.\n");
        ccnet_processor_send_update (processor, SC_BAD_OL, SS_BAD_OL, NULL, 0);
        transfer_task_set_error (((SeafileGetcommitProc *)processor)->tx_task,
                                 TASK_ERR_DOWNLOAD_COMMIT);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    n_objects = clen/41;

    request_object_batch_begin(priv);

    object_id = content;
    for (i = 0; i < n_objects; ++i) {
        object_id[40] = '\0';
        check_commit (processor, object_id);
        object_id += 41;
    }
    
    request_object_batch_flush (processor, priv);

    if (priv->pending_objects == 0) {
        ccnet_processor_send_update (processor, SC_END, SS_END, NULL, 0);
        ccnet_processor_done (processor, TRUE);
    }
}


static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileGetcommitProc *proc = (SeafileGetcommitProc *)processor;
    if (proc->tx_task->state != TASK_STATE_NORMAL) {
        /* TODO: not tested yet */
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                     NULL, 0);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    switch (processor->state) {
    case INIT:
        if (strncmp(code, SC_OK, 3) == 0) {
            processor->state = RECV_IDS;
        } else {
            g_warning ("[getcommit] Bad response: %s %s\n", code, code_msg);
            transfer_task_set_error (proc->tx_task,
                                     TASK_ERR_DOWNLOAD_COMMIT);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    case RECV_IDS:
        if (strncmp(code, SC_COMMIT_IDS, 3) == 0) {
            /* add to inspect queue */
            process_commit_list (processor, content, clen);
        } else if (strncmp(code, SC_END, 3) == 0) {
            /* change state to FETCH_OBJECT */
            processor->state = FETCH_OBJECT;
        } else {
            g_warning ("[getcommit] Bad response: %s %s\n", code, code_msg);
            transfer_task_set_error (proc->tx_task,
                                      TASK_ERR_DOWNLOAD_COMMIT);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    case FETCH_OBJECT:
        if (strncmp(code, SC_OBJECT, 3) == 0) {
            receive_commit (processor, content, clen);
        } else {
            g_warning ("[getcommit] Bad response: %s %s\n", code, code_msg);
            /* Transfer the task state to error when an error ocurred */
            transfer_task_set_error (proc->tx_task,
                                     TASK_ERR_DOWNLOAD_COMMIT);
            ccnet_processor_done (processor, FALSE);
        }
        break;
    default:
        g_return_if_reached ();
    }
}
