/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <ccnet.h>
#include "utils.h"
#include "seaf-utils.h"

#include "seafile-session.h"
#include "getca-proc.h"

/*
              seafile-putca <repo_id> <token>
  INIT      -------------------------->
                 OK
            <-------------------------

  REQUEST_SENT
               commit id list
            -------------------------->
               common ancestor id
            <--------------------------
 */

#define SC_ID_LIST "301"
#define SS_ID_LIST "Commit id list"
#define SC_ID_LIST_END "302"
#define SS_ID_LIST_END "Commit id list end"
#define SC_CA "303"
#define SS_CA "Common ancestor"

#define SC_ACCESS_DENIED "401"
#define SS_ACCESS_DENIED "Access denied"
#define SC_NO_CA "404"
#define SS_NO_CA "No common ancestor found"

enum {
    INIT,
    REQUEST_SENT,
};

typedef struct {
    char repo_id[41];
    char last_uploaded[41];
    char last_checkout[41];
    GList *commits;
    gboolean success;
} SeafileGetcaProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_GETCA_PROC, SeafileGetcaProcPriv))

#define USE_PRIV \
    SeafileGetcaProcPriv *priv = GET_PRIV(processor);

static int get_ca_start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

G_DEFINE_TYPE (SeafileGetcaProc, seafile_getca_proc, CCNET_TYPE_PROCESSOR)

static void
release_resource (CcnetProcessor *processor)
{
    USE_PRIV;

    if (priv->commits)
        string_list_free (priv->commits);

    CCNET_PROCESSOR_CLASS (seafile_getca_proc_parent_class)->release_resource (processor);
}

static void
seafile_getca_proc_class_init (SeafileGetcaProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "getca-proc";
    proc_class->start = get_ca_start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof(SeafileGetcaProcPriv));
}

static void
seafile_getca_proc_init (SeafileGetcaProc *processor)
{
}

static int
get_ca_start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;

    GString *buf = g_string_new (NULL);

    if (argc < 2) {
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    memcpy (priv->repo_id, argv[0], 36);

    g_string_printf (buf, "remote %s seafile-putca %s %s",
                     processor->peer_id, argv[0], argv[1]);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

static gboolean
traverse_commits_cb (SeafCommit *commit, void *data, gboolean *stop)
{
    CcnetProcessor *processor = data;
    USE_PRIV;

    /* Add commit id to list, including last_uploaded and last checkout,
     * because they can also be the common ancestor.
     */
    priv->commits = g_list_prepend (priv->commits, g_strdup(commit->commit_id));

    if (strcmp (commit->commit_id, priv->last_uploaded) == 0 ||
        strcmp (commit->commit_id, priv->last_checkout) == 0) {
        *stop = TRUE;
        return TRUE;
    }

    return TRUE;
}

static void *
list_commits_thread (void *data)
{
    CcnetProcessor *processor = data;
    USE_PRIV;
    char *last_uploaded, *last_checkout;
    SeafRepo *repo;

    last_uploaded = seaf_repo_manager_get_repo_property (seaf->repo_mgr,
                                                         priv->repo_id,
                                                         REPO_LOCAL_HEAD);
    if (!last_uploaded) {
        seaf_warning ("Last uploaded commit id is not found in db.\n");
        priv->success = FALSE;
        return data;
    }
    memcpy (priv->last_uploaded, last_uploaded, 40);
    g_free (last_uploaded);

    last_checkout = seaf_repo_manager_get_repo_property (seaf->repo_mgr,
                                                         priv->repo_id,
                                                         REPO_REMOTE_HEAD);
    if (!last_checkout) {
        seaf_warning ("Last checkout commit id is not found in db.\n");
        priv->success = FALSE;
        return data;
    }
    memcpy (priv->last_checkout, last_checkout, 40);
    g_free (last_checkout);

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, priv->repo_id);
    if (!repo) {
        seaf_warning ("Failed to find repo %s.\n", priv->repo_id);
        priv->success = FALSE;
        return data;
    }

    /* Since we don't download all commits, some commits may be missing.
     * But those missing commits (and their ancestors) can't be the common ancestor.
     */
    priv->success = 
        seaf_commit_manager_traverse_commit_tree_truncated (seaf->commit_mgr,
                                                            repo->id,
                                                            repo->version,
                                                            repo->head->commit_id,
                                                            traverse_commits_cb,
                                                            processor, FALSE);
    return data;
}

#define MAX_BUFFER_IDS 500

static void
list_commits_done (void *vdata)
{
    CcnetProcessor *processor = vdata;
    USE_PRIV;
    GString *buf;

    if (!priv->success) {
        ccnet_processor_done (processor, FALSE);
        return;
    }

    buf = g_string_new ("");
    GList *ptr;
    char *id;
    int n = 0;

    priv->commits = g_list_reverse (priv->commits);
    for (ptr = priv->commits; ptr; ptr = ptr->next) {
        id = ptr->data;
        g_string_append (buf, id);
        ++n;

        if (n == MAX_BUFFER_IDS) {
            seaf_debug ("Sending %d commit ids.\n", n);
            ccnet_processor_send_update (processor, SC_ID_LIST, SS_ID_LIST,
                                         buf->str, buf->len + 1);
            n = 0;
            g_string_free (buf, TRUE);
            buf = g_string_new ("");
        }
    }

    if (n != 0) {
        seaf_debug ("Sending %d commit ids.\n", n);
        ccnet_processor_send_update (processor, SC_ID_LIST, SS_ID_LIST,
                                     buf->str, buf->len + 1);
    }

    ccnet_processor_send_update (processor, SC_ID_LIST_END, SS_ID_LIST_END,
                                 NULL, 0);

    g_string_free (buf, TRUE);

    string_list_free (priv->commits);
    priv->commits = NULL;

    processor->state = REQUEST_SENT;
}

static void
send_commit_id_list (CcnetProcessor *processor)
{
    ccnet_processor_thread_create (processor, seaf->job_mgr,
                                   list_commits_thread, list_commits_done,
                                   processor);
}

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileGetcaProc *proc = (SeafileGetcaProc *)processor;
    USE_PRIV;

    switch (processor->state) {
    case INIT:
        if (strncmp(code, SC_OK, 3) == 0) {
            send_commit_id_list (processor);
            return;
        } else if (strncmp (code, SC_ACCESS_DENIED, 3) == 0) {
            seaf_warning ("Access denied to repo %.8s.\n", priv->repo_id);
            processor->failure = GETCA_PROC_ACCESS_DENIED;
            ccnet_processor_done (processor, FALSE);
            return;
        }
        break;
    case REQUEST_SENT:
        if (strncmp (code, SC_CA, 3) == 0) {
            if (clen != 41) {
                seaf_warning ("Bad common ancestor id len %d.\n", clen);
                ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                             NULL, 0);
                ccnet_processor_done (processor, FALSE);
            }
            memcpy (proc->ca_id, content, 40);
            ccnet_processor_done (processor, TRUE);
            return;
        } else if (strncmp (code, SC_NO_CA, 3) == 0) {
            seaf_warning ("No common ancestor found for repo %.8s.\n", priv->repo_id);
            processor->failure = GETCA_PROC_NO_CA;
            ccnet_processor_done (processor, FALSE);
            return;
        }
        break;
    default:
        g_return_if_reached ();
    }

    g_warning ("Bad response: %s %s.\n", code, code_msg);
    ccnet_processor_done (processor, FALSE);
}
