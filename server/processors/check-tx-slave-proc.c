/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <string.h>
#include <ccnet.h>
#include <stdlib.h>

#include <ccnet.h>
#include <ccnet/job-mgr.h>
#include <ccnet/ccnet-object.h>

#include "seafile-session.h"
#include "check-tx-slave-proc.h"

#include "log.h"

#define SC_GET_TOKEN        "301"
#define SS_GET_TOKEN        "Get token"
#define SC_PUT_TOKEN        "302"
#define SS_PUT_TOKEN        "Put token"
#define SC_GET_VERSION      "303"
#define SS_GET_VERSION      "Get version"
#define SC_VERSION          "304"
#define SS_VERSION          "Version"

#define SC_ACCESS_DENIED    "401"
#define SS_ACCESS_DENIED    "Access denied"
#define SC_SERVER_ERROR     "404"
#define SS_SERVER_ERROR     "Internal server error"
#define SC_PROTOCOL_MISMATCH "405"
#define SS_PROTOCOL_MISMATCH "Protocol version mismatch"

/* Only for upload */
#define SC_QUOTA_ERROR      "402"
#define SS_QUOTA_ERROR      "Failed to get quota"
#define SC_QUOTA_FULL       "403"
#define SS_QUOTA_FULL       "storage for the repo's owner is full"

/* Only for download */
#define SC_BAD_REPO         "406"
#define SS_BAD_REPO         "Repo doesn't exist"
#define SC_NO_BRANCH        "407"
#define SS_NO_BRANCH        "Branch not found"

enum {
    INIT,
    ACCESS_GRANTED,
};

enum {
    CHECK_TX_TYPE_UPLOAD,
    CHECK_TX_TYPE_DOWNLOAD,
};

typedef struct {
    int type;

    char repo_id[37];
    char *branch_name;
    char *email;

    char *rsp_code;
    char *rsp_msg;
    char head_id[41];
    int has_branch;
} SeafileCheckTxSlaveProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_CHECK_TX_SLAVE_PROC, SeafileCheckTxSlaveProcPriv))

#define USE_PRIV \
    SeafileCheckTxSlaveProcPriv *priv = GET_PRIV(processor);

G_DEFINE_TYPE (SeafileCheckTxSlaveProc, seafile_check_tx_slave_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);
static void thread_done (void *result);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    /* g_free works fine even if ptr is NULL. */
    g_free (priv->email);
    g_free (priv->branch_name);
    g_free (priv->rsp_code);
    g_free (priv->rsp_msg);

    CCNET_PROCESSOR_CLASS (seafile_check_tx_slave_proc_parent_class)->release_resource (processor);
}


static void
seafile_check_tx_slave_proc_class_init (SeafileCheckTxSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "check-tx-slave-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileCheckTxSlaveProcPriv));
}

static void
seafile_check_tx_slave_proc_init (SeafileCheckTxSlaveProc *processor)
{
}

#include "check-quota-common.h"

static void
get_branch_head (CcnetProcessor *processor)
{
    SeafBranch *branch;
    USE_PRIV;

    branch = seaf_branch_manager_get_branch (seaf->branch_mgr, 
                                             priv->repo_id, priv->branch_name);
    if (branch != NULL) {
        priv->has_branch = 1;
        memcpy (priv->head_id, branch->commit_id, 41);
        seaf_branch_unref (branch);

        priv->rsp_code = g_strdup(SC_OK);
        priv->rsp_msg = g_strdup(SS_OK);
    } else if (priv->type == CHECK_TX_TYPE_UPLOAD) {
        priv->rsp_code = g_strdup(SC_OK);
        priv->rsp_msg = g_strdup(SS_OK);
    } else {
        priv->rsp_code = g_strdup(SC_NO_BRANCH);
        priv->rsp_msg = g_strdup(SS_NO_BRANCH);
    }
}

static gboolean
check_repo_share_permission (SearpcClient *rpc_client,
                             const char *repo_id,
                             const char *user_name)
{
    GList *groups, *pgroup;
    GList *repos, *prepo;
    CcnetGroup *group;
    int group_id;
    char *shared_repo_id;
    gboolean ret = FALSE;

    if (seaf_share_manager_check_permission (seaf->share_mgr,
                                             repo_id,
                                             user_name) != NULL)
        return TRUE;

    groups = ccnet_get_groups_by_user (rpc_client, user_name);
    for (pgroup = groups; pgroup != NULL; pgroup = pgroup->next) {
        group = pgroup->data;
        g_object_get (group, "id", &group_id, NULL);

        repos = seaf_repo_manager_get_group_repoids (seaf->repo_mgr,
                                                     group_id, NULL);
        for (prepo = repos; prepo != NULL; prepo = prepo->next) {
            shared_repo_id = prepo->data;
            if (strcmp (shared_repo_id, repo_id) == 0) {
                ret = TRUE;
                break;
            }
        }
        for (prepo = repos; prepo != NULL; prepo = prepo->next)
            g_free (prepo->data);
        g_list_free (repos);
        if (ret)
            break;
    }

    for (pgroup = groups; pgroup != NULL; pgroup = pgroup->next)
        g_object_unref ((GObject *)pgroup->data);
    g_list_free (groups);
    return ret;
}

static void *
check_tx (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;

    char *owner = NULL;
    int org_id;
    SearpcClient *rpc_client = NULL;

    char *repo_id = priv->repo_id;

    rpc_client = create_sync_ccnetrpc_client
        (seaf->session->central_config_dir, seaf->session->config_dir, "ccnet-threaded-rpcserver");

    if (!rpc_client) {
        priv->rsp_code = g_strdup(SC_SERVER_ERROR);
        priv->rsp_msg = g_strdup(SS_SERVER_ERROR);
        goto out;
    }

    if (!seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id)) {
        priv->rsp_code = g_strdup(SC_BAD_REPO);
        priv->rsp_msg = g_strdup(SS_BAD_REPO);
        goto out;
    }

    if (priv->type == CHECK_TX_TYPE_UPLOAD &&
        check_repo_owner_quota (processor, rpc_client, repo_id) < 0)
        goto out;
    
    owner = seaf_repo_manager_get_repo_owner (seaf->repo_mgr, repo_id);
    if (owner != NULL) {
        /* If the user is not owner, check share permission */
        if (strcmp (owner, priv->email) != 0) {
            if(!check_repo_share_permission (rpc_client, repo_id, priv->email)) {
                priv->rsp_code = g_strdup(SC_ACCESS_DENIED);
                priv->rsp_msg = g_strdup(SS_ACCESS_DENIED);
                goto out;
            }
        }
    } else {
        /* This should be a repo created in an org. */
        org_id = seaf_repo_manager_get_repo_org (seaf->repo_mgr, repo_id);
        if (org_id < 0 ||
            !ccnet_org_user_exists (rpc_client, org_id, priv->email)) {
            priv->rsp_code = g_strdup(SC_ACCESS_DENIED);
            priv->rsp_msg = g_strdup(SS_ACCESS_DENIED);
            goto out;
        }
    }
    
    get_branch_head (processor);

out:
    g_free (owner);
    if (rpc_client)
        free_sync_rpc_client (rpc_client);
    return vprocessor;
}

static void 
thread_done (void *result)
{
    CcnetProcessor *processor = result;
    USE_PRIV;

    if (strcmp (priv->rsp_code, SC_OK) == 0) {
        if (priv->has_branch) {
            ccnet_processor_send_response (processor, 
                                           SC_OK, SS_OK, 
                                           priv->head_id, 41);
        } else
            ccnet_processor_send_response (processor, SC_OK, SS_OK, NULL, 0);
        processor->state = ACCESS_GRANTED;
    } else {
        ccnet_processor_send_response (processor,
                                       priv->rsp_code, priv->rsp_msg,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }
}

static void
get_email_cb (void *result, void *data, GError *error)
{
    char *email = result;
    CcnetProcessor *processor = data;
    USE_PRIV;

    if (!email) {
        seaf_warning ("[check tx] cannot find email for peer %s.\n",
                   processor->peer_id);
        ccnet_processor_send_response (processor, 
                                       SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    priv->email = g_strdup(email);

    ccnet_processor_thread_create (processor, check_tx, thread_done, processor);
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char *repo_id, *branch_name;
    USE_PRIV;

    if (argc < 4) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (strcmp (argv[0], "upload") == 0) {
        priv->type = CHECK_TX_TYPE_UPLOAD;
    } else if (strcmp (argv[0], "download") == 0) {
        priv->type = CHECK_TX_TYPE_DOWNLOAD;
    } else {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    repo_id = argv[2];
    branch_name = argv[3];

    if (strlen(repo_id) != 36) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    if (priv->type == CHECK_TX_TYPE_UPLOAD &&
        strcmp (branch_name, "master") != 0) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    memcpy (priv->repo_id, repo_id, 37);
    priv->branch_name = g_strdup(branch_name);

    ccnet_get_binding_email_async (seaf->async_ccnetrpc_client_t, processor->peer_id,
                                   get_email_cb, processor);

    return 0;
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    USE_PRIV;
    char *token;

    if (processor->state != ACCESS_GRANTED) {
        ccnet_processor_send_response (processor,
                                       SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    if (strncmp (code, SC_GET_TOKEN, 3) == 0) {
        token = seaf_token_manager_generate_token (seaf->token_mgr,
                                                   processor->peer_id,
                                                   priv->repo_id);
        ccnet_processor_send_response (processor,
                                       SC_PUT_TOKEN, SS_PUT_TOKEN,
                                       token, strlen(token) + 1);
        g_free (token);
        return;
    } else if (strncmp (code, SC_GET_VERSION, 3) == 0) {
        char buf[16];
        int len;
        len = snprintf (buf, sizeof(buf), "%d", CURRENT_PROTO_VERSION);
        ccnet_processor_send_response (processor,
                                       SC_VERSION, SS_VERSION,
                                       buf, len + 1);
        ccnet_processor_done (processor, TRUE);
        return;
    }

    ccnet_processor_send_response (processor,
                                   SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                   NULL, 0);
    ccnet_processor_done (processor, FALSE);
}
