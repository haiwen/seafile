/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include "ccnet.h"
#include "log.h"
#include "seafile-session.h"
#include "repo-mgr.h"

#include "putrepoemailtoken-proc.h"

#define SC_REPO_EMAIL       "300"
#define SS_REPO_EMAIL       "email"
#define SC_REPO_TOKEN       "301"
#define SS_REPO_TOKEN       "token"
#define SC_SERVER_ERROR     "400"
#define SS_SERVER_ERROR     "server error"
#define SC_ACCESS_DENIED    "401"
#define SS_ACCESS_DENIED    "access denied"
#define SC_NO_REPO          "402"
#define SS_NO_REPO          "repo does not exist"

typedef struct  {
    char *repo_id;
    char *email;
    char *token;
    char *rsp_code;
} SeafilePutrepoemailtokenProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_PUTREPOEMAILTOKEN_PROC, SeafilePutrepoemailtokenProcPriv))

#define USE_PRIV \
    SeafilePutrepoemailtokenProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafilePutrepoemailtokenProc, seafile_putrepoemailtoken_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);

static void get_email_cb (void *result, void *data, GError *error);
static void *get_repo_token (void *vprocessor);
static void get_repo_token_done (void *result);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;
    g_free (priv->email);
    g_free (priv->token);

    CCNET_PROCESSOR_CLASS (seafile_putrepoemailtoken_proc_parent_class)->release_resource (processor);
}


static void
seafile_putrepoemailtoken_proc_class_init (SeafilePutrepoemailtokenProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafilePutrepoemailtokenProcPriv));
}

static void
seafile_putrepoemailtoken_proc_init (SeafilePutrepoemailtokenProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;

    if (argc != 1) {
        ccnet_processor_send_response (processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    priv->repo_id = g_strdup(argv[0]);
    ccnet_get_binding_email_async (seaf->async_ccnetrpc_client_t, processor->peer_id,
                                   get_email_cb, processor);

    return 0;
}

static void
get_email_cb (void *result, void *data, GError *error)
{
    char *email = result;
    CcnetProcessor *processor = data;
    USE_PRIV;

    if (!email) {
        ccnet_processor_send_response (processor, 
                                       SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    } else {
        priv->email = g_strdup(email);
        ccnet_processor_thread_create (processor,
                                       get_repo_token,
                                       get_repo_token_done,
                                       processor);
    }
}

static void *
get_repo_token (void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;

    priv->rsp_code = SC_OK;
    if (!seaf_repo_manager_repo_exists (seaf->repo_mgr, priv->repo_id)) {
        priv->rsp_code = SC_NO_REPO;

    } else {
        priv->token = seaf_repo_manager_get_repo_token_nonnull (
            seaf->repo_mgr, priv->repo_id, priv->email);
        
        if (!priv->token)
            priv->rsp_code = SC_SERVER_ERROR;
    }
    
    return vprocessor;
}

static void 
get_repo_token_done (void *result)
{
    CcnetProcessor *processor = result;
    USE_PRIV;

    if (strcmp (priv->rsp_code, SC_NO_REPO) == 0) {
        ccnet_processor_send_response (processor, SC_NO_REPO,
                                       SS_NO_REPO, NULL, 0);
        ccnet_processor_done (processor, FALSE);

    } else if (strcmp (priv->rsp_code, SC_SERVER_ERROR) == 0) {
        ccnet_processor_send_response (processor, SC_SERVER_ERROR,
                                       SS_SERVER_ERROR, NULL, 0);
        ccnet_processor_done (processor, FALSE);
    } else {
        ccnet_processor_send_response (processor,
                                       SC_REPO_EMAIL, SS_REPO_EMAIL,
                                       priv->email,
                                       strlen(priv->email) + 1);
    }
}

static void
handle_update (CcnetProcessor *processor,
               char *code, char *code_msg,
               char *content, int clen)
{
    USE_PRIV;
    if (strcmp (code, SC_REPO_TOKEN) == 0) {
        ccnet_processor_send_response (processor,
                                       SC_REPO_TOKEN, SS_REPO_TOKEN,
                                       priv->token,
                                       strlen(priv->token) + 1);
        ccnet_processor_done (processor, TRUE);
    } else {
        seaf_warning ("bad update, %s : %s\n", code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }

}
