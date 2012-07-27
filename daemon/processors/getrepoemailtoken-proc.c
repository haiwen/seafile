/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include "ccnet/processor.h"
#include "log.h"
#include "seafile-session.h"
#include "repo-mgr.h"

#include "getrepoemailtoken-proc.h"

typedef struct {
    char *repo_id;
    char *email;
    char *token;

} SeafileGetrepoemailtokenProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_GETREPOEMAILTOKEN_PROC, SeafileGetrepoemailtokenProcPriv))

#define USE_PRIV \
    SeafileGetrepoemailtokenProcPriv *priv = GET_PRIV(processor);


G_DEFINE_TYPE (SeafileGetrepoemailtokenProc, seafile_getrepoemailtoken_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    /* FILL IT */
    USE_PRIV;
    g_free (priv->repo_id);
    g_free (priv->email);
    g_free (priv->token);

    CCNET_PROCESSOR_CLASS (seafile_getrepoemailtoken_proc_parent_class)->release_resource (processor);
}


static void
seafile_getrepoemailtoken_proc_class_init (SeafileGetrepoemailtokenProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "get-repo-email-token";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileGetrepoemailtokenProcPriv));
}

static void
seafile_getrepoemailtoken_proc_init (SeafileGetrepoemailtokenProc *processor)
{
}


static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;

    if (argc != 1) {
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    GString *buf = g_string_new(NULL);
    priv->repo_id = g_strdup(argv[0]);

    g_string_append_printf (buf, "remote %s seafile-put-repo-email-token %s",
                            processor->peer_id, priv->repo_id);

    ccnet_processor_send_request (processor, buf->str);

    g_string_free (buf, TRUE);
    return 0;
}

static void
set_repo_token_email (CcnetProcessor *processor)
{
    USE_PRIV;
    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr,
                                                 priv->repo_id);
    if (!repo)
        return;
    
    seaf_repo_manager_set_repo_email (seaf->repo_mgr, repo, priv->email);
    seaf_repo_manager_set_repo_token (seaf->repo_mgr, repo, priv->token);
}

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

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    USE_PRIV;

    if (strcmp (code, SC_REPO_EMAIL) == 0) {
        if (!content || content[clen - 1] != '\0')
            ccnet_processor_done (processor, FALSE);
        else {
            priv->email = g_strdup (content);
            ccnet_processor_send_update (processor, SC_REPO_TOKEN,
                                     SS_REPO_TOKEN, NULL, 0);
        }
        
    } else if (strcmp (code, SC_REPO_TOKEN) == 0) {
        if (!content || content[clen - 1] != '\0')
            ccnet_processor_done (processor, FALSE);
        else {
            priv->token = g_strdup (content);
            set_repo_token_email (processor);
            ccnet_processor_done (processor, TRUE);
        }
        
    } else if (strcmp (code, SC_ACCESS_DENIED) == 0) {
        seaf_warning ("[get repo email token] failed because %s", code_msg);
        ccnet_processor_done (processor, FALSE);

    } else if (strcmp (code, SC_SERVER_ERROR) == 0) {
        seaf_warning ("[get repo email token] repo %s is deleted on server", priv->repo_id);
        ccnet_processor_done (processor, FALSE);
        
    } else {
        seaf_warning ("bad response, %s : %s\n", code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}
