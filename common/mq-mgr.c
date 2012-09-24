/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <ccnet.h>

#include "mq-mgr.h"

#include "seafile-session.h"
#include "log.h"

typedef struct _SeafMqManagerPriv SeafMqManagerPriv;

struct _SeafMqManagerPriv {
    CcnetMqclientProc *mqclient_proc;
    CcnetTimer *timer; 
    /* keep it in memory since we always use the same message */
    CcnetMessage *heartbeat_msg;
};

#define HEARTBEAT_INTERVAL 2    /* 2s */
    
static int heartbeat_pulse (void *vmanager);

SeafMqManager *
seaf_mq_manager_new (SeafileSession *seaf)
{
    CcnetClient *client = seaf->session;
    SeafMqManager *mgr;
    SeafMqManagerPriv *priv;

    mgr = g_new0 (SeafMqManager, 1);
    priv = g_new0 (SeafMqManagerPriv, 1);
    
    
    mgr->seaf = seaf;
    mgr->priv = priv;

    priv->mqclient_proc = (CcnetMqclientProc *)
        ccnet_proc_factory_create_master_processor (client->proc_factory,
                                                    "mq-client");

    if (!priv->mqclient_proc) {
        seaf_warning ("Failed to create mqclient proc.\n");
        g_free (mgr);
        g_free(priv);
        return NULL;
    }

    return mgr;
}

static int
start_mq_client (CcnetMqclientProc *mqclient)
{
    if (ccnet_processor_startl ((CcnetProcessor *)mqclient, NULL) < 0) {
        ccnet_processor_done ((CcnetProcessor *)mqclient, FALSE);
        seaf_warning ("Failed to start mqclient proc\n");
        return -1;
    }

    seaf_message ("[mq client] mq cilent is started\n");

    return 0;
}

int
seaf_mq_manager_init (SeafMqManager *mgr)
{
    SeafMqManagerPriv *priv = mgr->priv;
    if (start_mq_client(priv->mqclient_proc) < 0)
        return -1;
    return 0;
}

int
seaf_mq_manager_start (SeafMqManager *mgr)
{
    SeafMqManagerPriv *priv = mgr->priv;
    priv->timer = ccnet_timer_new (heartbeat_pulse, mgr, 
                                   HEARTBEAT_INTERVAL * 1000);
    return 0;
}

static inline CcnetMessage *
create_message (SeafMqManager *mgr, const char *app, const char *body, int flags)
{
    CcnetClient *client = mgr->seaf->session;
    CcnetMessage *msg;
    
    char *from = client->base.id;
    char *to = client->base.id;

    msg = ccnet_message_new (from, to, app, body, flags);
    return msg;
}

void
seaf_mq_manager_set_heartbeat_name (SeafMqManager *mgr, const char *app)
{
    if (!app)
        return;

    SeafMqManagerPriv *priv = mgr->priv;
    if (priv->heartbeat_msg)
        return;

    seaf_message ("[mq mgr] publish to hearbeat mq: %s\n", app);

    priv->heartbeat_msg =
        create_message (seaf->mq_mgr, app, "heartbeat", 0);
}

/* Wrap around ccnet_message_new since all messages we use are local. */
static inline void
_send_message (SeafMqManager *mgr, CcnetMessage *msg)
{
    CcnetMqclientProc *mqclient_proc = mgr->priv->mqclient_proc;
    ccnet_mqclient_proc_put_message (mqclient_proc, msg);
}

void
seaf_mq_manager_publish_message (SeafMqManager *mgr,
                                 CcnetMessage *msg)
{
    _send_message (mgr, msg);
}

void
seaf_mq_manager_publish_message_full (SeafMqManager *mgr,
                                      const char *app,
                                      const char *body,
                                      int flags)
{
    CcnetMessage *msg = create_message (mgr, app, body, flags);
    _send_message (mgr, msg);
    ccnet_message_free (msg);
}

void
seaf_mq_manager_publish_notification (SeafMqManager *mgr,
                                      const char *type,
                                      const char *content)
{
    static const char *app = "seafile.notification";
    
    GString *buf = g_string_new(NULL);
    g_string_append_printf (buf, "%s\n%s", type, content);
    
    CcnetMessage *msg = create_message (mgr, app, buf->str, 0);
    _send_message (mgr, msg);
    
    g_string_free (buf, TRUE);
    ccnet_message_free (msg);
}

void
seaf_mq_manager_publish_event (SeafMqManager *mgr, const char *content)
{
    static const char *app = "seaf_server.event";

    CcnetMessage *msg = create_message (mgr, app, content, 0);
    _send_message (mgr, msg);

    ccnet_message_free (msg);
}

static int
heartbeat_pulse (void *vmanager)
{
    SeafMqManager *mgr = vmanager;

    _send_message (mgr, mgr->priv->heartbeat_msg);

    return TRUE;
}
