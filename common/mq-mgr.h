/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
 * Mq-manager is responsible for: 
 * 
 *  - Publishing heartbeat messages every HEARTBEAT_INTERVAL senconds to
 *    indicate it's alive. If seafile-applet doesn't get the message, it would
 *    check and try to restart seaf-daemon.
 *
 *  - Provide API for other modules to publish their messages.
 *
 * Currently we publish these types of messages:
 *
 *  - seafile.heartbeat <>
 *  - seafile.transfer <start | stop >
 *  - seafile.repo_sync_done <repo-name>
 *  - seafile.promt_create_repo <worktree>
 *  - seafile.repo_created <repo-name>
 *
 * And subscribe to no messages. 
 */

#ifndef SEAF_MQ_MANAGER_H
#define SEAF_MQ_MANAGER_H

struct _CcnetMessage;

typedef struct _SeafMqManager SeafMqManager;

struct _SeafMqManager {
    struct _SeafileSession   *seaf;
    struct _SeafMqManagerPriv *priv;
};

SeafMqManager *seaf_mq_manager_new (struct _SeafileSession *seaf);   

void seaf_mq_manager_set_heartbeat_name (SeafMqManager *mgr, const char *app);

int seaf_mq_manager_init (SeafMqManager *mgr);

int seaf_mq_manager_start (SeafMqManager *mgr);


void seaf_mq_manager_publish_message (SeafMqManager *mgr,
                                      struct _CcnetMessage *msg);

void
seaf_mq_manager_publish_message_full (SeafMqManager *mgr,
                                      const char *app,
                                      const char *body,
                                      int flags);

void
seaf_mq_manager_publish_notification (SeafMqManager *mgr,
                                      const char *type,
                                      const char *content);

void
seaf_mq_manager_publish_event (SeafMqManager *mgr, const char *content);

#endif
