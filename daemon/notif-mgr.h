/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef NOTIF_MGR_H
#define NOTIF_MGR_H
typedef struct _SeafNotifManager SeafNotifManager;
typedef struct _SeafNotifManagerPriv SeafNotifManagerPriv;

struct _SeafileSession;

struct _SeafNotifManager {
    struct _SeafileSession   *seaf;

    SeafNotifManagerPriv *priv;
};

SeafNotifManager *
seaf_notif_manager_new (struct _SeafileSession *seaf);

void
seaf_notif_manager_connect_server (SeafNotifManager *mgr, const char *host,
                                   gboolean use_notif_server_port);

void
seaf_notif_manager_subscribe_repo (SeafNotifManager *mgr, SeafRepo *repo);

void
seaf_notif_manager_unsubscribe_repo (SeafNotifManager *mgr, SeafRepo *repo);

gboolean
seaf_notif_manager_is_repo_subscribed (SeafNotifManager *mgr, SeafRepo *repo);

#endif
