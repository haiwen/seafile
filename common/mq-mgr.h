#ifndef SEAF_MQ_MANAGER_H
#define SEAF_MQ_MANAGER_H

#define SEAFILE_NOTIFY_CHAN "seafile.notification"

struct SeafMqManagerPriv;

typedef struct SeafMqManager {
    struct SeafMqManagerPriv *priv;
} SeafMqManager;

SeafMqManager *
seaf_mq_manager_new ();

void
seaf_mq_manager_init (SeafMqManager *mgr);

void
seaf_mq_manager_publish_notification (SeafMqManager *mgr, const char *type, const char *content);

json_t *
seaf_mq_manager_pop_message (SeafMqManager *mgr);

#endif
