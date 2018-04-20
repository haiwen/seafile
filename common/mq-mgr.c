#include "common.h"
#include "log.h"
#include "utils.h"
#include "mq-mgr.h"

typedef struct SeafMqManagerPriv {
    // chan <-> async_queue
    GHashTable *chans;
} SeafMqManagerPriv;

SeafMqManager *
seaf_mq_manager_new ()
{
    SeafMqManager *mgr = g_new0 (SeafMqManager, 1);
    mgr->priv = g_new0 (SeafMqManagerPriv, 1);
    mgr->priv->chans = g_hash_table_new_full (g_str_hash, g_str_equal,
                                              (GDestroyNotify)g_free,
                                              (GDestroyNotify)g_async_queue_unref);

    return mgr;
}

void
seaf_mq_manager_init (SeafMqManager *mgr)
{
    g_hash_table_replace (mgr->priv->chans, g_strdup (SEAFILE_NOTIFY_CHAN),
                          g_async_queue_new_full ((GDestroyNotify)json_decref));
}

void
seaf_mq_manager_publish_notification (SeafMqManager *mgr, const char *type, const char *content)
{
    const char *chan = SEAFILE_NOTIFY_CHAN;
    GAsyncQueue *async_queue = g_hash_table_lookup (mgr->priv->chans, chan);
    if (!async_queue) {
        seaf_warning ("Unkonwn message channel %s.\n", chan);
        return;
    }

    if (!type || !content) {
        seaf_warning ("type and content should not be NULL.\n");
        return;
    }

    json_t *msg = json_object ();
    json_object_set_new (msg, "type", json_string(type));
    json_object_set_new (msg, "content", json_string(content));

    g_async_queue_push (async_queue, msg);
}

json_t *
seaf_mq_manager_pop_message (SeafMqManager *mgr)
{
    const char *chan = SEAFILE_NOTIFY_CHAN;
    GAsyncQueue *async_queue = g_hash_table_lookup (mgr->priv->chans, chan);
    if (!async_queue) {
        seaf_warning ("Unkonwn message channel %s.\n", chan);
        return NULL;
    }

    return g_async_queue_try_pop (async_queue);
}
