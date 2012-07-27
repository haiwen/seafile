/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "ccnet.h"
#include "utils.h"
#include "db.h"

#include "kvitem.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "share-info.h"
#include "share-mgr.h"

struct _SeafShareManagerPriv {

    GHashTable *repo_hash;
    sqlite3    *db;

    GHashTable *sinfo_hash;
    GHashTable *group_index;
    GHashTable *repo_index;

    struct _CcnetKvclientProc *kv_proc;
};


static void item_got_cb (CcnetKVItem *item, void *vmanager);

SeafShareManager*
seaf_share_manager_new (SeafileSession *seaf)
{
    SeafShareManager *mgr = g_new0 (SeafShareManager, 1);
    mgr->priv = g_new0 (SeafShareManagerPriv, 1);
    
    mgr->seaf = seaf;

    mgr->priv->sinfo_hash = g_hash_table_new (g_str_hash, g_str_equal);
    mgr->priv->group_index = g_hash_table_new_full (
        g_str_hash, g_str_equal, g_free, NULL);
    mgr->priv->repo_index = g_hash_table_new_full (
        g_str_hash, g_str_equal, g_free, NULL);

    return mgr;
}

int
seaf_share_manager_init (SeafShareManager *mgr)
{

    return 0;
}


int seaf_share_manager_start (SeafShareManager *mgr)
{
    CcnetClient *ccnet_session = mgr->seaf->session;

    mgr->priv->kv_proc = (CcnetKvclientProc *) 
        ccnet_proc_factory_create_master_processor (ccnet_session->proc_factory,
                                                    "kvclient");
    if (!mgr->priv->kv_proc) {
        g_warning ("Create kvclient proc failed\n");
        return -1;
    }
   
    ccnet_kvclient_proc_set_item_got_cb (mgr->priv->kv_proc,
                                         item_got_cb, mgr);
    ccnet_processor_startl (CCNET_PROCESSOR(mgr->priv->kv_proc),
                            SHAREINFO_KV_CATEGORY, NULL);

    return 0;
}

static void
add_share_item (SeafShareManager *share_mgr, SeafShareInfo *info)
{
    GList *list;

    g_hash_table_insert (share_mgr->priv->sinfo_hash, info->id, info);
 
    /* add group index */
    list = g_hash_table_lookup (share_mgr->priv->group_index,
                                info->group_id);
    list = g_list_prepend (list, info);
    g_hash_table_insert (share_mgr->priv->group_index, 
                         g_strdup(info->group_id), list);

    /* add repo index */
    list = g_hash_table_lookup (share_mgr->priv->repo_index,
                                info->repo_id);
    list = g_list_prepend (list, info);
    g_hash_table_insert (share_mgr->priv->repo_index, 
                         g_strdup(info->repo_id), list);
}

static SeafShareInfo *
find_share_item (SeafShareManager *share_mgr,
                 const char *repo_id,
                 const char *group_id)
{
    GList *list, *ptr;

    list = g_hash_table_lookup (share_mgr->priv->group_index, group_id);
    for (ptr = list; ptr; ptr = ptr->next) {
        SeafShareInfo *info = ptr->data;
        if (strcmp(info->repo_id, repo_id) == 0)
            return info;
    }

    return NULL;
}

static void
remove_share_item (SeafShareManager *share_mgr, const char *id)
{
    SeafShareInfo *info;

    info = g_hash_table_lookup (share_mgr->priv->sinfo_hash, id);
    if (!info)
        return;

    GList *list;
    /* remove from group index */
    list = g_hash_table_lookup (share_mgr->priv->group_index, info->group_id);
    list = g_list_remove (list, info);
    g_hash_table_insert (share_mgr->priv->group_index, 
                         g_strdup(info->group_id), list);

    /* remove from repo index */
    list = g_hash_table_lookup (share_mgr->priv->repo_index, info->repo_id);
    list = g_list_remove (list, info);
    g_hash_table_insert (share_mgr->priv->repo_index, 
                         g_strdup(info->repo_id), list);
    seaf_share_info_free (info);
}

static void
send_info (SeafShareManager *share_mgr, SeafShareInfo *info)
{
    CcnetKVItem *item;

    item = g_new0 (CcnetKVItem, 1);
    item->category = SHAREINFO_KV_CATEGORY;
    item->group_id = info->group_id;
    item->id = info->id;
    item->value = seaf_share_info_to_json (info);
    item->timestamp = info->timestamp;

    ccnet_kvclient_proc_put_item (share_mgr->priv->kv_proc, item);

    g_free (item->value);
    g_free (item);
}

const char *
seaf_share_manager_share (SeafShareManager *share_mgr,
                          const char *repo_id,
                          const char *group_id)
{
    SeafShareInfo *info;    
    char *my_id = share_mgr->seaf->session->base.user_id;

    g_return_val_if_fail (repo_id != NULL && group_id != NULL, NULL);

    info = find_share_item (share_mgr, repo_id, group_id);
    if (info) {
        g_warning ("Repo %.8s is already shared to group %.8s\n",
                   repo_id, group_id);
        return NULL;
    }

    info = seaf_share_info_new (NULL, repo_id, group_id, my_id, 0);
    add_share_item (share_mgr, info);

    send_info (share_mgr, info);
 
    return info->id;
}

int
seaf_share_manager_unshare (SeafShareManager *share_mgr,
                            const char *id)
{
    SeafShareInfo *info;
    gint64 ts;

    info = g_hash_table_lookup (share_mgr->priv->sinfo_hash, id);
    if (!info) {
        ccnet_warning ("item %s not exists\n", id);
        return -1;
    }
    
    CcnetKVItem *item;

    item = g_new0 (CcnetKVItem, 1);
    item->category = SHAREINFO_KV_CATEGORY;
    item->group_id = info->group_id;
    item->id = info->id;
    item->value = "";

    ts = get_current_time();
    item->timestamp = info->timestamp < ts ? ts : info->timestamp + 1;
    ccnet_kvclient_proc_put_item (share_mgr->priv->kv_proc, item);
    g_free (item);

    remove_share_item (share_mgr, id);

    return 0;
}

GList *
seaf_share_manager_list_share_info_by_repo (SeafShareManager *mgr,
                                            const char *repo_id)
{
    return g_hash_table_lookup (mgr->priv->repo_index, repo_id);
}

#if 0
GList *
seaf_share_manager_list_share_info (SeafShareManager *mgr,
                                    int offset,
                                    int limit)
{
    return load_share_info (mgr->priv->db, offset, limit);
}
#endif

GList *
seaf_share_manager_list_share_info_by_group (SeafShareManager *mgr,
                                             const char *group_id)
{
    return g_hash_table_lookup (mgr->priv->group_index, group_id);
}

static void
item_got_cb (CcnetKVItem *item, void *vmanager)
{
    SeafShareManager *share_mgr = vmanager;
    SeafShareInfo *info = NULL;

    if (!item->value) {
        ccnet_warning ("[share-mgr] Receive kvitem with NULL value\n");
        return;
    }

    if (item->value[0] == '\0') {
        remove_share_item (share_mgr, item->id);
        return;
    }

    if ((info = seaf_share_info_from_json (item->value)) == NULL)
        return;
    
    g_assert (strcmp(item->id, info->id) == 0);
    g_assert (item->timestamp == info->timestamp);
    add_share_item (share_mgr, info);
}
