/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet/timer.h>

#include "seafile-session.h"
#include "web-accesstoken-mgr.h"


#define CLEANING_INTERVAL_MSEC 1000*300	/* 5 minutes */
#define TOKEN_EXPIRE_TIME 300	/* 5 minutes */
#define DEBUG 1

SeafWebAccessTokenManager*
seaf_web_at_manager_new (SeafileSession *seaf)
{
    SeafWebAccessTokenManager *mgr = g_new0 (SeafWebAccessTokenManager, 1);

    mgr->seaf = seaf;
    mgr->access_token_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                    g_free, g_free);

    return mgr;
}


#if DEBUG
static void
print_key_value (gpointer key, gpointer value, gpointer user_data)
{
    AccessTokenHashVal *val = (AccessTokenHashVal *)value;
    printf ("%s ---> %s|%s|%s|%s|%ld\n", (char *)key,
            val->repo_id, val->obj_id,
            val->op, val->username, val->expire_time);
}

static void
display_hash_table (GHashTable *table)
{
    if (g_hash_table_size (table) > 0)
        printf("-------------------------\n");
    g_hash_table_foreach (table, print_key_value, NULL);
    if (g_hash_table_size (table) > 0)
        printf("-------------------------\n");
}
#endif

static gboolean
remove_expire_token (gpointer key, gpointer value, gpointer user_data)
{
    AccessTokenHashVal *val = (AccessTokenHashVal *)value;
    long now = (long)time(NULL);

    if (val && now > val->expire_time) {
        return TRUE;
    }

    return FALSE;
}

static void
remove_expire_token_hash (GHashTable *table)
{
    g_hash_table_foreach_remove (table, remove_expire_token, NULL);
}

static int
clean_pulse (void *vmanager)
{
    SeafWebAccessTokenManager *manager = vmanager;
    
#if DEBUG
    display_hash_table (manager->access_token_hash);
#endif
    
    remove_expire_token_hash (manager->access_token_hash);
    
    return TRUE;
}

int
seaf_web_at_manager_start (SeafWebAccessTokenManager *mgr)
{
    ccnet_timer_new (clean_pulse, mgr, CLEANING_INTERVAL_MSEC);

    return 0;
}

int
seaf_web_at_manager_save_access_token (SeafWebAccessTokenManager *mgr,
                                       const char *token, const char *repo_id,
                                       const char *obj_id, const char *op,
                                       const char *username)
{
    AccessTokenHashVal *hashVal = g_new0 (AccessTokenHashVal, 1);
    strcpy (hashVal->repo_id, repo_id);
    strcpy (hashVal->obj_id, obj_id);
    strcpy (hashVal->op, op);
    strcpy (hashVal->username, username);
    hashVal->expire_time = (long)time(NULL) + TOKEN_EXPIRE_TIME;	
    g_hash_table_insert (mgr->access_token_hash, g_strdup (token),
                         hashVal);
#if DEBUG
    display_hash_table (mgr->access_token_hash);
#endif   
    return 0;
}

SeafileWebAccess *
seaf_web_at_manager_query_access_token (SeafWebAccessTokenManager *mgr,
                                        const char *token)
{
    SeafileWebAccess *webaccess= NULL; 
    AccessTokenHashVal *hashVal = NULL;
    hashVal = (AccessTokenHashVal *)g_hash_table_lookup (mgr->access_token_hash,
                                                         (gconstpointer)token);
    if (hashVal != NULL) {
        char *repo_id = hashVal->repo_id;
        char *obj_id = hashVal->obj_id;
        char *op = hashVal->op;
        char *username = hashVal->username;
        
        long expire_time = hashVal->expire_time;
        long now = (long)time(NULL);        

        if (now - expire_time > 0)
            return NULL;
        else {
            webaccess = g_object_new (SEAFILE_TYPE_WEB_ACCESS,
                                      "repo_id", repo_id,
                                      "obj_id", obj_id,
                                      "op", op,
                                      "username", username,
                                      NULL);
            return webaccess;
        }
    }

    return NULL;
}

