/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet/timer.h>

#include "seafile-session.h"
#include "web-accesstoken-mgr.h"

#include "utils.h"

#define CLEANING_INTERVAL_MSEC 1000*300	/* 5 minutes */
#define TOKEN_EXPIRE_TIME 3600	        /* 1 hour */
#define TOKEN_LEN 8

/* #define DEBUG 1 */

typedef struct {
    char repo_id[37];
    char obj_id[41];
    char op[10];
    char username[255];
    long expire_time;
} AccessInfo;

typedef struct {
    char token[TOKEN_LEN + 1];
    long expire_time;
} AccessToken;

SeafWebAccessTokenManager*
seaf_web_at_manager_new (SeafileSession *seaf)
{
    SeafWebAccessTokenManager *mgr = g_new0 (SeafWebAccessTokenManager, 1);

    mgr->seaf = seaf;
    mgr->access_token_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                    g_free, g_free);
    mgr->access_info_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                   g_free, g_free);

    return mgr;
}

static gboolean
remove_expire_info (gpointer key, gpointer value, gpointer user_data)
{
    AccessInfo *info = (AccessInfo *)value;
    long now = *((long*)user_data);

    if (info && now >= info->expire_time) {
        return TRUE;
    }

    return FALSE;
}

static gboolean
remove_expire_token (gpointer key, gpointer value, gpointer user_data)
{
    AccessToken *token = (AccessToken *)value;
    long now = *((long*)user_data);

    if (token && now >= token->expire_time) {
        return TRUE;
    }

    return FALSE;
}

static int
clean_pulse (void *vmanager)
{
    SeafWebAccessTokenManager *manager = vmanager;
    long now = (long)time(NULL);

    g_hash_table_foreach_remove (manager->access_token_hash,
                                 remove_expire_info, &now);
    g_hash_table_foreach_remove (manager->access_info_hash,
                                 remove_expire_token, &now);
    
    return TRUE;
}

int
seaf_web_at_manager_start (SeafWebAccessTokenManager *mgr)
{
    ccnet_timer_new (clean_pulse, mgr, CLEANING_INTERVAL_MSEC);

    return 0;
}

static char *
gen_new_token (GHashTable *token_hash)
{
    char uuid[37];
    char *token;

    while (1) {
        gen_uuid_inplace (uuid);
        token = g_strndup(uuid, TOKEN_LEN);

        /* Make sure the new token doesn't conflict with an existing one. */
        if (g_hash_table_lookup (token_hash, token) != NULL)
            g_free (token);
        else
            return token;
    }
}

char *
seaf_web_at_manager_get_access_token (SeafWebAccessTokenManager *mgr,
                                      const char *repo_id,
                                      const char *obj_id,
                                      const char *op,
                                      const char *username)
{
    GString *key = g_string_new (NULL);
    AccessToken *token;
    AccessInfo *info;
    long now = (long)time(NULL);
    long expire;
    char *t;

    g_string_printf (key, "%s %s %s %s", repo_id, obj_id, op, username);

    token = g_hash_table_lookup (mgr->access_info_hash, key->str);
    /* To avoid returning an almost expired token, we returns token
     * that has at least 1 minute "life time".
     */
    if (!token || token->expire_time - now <= 60) {
        t = gen_new_token (mgr->access_token_hash);
        expire = now + TOKEN_EXPIRE_TIME;

        token = g_new0 (AccessToken, 1);
        memcpy (token->token, t, TOKEN_LEN);
        token->expire_time = expire;

        g_hash_table_insert (mgr->access_info_hash, g_strdup(key->str), token);

        info = g_new0 (AccessInfo, 1);
        memcpy (info->repo_id, repo_id, 36);
        memcpy (info->obj_id, obj_id, 40);
        memcpy (info->op, op, 10);
        memcpy (info->username, username, 255);
        info->expire_time = expire;

        g_hash_table_insert (mgr->access_token_hash, g_strdup(t), info);

        g_free (t);
    }

    g_string_free (key, TRUE);
    return g_strdup(token->token);
}

SeafileWebAccess *
seaf_web_at_manager_query_access_token (SeafWebAccessTokenManager *mgr,
                                        const char *token)
{
    SeafileWebAccess *webaccess;
    AccessInfo *info;

    info = g_hash_table_lookup (mgr->access_token_hash, token);
    if (info != NULL) {
        long expire_time = info->expire_time;
        long now = (long)time(NULL);        

        if (now - expire_time >= 0) {
            return NULL;
        } else {
            webaccess = g_object_new (SEAFILE_TYPE_WEB_ACCESS,
                                      "repo_id", info->repo_id,
                                      "obj_id", info->obj_id,
                                      "op", info->op,
                                      "username", info->username,
                                      NULL);
            return webaccess;
        }
    }

    return NULL;
}
