/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "web-accesstoken-mgr.h"

#include "utils.h"

#define TOKEN_LEN 8

/* #define DEBUG 1 */

typedef struct {
    char *repo_id;
    char *obj_id;
    char *op;
    char *username;
} AccessInfo;

static void
free_access_info (AccessInfo *info)
{
    if (!info)
        return;

    g_free (info->repo_id);
    g_free (info->obj_id);
    g_free (info->op);
    g_free (info->username);
    g_free (info);
}

SeafWebAccessTokenManager*
seaf_web_at_manager_new (SeafileSession *seaf)
{
    SeafWebAccessTokenManager *mgr = g_new0 (SeafWebAccessTokenManager, 1);

    mgr->seaf = seaf;
    mgr->access_token_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                    g_free,
                                                    (GDestroyNotify)free_access_info);

    return mgr;
}

int
seaf_web_at_manager_start (SeafWebAccessTokenManager *mgr)
{
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
    AccessInfo *info;
    char *t;

    t = gen_new_token (mgr->access_token_hash);
    if (t == NULL)
        return NULL;

    info = g_new0 (AccessInfo, 1);
    info->repo_id = g_strdup (repo_id);
    info->obj_id = g_strdup (obj_id);
    info->op = g_strdup (op);
    info->username = g_strdup (username);

    g_hash_table_insert (mgr->access_token_hash, g_strdup(t), info);

    return t;
}

SeafileWebAccess *
seaf_web_at_manager_query_access_token (SeafWebAccessTokenManager *mgr,
                                        const char *token)
{
    SeafileWebAccess *webaccess;
    AccessInfo *info;

    info = g_hash_table_lookup (mgr->access_token_hash, token);
    if (info != NULL) {
        webaccess = g_object_new (SEAFILE_TYPE_WEB_ACCESS,
                                  "repo_id", info->repo_id,
                                  "obj_id", info->obj_id,
                                  "op", info->op,
                                  "username", info->username,
                                  NULL);
        g_hash_table_remove(mgr->access_token_hash, token);
        return webaccess;
    }

    return NULL;
}
