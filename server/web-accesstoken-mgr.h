/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef WEB_ACCESSTOKEN_MGR_H
#define WEB_ACCESSTOKEN_MGR_H

#include <glib.h>

struct _SeafileSession;

struct _SeafWebAccessTokenManager {
     struct _SeafileSession	*seaf;
     GHashTable		*access_token_hash;
};
typedef struct _SeafWebAccessTokenManager SeafWebAccessTokenManager;

typedef struct {
    char repo_id[37];
    char obj_id[41];
    char op[10];
    char username[255];
    long expire_time;
} AccessTokenHashVal;

SeafWebAccessTokenManager* seaf_web_at_manager_new (struct _SeafileSession *seaf);

int
seaf_web_at_manager_start (SeafWebAccessTokenManager *mgr);

int
seaf_web_at_manager_save_access_token (SeafWebAccessTokenManager *mgr,
                                       const char *token, const char *repo_id,
                                       const char *obj_id, const char *op,
                                       const char *username);

SeafileWebAccess *
seaf_web_at_manager_query_access_token (SeafWebAccessTokenManager *mgr,
                                        const char *token);

#endif /* WEB_ACCESSTOKEN_MGR_H */

