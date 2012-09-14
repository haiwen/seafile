/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef WEB_ACCESSTOKEN_MGR_H
#define WEB_ACCESSTOKEN_MGR_H

#include <glib.h>

struct _SeafileSession;

struct _SeafWebAccessTokenManager {
    struct _SeafileSession	*seaf;
    GHashTable		*access_token_hash; /* token -> access info */
    GHashTable      *access_info_hash;  /* access info -> token */
};
typedef struct _SeafWebAccessTokenManager SeafWebAccessTokenManager;

SeafWebAccessTokenManager* seaf_web_at_manager_new (struct _SeafileSession *seaf);

int
seaf_web_at_manager_start (SeafWebAccessTokenManager *mgr);

/*
 * Returns an access token for the given access info.
 * If a token doesn't exist or has expired, generate and return a new one.
 */
char *
seaf_web_at_manager_get_access_token (SeafWebAccessTokenManager *mgr,
                                      const char *repo_id,
                                      const char *obj_id,
                                      const char *op,
                                      const char *username);

/*
 * Returns access info for the given token.
 */
SeafileWebAccess *
seaf_web_at_manager_query_access_token (SeafWebAccessTokenManager *mgr,
                                        const char *token);

#endif /* WEB_ACCESSTOKEN_MGR_H */

