/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_TOKEN_MGR_H
#define SEAF_TOKEN_MGR_H

#include <searpc-client.h>

struct _SeafileSession;
struct TokenManagerPriv;

struct _SeafTokenManager {
    struct _SeafileSession  *seaf;
    struct TokenManagerPriv *priv;
};
typedef struct _SeafTokenManager SeafTokenManager;

SeafTokenManager *
seaf_token_manager_new (struct _SeafileSession *session);

/* Generate a token, signed by me.
 * This is called by a master server.
 */
char *
seaf_token_manager_generate_token (SeafTokenManager *mgr,
                                   const char *client_id,
                                   const char *repo_id);

/* Verify whether a token is valid.
 *
 * @peer_id: the peer who presents this token to me.
 * If the token is valid, repo id will be stored in @ret_repo_id.
 */
int
seaf_token_manager_verify_token (SeafTokenManager *mgr,
                                 SearpcClient *rpc_client,
                                 const char *peer_id,
                                 char *token,
                                 char *ret_repo_id);

#if 0
/* Record a used token so that it cannot be reused.
 * This function should only be called after the token has been verified.
 */
void
seaf_token_manager_invalidate_token (SeafTokenManager *mgr,
                                     char *token);
#endif

#endif
