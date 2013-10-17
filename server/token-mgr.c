#include <ccnet.h>

#include "common.h"
#include "seafile-session.h"
#include "utils.h"

/*
 * Token format:
 *
 * master_id
 * client_id
 * repo_id
 * timestamp
 * signature
 */

#define TOKEN_TIME_TO_EXPIRE 24 * 3600 /* a token is valid in 1 day. */

struct TokenManagerPriv {
    /* (master, client, repo) --> timestamp */
    GHashTable *token_hash;
};

SeafTokenManager *
seaf_token_manager_new (struct _SeafileSession *session)
{
    SeafTokenManager *mgr = g_new0(SeafTokenManager, 1);
    struct TokenManagerPriv *priv = g_new0(struct TokenManagerPriv, 1);

    mgr->seaf = session;
    mgr->priv = priv;

    /* mgr->priv->token_hash = g_hash_table_new_full (g_str_hash, g_str_equal, */
    /*                                                g_free, g_free); */

    return mgr;
}

char *
seaf_token_manager_generate_token (SeafTokenManager *mgr,
                                   const char *client_id,
                                   const char *repo_id)
{
    GString *token = g_string_new (NULL);
    char *sig_base64;

    g_string_append_printf (token, "%s\n%s\n%s\n%"G_GUINT64_FORMAT,
                            seaf->session->base.id,
                            client_id,
                            repo_id,
                            (guint64)time(NULL));

    /* Create signature with my private key. */
    sig_base64 = ccnet_sign_message (seaf->ccnetrpc_client, token->str);
    g_string_append_printf (token, "\n%s", sig_base64);
    g_free (sig_base64);

    return g_string_free (token, FALSE);
}

int
seaf_token_manager_verify_token (SeafTokenManager *mgr,
                                 SearpcClient *rpc_client,
                                 const char *peer_id,
                                 char *token,
                                 char *ret_repo_id)
{
    char **keys;
    char *master_id, *client_id, *repo_id, *ts_str, *signature;
    guint64 timestamp;
    char *sep;
    int ret = 0;

    if (token[0] == '\0')
        return -1;

    keys = g_strsplit (token, "\n", 5);
    if (g_strv_length(keys) != 5) {
        ret = -1;
        goto out;
    }

    master_id = keys[0];
    client_id = keys[1];
    repo_id = keys[2];
    ts_str = keys[3];
    signature = keys[4];

    if (strlen(master_id) != 40 ||
        strlen(client_id) != 40 ||
        strlen(repo_id) != 36) {
        ret = -1;
        goto out;
    }

    sep = strrchr (token, '\n');
    sep[0] = '\0';

    if (!rpc_client)
        rpc_client = seaf->ccnetrpc_client;

    /* Verify signature.
     * TODO: we should first check whether master_id is a master server.
     */
    if (ccnet_verify_message (rpc_client,
                              token, signature, master_id) < 0) {
        ret = -1;
        goto out;
    }

    sep[0] = '\n';

    /* Check whether this token is assigned to the peer. */
    if (peer_id && strcmp (peer_id, client_id) != 0) {
        ret = -1;
        goto out;
    }

    timestamp = strtoul(ts_str, NULL, 10);

    /* The timestamp contained in the token cannot be smaller than
     * the last one received, and should not be older than 1 hour.
     */
    if (timestamp + TOKEN_TIME_TO_EXPIRE <= (guint64)time(NULL)) {
        ret = -1;
        goto out;
    }

    /* OK, the token is valid. */
    if (ret_repo_id != NULL)
        memcpy (ret_repo_id, repo_id, 37);

out:
    g_strfreev (keys);
    return ret;
}

#if 0
void
seaf_token_manager_invalidate_token (SeafTokenManager *mgr,
                                     char *token)
{
    char **keys;
    char *master_id, *client_id, *repo_id, *ts_str;
    char hash_key[128];
    guint64 timestamp;

    /* We assume that the token has been verified. */

    keys = g_strsplit (token, "\n", 5);

    master_id = keys[0];
    client_id = keys[1];
    repo_id = keys[2];
    ts_str = keys[3];

    snprintf (hash_key, sizeof(hash_key), "%s%s%s",
              master_id, client_id, repo_id);

    timestamp = strtoul(ts_str, NULL, 10);

    /* Record the timestamp so that it cannot be reused. */
    guint64 *new_ts = g_new0(guint64, 1);
    *new_ts = timestamp;
    g_hash_table_insert (mgr->priv->token_hash, g_strdup(hash_key), new_ts);

    g_strfreev (keys);
}
#endif
