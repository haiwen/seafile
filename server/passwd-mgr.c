#include "common.h"
#include "log.h"

#include <glib.h>
#include <ccnet/timer.h>

#include "seafile-session.h"
#include "seafile-object.h"
#include "seafile-error.h"
#include "seafile-crypt.h"

#include "utils.h"

#define REAP_INTERVAL 60
#define REAP_THRESHOLD 3600

typedef struct {
    unsigned char key[16];
    unsigned char iv[16];
    guint64 expire_time;
} DecryptKey;

struct _SeafPasswdManagerPriv {
    GHashTable *decrypt_keys;
    CcnetTimer *reap_timer;
};

static int reap_expired_passwd (void *vmgr);

SeafPasswdManager *
seaf_passwd_manager_new (struct _SeafileSession *session)
{
    SeafPasswdManager *mgr = g_new0 (SeafPasswdManager, 1);

    mgr->session = session;
    mgr->priv = g_new0 (struct _SeafPasswdManagerPriv, 1);
    mgr->priv->decrypt_keys = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                     g_free, g_free);

    return mgr;
}

int
seaf_passwd_manager_start (SeafPasswdManager *mgr)
{
    mgr->priv->reap_timer = ccnet_timer_new (reap_expired_passwd,
                                             mgr, REAP_INTERVAL * 1000);
    return 1;
}

int
seaf_passwd_manager_set_passwd (SeafPasswdManager *mgr,
                                const char *repo_id,
                                const char *user,
                                const char *passwd,
                                GError **error)
{
    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    DecryptKey *crypt_key;
    GString *hash_key;

    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid repo");
        return -1;
    }

    if (!repo->encrypted) {
        seaf_repo_unref (repo);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Repo is not encrypted");
        return -1;
    }

    if (seaf_repo_verify_passwd (repo, passwd) < 0) {
        seaf_repo_unref (repo);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Incorrect password");
        return -1;
    }

    crypt_key = g_new0 (DecryptKey, 1);
    if (!crypt_key) {
        g_warning ("Failed to alloc crypt key struct.\n");
        seaf_repo_unref (repo);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Internal server error");
        return -1;
    }

    seafile_generate_enc_key (passwd, strlen(passwd), repo->enc_version,
                              crypt_key->key, crypt_key->iv);
    crypt_key->expire_time = (guint64)time(NULL) + REAP_THRESHOLD;

    hash_key = g_string_new (NULL);
    g_string_printf (hash_key, "%s.%s", repo_id, user);

    /* g_debug ("[passwd mgr] Set passwd for %s\n", hash_key->str); */

    g_hash_table_insert (mgr->priv->decrypt_keys,
                         g_string_free (hash_key, FALSE),
                         crypt_key);
    seaf_repo_unref (repo);

    return 0;
}

int
seaf_passwd_manager_unset_passwd (SeafPasswdManager *mgr,
                                  const char *repo_id,
                                  const char *user,
                                  GError **error)
{
    GString *hash_key;

    hash_key = g_string_new (NULL);
    g_string_printf (hash_key, "%s.%s", repo_id, user);
    g_hash_table_remove (mgr->priv->decrypt_keys, hash_key->str);
    g_string_free (hash_key, TRUE);

    return 0;
}     

gboolean
seaf_passwd_manager_is_passwd_set (SeafPasswdManager *mgr,
                                   const char *repo_id,
                                   const char *user)
{
    GString *key = g_string_new (NULL);
    gboolean ret = FALSE;

    g_string_printf (key, "%s.%s", repo_id, user);
    /* g_debug ("[passwd mgr] check passwd for %s\n", key->str); */
    if (g_hash_table_lookup (mgr->priv->decrypt_keys, key->str) != NULL)
        ret = TRUE;
    g_string_free (key, TRUE);

    return ret;
}

SeafileCryptKey *
seaf_passwd_manager_get_decrypt_key (SeafPasswdManager *mgr,
                                     const char *repo_id,
                                     const char *user)
{
    GString *hash_key;
    DecryptKey *crypt_key;
    SeafileCryptKey *ret;
    char key_hex[33], iv_hex[33];

    hash_key = g_string_new (NULL);
    g_string_printf (hash_key, "%s.%s", repo_id, user);

    /* g_debug ("[passwd mgr] get passwd for %s.\n", hash_key->str); */

    crypt_key = g_hash_table_lookup (mgr->priv->decrypt_keys, hash_key->str);
    if (!crypt_key) {
        g_string_free (hash_key, TRUE);
        return NULL;
    }

    rawdata_to_hex (crypt_key->key, key_hex, 16);
    rawdata_to_hex (crypt_key->iv, iv_hex, 16);

    ret = seafile_crypt_key_new ();
    g_object_set (ret, "key", key_hex, "iv", iv_hex, NULL);

    g_string_free (hash_key, TRUE);
    return ret;
}

int
seaf_passwd_manager_get_decrypt_key_raw (SeafPasswdManager *mgr,
                                         const char *repo_id,
                                         const char *user,
                                         unsigned char *key_out,
                                         unsigned char *iv_out)
{
    GString *hash_key;
    DecryptKey *crypt_key;

    hash_key = g_string_new (NULL);
    g_string_printf (hash_key, "%s.%s", repo_id, user);

    crypt_key = g_hash_table_lookup (mgr->priv->decrypt_keys, hash_key->str);
    if (!crypt_key) {
        g_string_free (hash_key, TRUE);
        return -1;
    }
    g_string_free (hash_key, TRUE);

    memcpy (key_out, crypt_key->key, 16);
    memcpy (iv_out, crypt_key->iv, 16);

    return 0;
}

static int
reap_expired_passwd (void *vmgr)
{
    SeafPasswdManager *mgr = vmgr;
    GHashTableIter iter;
    gpointer key, value;
    DecryptKey *crypt_key;
    guint64 now = (guint64)time(NULL);

    g_hash_table_iter_init (&iter, mgr->priv->decrypt_keys);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        crypt_key = value;
        if (crypt_key->expire_time <= now) {
            /* g_debug ("[passwd mgr] Remove passwd for %s\n", (char *)key); */
            g_hash_table_iter_remove (&iter);
        }
    }

    return 1;
}
