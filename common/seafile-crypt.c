/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <string.h>
#include <glib.h>
#include "seafile-crypt.h"

#ifdef USE_GPL_CRYPTO
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <nettle/pbkdf2.h>
#else
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif

#include "utils.h"
#include "log.h"

/*
  The EVP_EncryptXXX and EVP_DecryptXXX series of functions have a
  weird choice of returned value.
*/
#define ENC_SUCCESS 1
#define ENC_FAILURE 0
#define DEC_SUCCESS 1
#define DEC_FAILURE 0

#define KEYGEN_ITERATION 1 << 19
#define KEYGEN_ITERATION2 1000
/* Should generate random salt for each repo. */
static unsigned char salt[8] = { 0xda, 0x90, 0x45, 0xc3, 0x06, 0xc7, 0xcc, 0x26 };

SeafileCrypt *
seafile_crypt_new (int version, unsigned char *key, unsigned char *iv)
{
    SeafileCrypt *crypt = g_new0 (SeafileCrypt, 1);
    crypt->version = version;
    if (version == 1)
        memcpy (crypt->key, key, 16);
    else
        memcpy (crypt->key, key, 32);
    memcpy (crypt->iv, iv, 16);
    return crypt;
}

int
seafile_derive_key (const char *data_in, int in_len, int version,
                    const char *repo_salt,
                    unsigned char *key, unsigned char *iv)
{
#ifdef USE_GPL_CRYPTO
    if (version != 2) {
        seaf_warning ("Encrypted library version %d is not supported.\n", version);
        return -1;
    }

    pbkdf2_hmac_sha256 (in_len, (const guchar *)data_in, KEYGEN_ITERATION2,
                        sizeof(salt), salt, 32, key);
    pbkdf2_hmac_sha256 (32, (const guchar *)key, 10, sizeof(salt), salt, 16, iv);

    return 0;
#else
    if (version >= 3) {
        unsigned char repo_salt_bin[32];

        hex_to_rawdata (repo_salt, repo_salt_bin, 32);

        PKCS5_PBKDF2_HMAC (data_in, in_len,
                           repo_salt_bin, sizeof(repo_salt_bin),
                           KEYGEN_ITERATION2,
                           EVP_sha256(),
                           32, key);
        PKCS5_PBKDF2_HMAC ((char *)key, 32,
                           repo_salt_bin, sizeof(repo_salt_bin),
                           10,
                           EVP_sha256(),
                           16, iv);
        return 0;
    } else if (version == 2) {
        PKCS5_PBKDF2_HMAC (data_in, in_len,
                           salt, sizeof(salt),
                           KEYGEN_ITERATION2,
                           EVP_sha256(),
                           32, key);
        PKCS5_PBKDF2_HMAC ((char *)key, 32,
                           salt, sizeof(salt),
                           10,
                           EVP_sha256(),
                           16, iv);
        return 0;
    } else if (version == 1) {
        EVP_BytesToKey (EVP_aes_128_cbc(), /* cipher mode */
                        EVP_sha1(),        /* message digest */
                        salt,              /* salt */
                        (unsigned char*)data_in,
                        in_len,
                        KEYGEN_ITERATION,   /* iteration times */
                        key, /* the derived key */
                        iv); /* IV, initial vector */
        return 0;
    } else {
        EVP_BytesToKey (EVP_aes_128_ecb(), /* cipher mode */
                        EVP_sha1(),        /* message digest */
                        NULL,              /* salt */
                        (unsigned char*)data_in,
                        in_len,
                        3,   /* iteration times */
                        key, /* the derived key */
                        iv); /* IV, initial vector */
        return 0;
    }
#endif
}

int
seafile_generate_repo_salt (char *repo_salt)
{
    unsigned char repo_salt_bin[32];

#ifdef USE_GPL_CRYPTO
    int rc = gnutls_rnd (GNUTLS_RND_RANDOM, repo_salt_bin, sizeof(repo_salt_bin));
#else
    int rc = RAND_bytes (repo_salt_bin, sizeof(repo_salt_bin));
#endif
    if (rc != 1) {
        seaf_warning ("Failed to generate salt for repo encryption.\n");
        return -1;
    }

    rawdata_to_hex (repo_salt_bin, repo_salt, 32);

    return 0;
}

int
seafile_generate_random_key (const char *passwd,
                             int version,
                             const char *repo_salt,
                             char *random_key)
{
    SeafileCrypt *crypt;
    unsigned char secret_key[32], *rand_key;
    int outlen;
    unsigned char key[32], iv[16];

#ifdef USE_GPL_CRYPTO
    if (gnutls_rnd (GNUTLS_RND_RANDOM, secret_key, sizeof(secret_key)) < 0) {
        seaf_warning ("Failed to generate secret key for repo encryption.\n");
        return -1;
    }
#else
    if (RAND_bytes (secret_key, sizeof(secret_key)) != 1) {
        seaf_warning ("Failed to generate secret key for repo encryption.\n");
        return -1;
    }
#endif

    seafile_derive_key (passwd, strlen(passwd), version, repo_salt, key, iv);

    crypt = seafile_crypt_new (version, key, iv);

    seafile_encrypt ((char **)&rand_key, &outlen,
                     (char *)secret_key, sizeof(secret_key), crypt);

    rawdata_to_hex (rand_key, random_key, 48);

    g_free (crypt);
    g_free (rand_key);

    return 0;
}

void
seafile_generate_magic (int version, const char *repo_id,
                        const char *passwd,
                        const char *repo_salt,
                        char *magic)
{
    GString *buf = g_string_new (NULL);
    unsigned char key[32], iv[16];

    /* Compute a "magic" string from repo_id and passwd.
     * This is used to verify the password given by user before decrypting
     * data.
     */
    g_string_append_printf (buf, "%s%s", repo_id, passwd);

    seafile_derive_key (buf->str, buf->len, version, repo_salt, key, iv);

    g_string_free (buf, TRUE);
    rawdata_to_hex (key, magic, 32);
}

int
seafile_verify_repo_passwd (const char *repo_id,
                            const char *passwd,
                            const char *magic,
                            int version,
                            const char *repo_salt)
{
    GString *buf = g_string_new (NULL);
    unsigned char key[32], iv[16];
    char hex[65];

    if (version != 1 && version != 2 && version != 3 && version != 4) {
        seaf_warning ("Unsupported enc_version %d.\n", version);
        return -1;
    }

    /* Recompute the magic and compare it with the one comes with the repo. */
    g_string_append_printf (buf, "%s%s", repo_id, passwd);

    seafile_derive_key (buf->str, buf->len, version, repo_salt, key, iv);

    g_string_free (buf, TRUE);

    if (version >= 2)
        rawdata_to_hex (key, hex, 32);
    else
        rawdata_to_hex (key, hex, 16);

    if (g_strcmp0 (hex, magic) == 0)
        return 0;
    else
        return -1;
}

int
seafile_decrypt_repo_enc_key (int enc_version,
                              const char *passwd, const char *random_key,
                              const char *repo_salt,
                              unsigned char *key_out, unsigned char *iv_out)
{
    unsigned char key[32], iv[16];

    seafile_derive_key (passwd, strlen(passwd), enc_version, repo_salt, key, iv);

    if (enc_version == 1) {
        memcpy (key_out, key, 16);
        memcpy (iv_out, iv, 16);
        return 0;
    } else if (enc_version >= 2) {
        unsigned char enc_random_key[48], *dec_random_key;
        int outlen;
        SeafileCrypt *crypt;

        if (random_key == NULL || random_key[0] == 0) {
            seaf_warning ("Empty random key.\n");
            return -1;
        }

        hex_to_rawdata (random_key, enc_random_key, 48);

        crypt = seafile_crypt_new (enc_version, key, iv);
        if (seafile_decrypt ((char **)&dec_random_key, &outlen,
                             (char *)enc_random_key, 48,
                             crypt) < 0) {
            seaf_warning ("Failed to decrypt random key.\n");
            g_free (crypt);
            return -1;
        }
        g_free (crypt);

        seafile_derive_key ((char *)dec_random_key, 32, enc_version,
                            repo_salt,
                            key, iv);
        memcpy (key_out, key, 32);
        memcpy (iv_out, iv, 16);

        g_free (dec_random_key);
        return 0;
    }

    return -1;
}

int
seafile_update_random_key (const char *old_passwd, const char *old_random_key,
                           const char *new_passwd, char *new_random_key,
                           int enc_version, const char *repo_salt)
{
    unsigned char key[32], iv[16];
    unsigned char random_key_raw[48], *secret_key, *new_random_key_raw;
    int secret_key_len, random_key_len;
    SeafileCrypt *crypt;

    /* First, use old_passwd to decrypt secret key from old_random_key. */
    seafile_derive_key (old_passwd, strlen(old_passwd), enc_version,
                        repo_salt, key, iv);

    hex_to_rawdata (old_random_key, random_key_raw, 48);

    crypt = seafile_crypt_new (enc_version, key, iv);
    if (seafile_decrypt ((char **)&secret_key, &secret_key_len,
                         (char *)random_key_raw, 48,
                         crypt) < 0) {
        seaf_warning ("Failed to decrypt random key.\n");
        g_free (crypt);
        return -1;
    }
    g_free (crypt);

    /* Second, use new_passwd to encrypt secret key. */
    seafile_derive_key (new_passwd, strlen(new_passwd), enc_version,
                        repo_salt, key, iv);
    crypt = seafile_crypt_new (enc_version, key, iv);

    seafile_encrypt ((char **)&new_random_key_raw, &random_key_len,
                     (char *)secret_key, secret_key_len, crypt);

    rawdata_to_hex (new_random_key_raw, new_random_key, 48);

    g_free (secret_key);
    g_free (new_random_key_raw);
    g_free (crypt);

    return 0;
}

#ifdef USE_GPL_CRYPTO

int
seafile_encrypt (char **data_out,
                 int *out_len,
                 const char *data_in,
                 const int in_len,
                 SeafileCrypt *crypt)
{
    char *buf = NULL, *enc_buf = NULL;
    int buf_size, remain;
    guint8 padding;
    gnutls_cipher_hd_t handle;
    gnutls_datum_t key, iv;
    int rc, ret = 0;

    buf_size = BLK_SIZE * ((in_len / BLK_SIZE) + 1);
    remain = buf_size - in_len;
    buf = g_new (char, buf_size);

    memcpy (buf, data_in, in_len);
    padding = (guint8)remain;
    memset (buf + in_len, padding, remain);

    key.data = crypt->key;
    key.size = sizeof(crypt->key);
    iv.data = crypt->iv;
    iv.size = sizeof(crypt->iv);
    rc = gnutls_cipher_init (&handle, GNUTLS_CIPHER_AES_256_CBC, &key, &iv);
    if (rc < 0) {
        seaf_warning ("Failed to init cipher: %s\n", gnutls_strerror(rc));
        ret = -1;
        goto out;
    }

    enc_buf = g_new (char, buf_size);
    rc = gnutls_cipher_encrypt2 (handle, buf, buf_size, enc_buf, buf_size);
    if (rc < 0) {
        seaf_warning ("Failed to encrypt: %s\n", gnutls_strerror(rc));
        ret = -1;
        gnutls_cipher_deinit (handle);
        goto out;
    }

    gnutls_cipher_deinit (handle);

out:
    g_free (buf);
    if (ret < 0) {
        g_free (enc_buf);
        *data_out = NULL;
        *out_len = -1;
    } else {
        *data_out = enc_buf;
        *out_len = buf_size;
    }
    return ret;
}

int
seafile_decrypt (char **data_out,
                 int *out_len,
                 const char *data_in,
                 const int in_len,
                 SeafileCrypt *crypt)
{
    char *dec_buf = NULL;
    gnutls_cipher_hd_t handle;
    gnutls_datum_t key, iv;
    int rc, ret = 0;
    guint8 padding;
    int remain;

    if (in_len <= 0 || in_len % BLK_SIZE != 0) {
        seaf_warning ("Invalid encrypted buffer size.\n");
        return -1;
    }

    key.data = crypt->key;
    key.size = sizeof(crypt->key);
    iv.data = crypt->iv;
    iv.size = sizeof(crypt->iv);
    rc = gnutls_cipher_init (&handle, GNUTLS_CIPHER_AES_256_CBC, &key, &iv);
    if (rc < 0) {
        seaf_warning ("Failed to init cipher: %s\n", gnutls_strerror(rc));
        ret = -1;
        goto out;
    }

    dec_buf = g_new (char, in_len);
    rc = gnutls_cipher_decrypt2 (handle, data_in, in_len, dec_buf, in_len);
    if (rc < 0) {
        seaf_warning ("Failed to decrypt data: %s\n", gnutls_strerror(rc));
        ret = -1;
        gnutls_cipher_deinit (handle);
        goto out;
    }

    padding = dec_buf[in_len - 1];
    remain = padding;
    *out_len = (in_len - remain);
    *data_out = dec_buf;

    gnutls_cipher_deinit (handle);
out:
    if (ret < 0) {
        g_free (dec_buf);
        *data_out = NULL;
        *out_len = -1;
    }
    return ret;
}

#else

int
seafile_encrypt (char **data_out,
                 int *out_len,
                 const char *data_in,
                 const int in_len,
                 SeafileCrypt *crypt)
{
    *data_out = NULL;
    *out_len = -1;

    /* check validation */
    if ( data_in == NULL || in_len <= 0 || crypt == NULL) {
        seaf_warning ("Invalid params.\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx;
    int ret;
    int blks;

    /* Prepare CTX for encryption. */
    ctx = EVP_CIPHER_CTX_new ();

    if (crypt->version == 1)
        ret = EVP_EncryptInit_ex (ctx,
                                  EVP_aes_128_cbc(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  crypt->key,  /* derived key */
                                  crypt->iv);  /* initial vector */
    else if (crypt->version == 3)
        ret = EVP_EncryptInit_ex (ctx,
                                  EVP_aes_128_ecb(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  crypt->key,  /* derived key */
                                  crypt->iv);  /* initial vector */
    else
        ret = EVP_EncryptInit_ex (ctx,
                                  EVP_aes_256_cbc(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  crypt->key,  /* derived key */
                                  crypt->iv);  /* initial vector */

    if (ret == ENC_FAILURE) {
        EVP_CIPHER_CTX_free (ctx);
        return -1;
    }

    /* Allocating output buffer. */
    
    /*
      For EVP symmetric encryption, padding is always used __even if__
      data size is a multiple of block size, in which case the padding
      length is the block size. so we have the following:
    */
    
    blks = (in_len / BLK_SIZE) + 1;

    *data_out = (char *)g_malloc (blks * BLK_SIZE);

    if (*data_out == NULL) {
        seaf_warning ("failed to allocate the output buffer.\n");
        goto enc_error;
    }                

    int update_len, final_len;

    /* Do the encryption. */
    ret = EVP_EncryptUpdate (ctx,
                             (unsigned char*)*data_out,
                             &update_len,
                             (unsigned char*)data_in,
                             in_len);

    if (ret == ENC_FAILURE)
        goto enc_error;


    /* Finish the possible partial block. */
    ret = EVP_EncryptFinal_ex (ctx,
                               (unsigned char*)*data_out + update_len,
                               &final_len);

    *out_len = update_len + final_len;

    /* out_len should be equal to the allocated buffer size. */
    if (ret == ENC_FAILURE || *out_len != (blks * BLK_SIZE))
        goto enc_error;
    
    EVP_CIPHER_CTX_free (ctx);

    return 0;

enc_error:

    EVP_CIPHER_CTX_free (ctx);

    *out_len = -1;

    if (*data_out != NULL)
        g_free (*data_out);

    *data_out = NULL;

    return -1;
    
}
                               
int
seafile_decrypt (char **data_out,
                 int *out_len,
                 const char *data_in,
                 const int in_len,
                 SeafileCrypt *crypt)
{
    *data_out = NULL;
    *out_len = -1;

    /* Check validation. Because padding is always used, in_len must
     * be a multiple of BLK_SIZE */
    if ( data_in == NULL || in_len <= 0 || in_len % BLK_SIZE != 0 ||
         crypt == NULL) {

        seaf_warning ("Invalid param(s).\n");
        return -1;
    }

    EVP_CIPHER_CTX *ctx;
    int ret;

    /* Prepare CTX for decryption. */
    ctx = EVP_CIPHER_CTX_new ();

    if (crypt->version == 1)
        ret = EVP_DecryptInit_ex (ctx,
                                  EVP_aes_128_cbc(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  crypt->key,  /* derived key */
                                  crypt->iv);  /* initial vector */
    else if (crypt->version == 3)
        ret = EVP_DecryptInit_ex (ctx,
                                  EVP_aes_128_ecb(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  crypt->key,  /* derived key */
                                  crypt->iv);  /* initial vector */
    else
        ret = EVP_DecryptInit_ex (ctx,
                                  EVP_aes_256_cbc(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  crypt->key,  /* derived key */
                                  crypt->iv);  /* initial vector */

    if (ret == DEC_FAILURE) {
        EVP_CIPHER_CTX_free (ctx);
        return -1;
    }

    /* Allocating output buffer. */
    
    *data_out = (char *)g_malloc (in_len);

    if (*data_out == NULL) {
        seaf_warning ("failed to allocate the output buffer.\n");
        goto dec_error;
    }                

    int update_len, final_len;

    /* Do the decryption. */
    ret = EVP_DecryptUpdate (ctx,
                             (unsigned char*)*data_out,
                             &update_len,
                             (unsigned char*)data_in,
                             in_len);

    if (ret == DEC_FAILURE)
        goto dec_error;


    /* Finish the possible partial block. */
    ret = EVP_DecryptFinal_ex (ctx,
                               (unsigned char*)*data_out + update_len,
                               &final_len);

    *out_len = update_len + final_len;

    /* out_len should be smaller than in_len. */
    if (ret == DEC_FAILURE || *out_len > in_len)
        goto dec_error;

    EVP_CIPHER_CTX_free (ctx);
    
    return 0;

dec_error:

    EVP_CIPHER_CTX_free (ctx);

    *out_len = -1;
    if (*data_out != NULL)
        g_free (*data_out);

    *data_out = NULL;

    return -1;
    
}

#endif  /* USE_GPL_CRYPTO */
