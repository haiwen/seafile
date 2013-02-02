/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>
#include <glib.h>
#include "seafile-crypt.h"


/*
  The EVP_EncryptXXX and EVP_DecryptXXX series of functions have a
  weird choice of returned value.
*/
#define ENC_SUCCESS 1
#define ENC_FAILURE 0
#define DEC_SUCCESS 1
#define DEC_FAILURE 0

#define KEYGEN_ITERATION 1 << 19
/* truly random sequece read from /dev/urandom. */
static unsigned char salt[8] = { 0xda, 0x90, 0x45, 0xc3, 0x06, 0xc7, 0xcc, 0x26 };

SeafileCrypt *
seafile_crypt_new (int version, unsigned char *key, unsigned char *iv)
{
    SeafileCrypt *crypt = g_new0 (SeafileCrypt, 1);
    crypt->version = version;
    memcpy (crypt->key, key, 16);
    memcpy (crypt->iv, iv, 16);
    return crypt;
}

int
seafile_generate_enc_key (const char *data_in, int in_len, int version,
                          unsigned char *key, unsigned char *iv)
{
    if (version >= 1)
        return EVP_BytesToKey (EVP_aes_128_cbc(), /* cipher mode */
                               EVP_sha1(),        /* message digest */
                               salt,              /* salt */
                               (unsigned char*)data_in,
                               in_len,
                               KEYGEN_ITERATION,   /* iteration times */
                               key, /* the derived key */
                               iv); /* IV, initial vector */
    else
        return EVP_BytesToKey (EVP_aes_128_ecb(), /* cipher mode */
                               EVP_sha1(),        /* message digest */
                               NULL,              /* salt */
                               (unsigned char*)data_in,
                               in_len,
                               3,   /* iteration times */
                               key, /* the derived key */
                               iv); /* IV, initial vector */
}

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
        g_warning ("Invalid params.\n");
        return -1;
    }

    EVP_CIPHER_CTX ctx;
    int ret;
    int blks;

    /* Prepare CTX for encryption. */
    EVP_CIPHER_CTX_init (&ctx);

    if (crypt->version >= 1)
        ret = EVP_EncryptInit_ex (&ctx,
                                  EVP_aes_128_cbc(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  crypt->key,  /* derived key */
                                  crypt->iv);  /* initial vector */
    else
        ret = EVP_EncryptInit_ex (&ctx,
                                  EVP_aes_128_ecb(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  crypt->key,  /* derived key */
                                  crypt->iv);  /* initial vector */

    if (ret == ENC_FAILURE)
        return -1;

    /* Allocating output buffer. */
    
    /*
      For EVP symmetric encryption, padding is always used __even if__
      data size is a multiple of block size, in which case the padding
      length is the block size. so we have the following:
    */
    
    blks = (in_len / BLK_SIZE) + 1;

    *data_out = (char *)g_malloc (blks * BLK_SIZE);

    if (*data_out == NULL) {
        g_warning ("failed to allocate the output buffer.\n");
        goto enc_error;
    }                

    int update_len, final_len;

    /* Do the encryption. */
    ret = EVP_EncryptUpdate (&ctx,
                             (unsigned char*)*data_out,
                             &update_len,
                             (unsigned char*)data_in,
                             in_len);

    if (ret == ENC_FAILURE)
        goto enc_error;


    /* Finish the possible partial block. */
    ret = EVP_EncryptFinal_ex (&ctx,
                               (unsigned char*)*data_out + update_len,
                               &final_len);

    *out_len = update_len + final_len;

    /* out_len should be equal to the allocated buffer size. */
    if (ret == ENC_FAILURE || *out_len != (blks * BLK_SIZE))
        goto enc_error;
    
    EVP_CIPHER_CTX_cleanup (&ctx);

    return 0;

enc_error:

    EVP_CIPHER_CTX_cleanup (&ctx);

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

        g_warning ("Invalid param(s).\n");
        return -1;
    }

    EVP_CIPHER_CTX ctx;
    int ret;

    /* Prepare CTX for decryption. */
    EVP_CIPHER_CTX_init (&ctx);

    if (crypt->version >= 1)
        ret = EVP_DecryptInit_ex (&ctx,
                                  EVP_aes_128_cbc(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  crypt->key,  /* derived key */
                                  crypt->iv);  /* initial vector */
    else
        ret = EVP_DecryptInit_ex (&ctx,
                                  EVP_aes_128_ecb(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  crypt->key,  /* derived key */
                                  crypt->iv);  /* initial vector */

    if (ret == DEC_FAILURE)
        return -1;

    /* Allocating output buffer. */
    
    *data_out = (char *)g_malloc (in_len);

    if (*data_out == NULL) {
        g_warning ("failed to allocate the output buffer.\n");
        goto dec_error;
    }                

    int update_len, final_len;

    /* Do the decryption. */
    ret = EVP_DecryptUpdate (&ctx,
                             (unsigned char*)*data_out,
                             &update_len,
                             (unsigned char*)data_in,
                             in_len);

    if (ret == DEC_FAILURE)
        goto dec_error;


    /* Finish the possible partial block. */
    ret = EVP_DecryptFinal_ex (&ctx,
                               (unsigned char*)*data_out + update_len,
                               &final_len);

    *out_len = update_len + final_len;

    /* out_len should be smaller than in_len. */
    if (ret == DEC_FAILURE || *out_len > in_len)
        goto dec_error;

    EVP_CIPHER_CTX_cleanup (&ctx);
    
    return 0;

dec_error:

    EVP_CIPHER_CTX_cleanup (&ctx);

    *out_len = -1;
    if (*data_out != NULL)
        g_free (*data_out);

    *data_out = NULL;

    return -1;
    
}

int
seafile_decrypt_init (EVP_CIPHER_CTX *ctx,
                      int version,
                      const unsigned char *key,
                      const unsigned char *iv)
{
    int ret;

    /* Prepare CTX for decryption. */
    EVP_CIPHER_CTX_init (ctx);

    if (version >= 1)
        ret = EVP_DecryptInit_ex (ctx,
                                  EVP_aes_128_cbc(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  key,  /* derived key */
                                  iv);  /* initial vector */
    else
        ret = EVP_DecryptInit_ex (ctx,
                                  EVP_aes_128_ecb(), /* cipher mode */
                                  NULL, /* engine, NULL for default */
                                  key,  /* derived key */
                                  iv);  /* initial vector */

    if (ret == DEC_FAILURE)
        return -1;

    return 0;
}
