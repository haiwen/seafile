/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*
  Description:
  
  The function pair "seafile_encrypt/seafile_decrypt" are used to
  encrypt/decrypt data in the seafile system, using AES 128 bit ecb
  algorithm provided by openssl.
*/  

#ifndef _SEAFILE_CRYPT_H
#define _SEAFILE_CRYPT_H

#include <openssl/aes.h>
#include <openssl/evp.h>


/* Block size, in bytes. For AES it can only be 16 bytes. */
#define BLK_SIZE 16
#define ENCRYPT_BLK_SIZE BLK_SIZE

struct SeafileCrypt {
    int version;
    unsigned char key[16];   /* set when enc_version >= 1 */
    unsigned char iv[16];
};

typedef struct SeafileCrypt SeafileCrypt;

SeafileCrypt *
seafile_crypt_new (int version, unsigned char *key, unsigned char *iv);

/*  
  @data_out: pointer to the output of the encrpyted/decrypted data,
  whose content must be freed by g_free when not used.

  @out_len: pointer to length of output, in bytes

  @data_in: address of input buffer

  @in_len: length of data to be encrpyted/decrypted, in bytes 

  @crypt: container of crypto info.
  
  RETURN VALUES:

  On success, 0 is returned, and the encrpyted/decrypted data is in
  *data_out, with out_len set to its length. On failure, -1 is returned
  and *data_out is set to NULL, with out_len set to -1;

  NOTE:

  In AES, padding is always used, so the output length of
  seafile_encrypt is always a multiple of BLK_SIZE(16 Bytes), and the
  input length of seafile_decrypt *must* be a multiple of BLK_SIZE.
  
*/

int
seafile_generate_enc_key (const char *data_in, int in_len, int version,
                          unsigned char *key, unsigned char *iv);

int
seafile_encrypt (char **data_out,
                 int *out_len,
                 const char *data_in,
                 const int in_len,
                 SeafileCrypt *crypt);


int
seafile_decrypt (char **data_out,
                 int *out_len,
                 const char *data_in,
                 const int in_len,
                 SeafileCrypt *crypt);

int
seafile_decrypt_init (EVP_CIPHER_CTX *ctx,
                      int version,
                      const unsigned char *key,
                      const unsigned char *iv);

#endif  /* _SEAFILE_CRYPT_H */
