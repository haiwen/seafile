/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_RSA_H
#define CCNET_RSA_H

#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

 
RSA* private_key_to_pub(RSA *priv);

GString* public_key_to_gstring(const RSA *rsa);
void public_key_append_to_gstring(const RSA *rsa, GString *buf);

RSA* public_key_from_string(char *str);

unsigned char* private_key_decrypt(RSA *key, unsigned char *data,
                                   int len, int *decrypt_len);

unsigned char* public_key_encrypt(RSA *key, unsigned char *data,
                                  int len, int *encrypt_len);


char *id_from_pubkey (RSA *pubkey);

RSA* generate_private_key(u_int bits);


#endif
