/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <string.h>
#include <glib.h>

#include "rsa.h"
#include "utils.h"

RSA*
private_key_to_pub(RSA *priv)
{
    RSA *pub = RSA_new();

    pub->n = BN_dup(priv->n);
    pub->e = BN_dup(priv->e);

    return pub;
}


GString* public_key_to_gstring(const RSA *rsa)
{
    GString *buf = g_string_new(NULL);
    unsigned char *temp;
    char *coded;

    gsize len = BN_num_bytes(rsa->n);
    temp = malloc(len);
    BN_bn2bin(rsa->n, temp);
    coded = g_base64_encode(temp, len);
    g_string_append (buf, coded);
    g_string_append_c (buf, ' ');
    g_free(coded);
    
    len = BN_num_bytes(rsa->e);
    temp = realloc(temp, len);
    BN_bn2bin(rsa->e, temp);
    coded = g_base64_encode(temp, len);
    g_string_append (buf, coded);
    g_free(coded);

    free(temp);
    
    return buf;
}

void
public_key_append_to_gstring(const RSA *rsa, GString *buf)
{
    unsigned char *temp;
    char *coded;

    gsize len = BN_num_bytes(rsa->n);
    temp = malloc(len);
    BN_bn2bin(rsa->n, temp);
    coded = g_base64_encode(temp, len);
    g_string_append (buf, coded);
    g_string_append_c (buf, ' ');
    g_free(coded);
    
    len = BN_num_bytes(rsa->e);
    temp = realloc(temp, len);
    BN_bn2bin(rsa->e, temp);
    coded = g_base64_encode(temp, len);
    g_string_append (buf, coded);
    g_free(coded);

    free(temp);
}

RSA* public_key_from_string(char *str)
{
    char *p;
    unsigned char *num;
    gsize len;
    if (!str)
        return NULL;

    if ( !(p = strchr(str, ' ')) )
        return NULL;
    *p = '\0';

    RSA *key = RSA_new();

    num = g_base64_decode(str, &len);
    key->n = BN_bin2bn(num, len, NULL);
    if (!key->n)
        goto err;
    g_free(num);
    
    num = g_base64_decode(p+1, &len);
    key->e = BN_bin2bn(num, len, NULL);
    if (!key->e)
        goto err;
    g_free(num);

    *p = ' ';
    return key;
err:
    *p = ' ';
    RSA_free (key);
    g_free(num);
    return NULL;
}

unsigned char *
private_key_decrypt(RSA *key, unsigned char *data, int len, int *decrypt_len)
{
    int size;
    unsigned char *buf;

    size = RSA_size(key);
    buf = g_malloc(size);
    *decrypt_len = RSA_private_decrypt(len, data, buf, key, RSA_PKCS1_PADDING);

    return buf;
}

unsigned char *
public_key_encrypt(RSA *key, unsigned char *data, int len, int *encrypt_len)
{
    int size;
    unsigned char *buf;

    size = RSA_size(key);
    buf = g_malloc(size);
    *encrypt_len = RSA_public_encrypt(len, data, buf, key, RSA_PKCS1_PADDING);

    return buf;
}

char *
id_from_pubkey (RSA *pubkey)
{
    GString *buf;
    unsigned char sha1[20];
    char *id = g_malloc(41);

    buf = public_key_to_gstring (pubkey);
    calculate_sha1 (sha1, buf->str);
    sha1_to_hex (sha1, id);
    g_string_free (buf, TRUE);

    return id;
}

RSA *
generate_private_key(u_int bits)
{
	RSA *private = NULL;

	private = RSA_generate_key(bits, 35, NULL, NULL);
	if (private == NULL)
		g_error ("rsa_generate_private_key: key generation failed.");
	return private;
}
