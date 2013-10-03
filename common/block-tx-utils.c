#include "common.h"
#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include "utils.h"
#include "block-tx-utils.h"

/* Utility functions for block transfer protocol. */

/* Encryption related functions. */

void
blocktx_generate_encrypt_key (unsigned char *session_key, int sk_len,
                              unsigned char *key, unsigned char *iv)
{
    EVP_BytesToKey (EVP_aes_256_cbc(), /* cipher mode */
                    EVP_sha1(),        /* message digest */
                    NULL,              /* salt */
                    session_key,
                    sk_len,
                    3,   /* iteration times */
                    key, /* the derived key */
                    iv); /* IV, initial vector */
}

int
blocktx_encrypt_init (EVP_CIPHER_CTX *ctx,
                      const unsigned char *key,
                      const unsigned char *iv)
{
    int ret;

    /* Prepare CTX for encryption. */
    EVP_CIPHER_CTX_init (ctx);

    ret = EVP_EncryptInit_ex (ctx,
                              EVP_aes_256_cbc(), /* cipher mode */
                              NULL, /* engine, NULL for default */
                              key,  /* derived key */
                              iv);  /* initial vector */
    if (ret == 0)
        return -1;

    return 0;
}

int
blocktx_decrypt_init (EVP_CIPHER_CTX *ctx,
                      const unsigned char *key,
                      const unsigned char *iv)
{
    int ret;

    /* Prepare CTX for decryption. */
    EVP_CIPHER_CTX_init (ctx);

    ret = EVP_DecryptInit_ex (ctx,
                              EVP_aes_256_cbc(), /* cipher mode */
                              NULL, /* engine, NULL for default */
                              key,  /* derived key */
                              iv);  /* initial vector */
    if (ret == 0)
        return -1;

    return 0;
}

/* Sending frame */

int
send_encrypted_data_frame_begin (evutil_socket_t data_fd,
                                 int frame_len)
{
    /* Compute data size after encryption.
     * Block size is 16 bytes and AES always add one padding block.
     */
    int enc_frame_len;

    enc_frame_len = ((frame_len >> 4) + 1) << 4;
    enc_frame_len = htonl (enc_frame_len);

    if (sendn (data_fd, &enc_frame_len, sizeof(int)) < 0) {
        seaf_warning ("Failed to send frame length: %s.\n",
                      evutil_socket_error_to_string(evutil_socket_geterror(data_fd)));
        return -1;
    }

    return 0;
}

int
send_encrypted_data (EVP_CIPHER_CTX *ctx,
                     evutil_socket_t data_fd,
                     const void *buf, int len)
{
    char out_buf[len + ENC_BLOCK_SIZE];
    int out_len;

    if (EVP_EncryptUpdate (ctx,
                           (unsigned char *)out_buf, &out_len,
                           (unsigned char *)buf, len) == 0) {
        seaf_warning ("Failed to encrypt data.\n");
        return -1;
    }

    if (sendn (data_fd, out_buf, out_len) < 0) {
        seaf_warning ("Failed to write data: %s.\n",
                      evutil_socket_error_to_string(evutil_socket_geterror(data_fd)));
        return -1;
    }

    return 0;
}

int
send_encrypted_data_frame_end (EVP_CIPHER_CTX *ctx,
                               evutil_socket_t data_fd)
{
    char out_buf[ENC_BLOCK_SIZE];
    int out_len;

    if (EVP_EncryptFinal_ex (ctx, (unsigned char *)out_buf, &out_len) == 0) {
        seaf_warning ("Failed to encrypt data.\n");
        return -1;
    }
    if (sendn (data_fd, out_buf, out_len) < 0) {
        seaf_warning ("Failed to write data: %s.\n",
                      evutil_socket_error_to_string(evutil_socket_geterror(data_fd)));
        return -1;
    }

    return 0;
}

/* Receiving frame */

static int
handle_frame_content (struct evbuffer *buf, FrameParser *parser)
{
    char *frame;
    EVP_CIPHER_CTX ctx;
    char *out;
    int outlen, outlen2;
    int ret = 0;

    struct evbuffer *input = buf;

    if (evbuffer_get_length (input) < parser->enc_frame_len)
        return 0;

    if (parser->version == 1)
        blocktx_decrypt_init (&ctx, parser->key, parser->iv);
    else if (parser->version == 2)
        blocktx_decrypt_init (&ctx, parser->key_v2, parser->iv_v2);

    frame = g_malloc (parser->enc_frame_len);
    out = g_malloc (parser->enc_frame_len + ENC_BLOCK_SIZE);

    evbuffer_remove (input, frame, parser->enc_frame_len);

    if (EVP_DecryptUpdate (&ctx,
                           (unsigned char *)out, &outlen,
                           (unsigned char *)frame,
                           parser->enc_frame_len) == 0) {
        seaf_warning ("Failed to decrypt frame content.\n");
        ret = -1;
        goto out;
    }

    if (EVP_DecryptFinal_ex (&ctx, (unsigned char *)(out + outlen), &outlen2) == 0)
    {
        seaf_warning ("Failed to decrypt frame content.\n");
        ret = -1;
        goto out;
    }

    ret = parser->content_cb (out, outlen + outlen2, parser->cbarg);

out:
    g_free (frame);
    g_free (out);
    parser->enc_frame_len = 0;
    EVP_CIPHER_CTX_cleanup (&ctx);
    return ret;
}

int
handle_one_frame (struct evbuffer *buf, FrameParser *parser)
{
    struct evbuffer *input = buf;

    if (!parser->enc_frame_len) {
        /* Read the length of the encrypted frame first. */
        if (evbuffer_get_length (input) < sizeof(int))
            return 0;

        int frame_len;
        evbuffer_remove (input, &frame_len, sizeof(int));
        parser->enc_frame_len = ntohl (frame_len);

        if (evbuffer_get_length (input) > 0)
            return handle_frame_content (buf, parser);

        return 0;
    } else {
        return handle_frame_content (buf, parser);
    }
}

static int
handle_frame_fragment_content (struct evbuffer *buf, FrameParser *parser)
{
    char *fragment = NULL, *out = NULL;
    int fragment_len, outlen;
    int ret = 0;

    struct evbuffer *input = buf;

    fragment_len = evbuffer_get_length (input);
    fragment = g_malloc (fragment_len);
    evbuffer_remove (input, fragment, fragment_len);

    out = g_malloc (fragment_len + ENC_BLOCK_SIZE);

    if (EVP_DecryptUpdate (&parser->ctx,
                           (unsigned char *)out, &outlen,
                           (unsigned char *)fragment, fragment_len) == 0) {
        seaf_warning ("Failed to decrypt frame fragment.\n");
        ret = -1;
        goto out;
    }

    ret = parser->fragment_cb (out, outlen, 0, parser->cbarg);
    if (ret < 0)
        goto out;

    parser->remain -= fragment_len;

    if (parser->remain <= 0) {
        if (EVP_DecryptFinal_ex (&parser->ctx,
                                 (unsigned char *)out,
                                 &outlen) == 0) {
            seaf_warning ("Failed to decrypt frame fragment.\n");
            ret = -1;
            goto out;
        }

        ret = parser->fragment_cb (out, outlen, 1, parser->cbarg);
        if (ret < 0)
            goto out;

        EVP_CIPHER_CTX_cleanup (&parser->ctx);
        parser->enc_init = FALSE;
        parser->enc_frame_len = 0;
    }

out:
    g_free (fragment);
    g_free (out);
    if (ret < 0) {
        EVP_CIPHER_CTX_cleanup (&parser->ctx);
        parser->enc_init = FALSE;
        parser->enc_frame_len = 0;
    }
    return ret;
}

int
handle_frame_fragments (struct evbuffer *buf, FrameParser *parser)
{
    struct evbuffer *input = buf;

    if (!parser->enc_frame_len) {
        /* Read the length of the encrypted frame first. */
        if (evbuffer_get_length (input) < sizeof(int))
            return 0;

        int frame_len;
        evbuffer_remove (input, &frame_len, sizeof(int));
        parser->enc_frame_len = ntohl (frame_len);
        parser->remain = parser->enc_frame_len;

        if (parser->version == 1)
            blocktx_decrypt_init (&parser->ctx, parser->key, parser->iv);
        else if (parser->version == 2)
            blocktx_decrypt_init (&parser->ctx, parser->key_v2, parser->iv_v2);
        parser->enc_init = TRUE;

        if (evbuffer_get_length (input) > 0)
            return handle_frame_fragment_content (buf, parser);

        return 0;
    } else {
        return handle_frame_fragment_content (buf, parser);
    }
}
