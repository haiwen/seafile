#ifndef BLOCK_TX_UTILS_H
#define BLOCK_TX_UTILS_H

#include <event2/buffer.h>
#include <event2/util.h>
#include <openssl/evp.h>

/* Common structures and contants shared by the client and server. */

/* We use AES 256 */
#define ENC_KEY_SIZE 32
#define ENC_BLOCK_SIZE 16

#define BLOCK_PROTOCOL_VERSION 2

enum {
    STATUS_OK = 0,
    STATUS_VERSION_MISMATCH,
    STATUS_BAD_REQUEST,
    STATUS_ACCESS_DENIED,
    STATUS_INTERNAL_SERVER_ERROR,
    STATUS_NOT_FOUND,
};

struct _HandshakeRequest {
    gint32 version;
    gint32 key_len;
    char enc_session_key[0];
} __attribute__((__packed__));

typedef struct _HandshakeRequest HandshakeRequest;

struct _HandshakeResponse {
    gint32 status;
    gint32 version;
} __attribute__((__packed__));

typedef struct _HandshakeResponse HandshakeResponse;

struct _AuthResponse {
    gint32 status;
} __attribute__((__packed__));

typedef struct _AuthResponse AuthResponse;

enum {
    REQUEST_COMMAND_GET = 0,
    REQUEST_COMMAND_PUT,
};

struct _RequestHeader {
    gint32 command;
    char block_id[40];
} __attribute__((__packed__));

typedef struct _RequestHeader RequestHeader;

struct _ResponseHeader {
    gint32 status;
} __attribute__((__packed__));

typedef struct _ResponseHeader ResponseHeader;

/* Utility functions for encryption. */

void
blocktx_generate_encrypt_key (unsigned char *session_key, int sk_len,
                              unsigned char *key, unsigned char *iv);

int
blocktx_encrypt_init (EVP_CIPHER_CTX *ctx,
                      const unsigned char *key,
                      const unsigned char *iv);

int
blocktx_decrypt_init (EVP_CIPHER_CTX *ctx,
                      const unsigned char *key,
                      const unsigned char *iv);

/*
 * Encrypted data is sent in "frames".
 * Format of a frame:
 *
 * length of data in the frame after encryption + encrypted data.
 *
 * Each frame can contain three types of contents:
 * 1. Auth request or response;
 * 2. Block request or response header;
 * 3. Block content.
 */

int
send_encrypted_data_frame_begin (evutil_socket_t data_fd,
                                 int frame_len);

int
send_encrypted_data (EVP_CIPHER_CTX *ctx,
                     evutil_socket_t data_fd,
                     const void *buf, int len);

int
send_encrypted_data_frame_end (EVP_CIPHER_CTX *ctx,
                               evutil_socket_t data_fd);

typedef int (*FrameContentCB) (char *, int, void *);

typedef int (*FrameFragmentCB) (char *, int, int, void *);

typedef struct _FrameParser {
    int enc_frame_len;

    unsigned char key[ENC_KEY_SIZE];
    unsigned char iv[ENC_BLOCK_SIZE];
    gboolean enc_init;
    EVP_CIPHER_CTX ctx;

    unsigned char key_v2[ENC_KEY_SIZE];
    unsigned char iv_v2[ENC_BLOCK_SIZE];

    int version;

    /* Used when parsing fragments */
    int remain;

    FrameContentCB content_cb;
    FrameFragmentCB fragment_cb;
    void *cbarg;
} FrameParser;

/* Handle entire frame all at once.
 * parser->content_cb() will be called after the entire frame is read.
 */
int
handle_one_frame (struct evbuffer *buf, FrameParser *parser);

/* Handle a frame fragment by fragment.
 * parser->fragment_cb() will be called when any amount data is read.
 */
int
handle_frame_fragments (struct evbuffer *buf, FrameParser *parser);

#endif
