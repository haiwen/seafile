#include "common.h"
#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include "net.h"

#ifndef WIN32
#include <sys/select.h>
#endif
#include <event2/buffer.h>
#include <event2/util.h>

#include <ccnet.h>
#include <ccnet/job-mgr.h>

#include "seafile-session.h"
#include "block-tx-server.h"
#include "block-tx-utils.h"
#include "utils.h"

enum {
    RECV_STATE_HANDSHAKE = 0,
    RECV_STATE_AUTH,
    RECV_STATE_HEADER,
    RECV_STATE_CONTENT,
};

struct _BlockTxServer {
    evutil_socket_t data_fd;
    struct evbuffer *recv_buf;

    int recv_state;
    int session_key_len;
    int command;
    char curr_block_id[41];

    /* Used by put block */
    BlockHandle *block;

    unsigned char key[ENC_KEY_SIZE];
    unsigned char iv[ENC_BLOCK_SIZE];

    unsigned char key_v2[ENC_KEY_SIZE];
    unsigned char iv_v2[ENC_BLOCK_SIZE];

    FrameParser parser;

    gboolean break_loop;

    int version;

    char store_id[37];
    int repo_version;
};

typedef struct _BlockTxServer BlockTxServer;

/* Handshake */

static int
send_handshake_response (BlockTxServer *server, int status)
{
    HandshakeResponse rsp;

    rsp.status = htonl (status);
    rsp.version = htonl (BLOCK_PROTOCOL_VERSION);

    if (sendn (server->data_fd, &rsp, sizeof(rsp)) < 0) {
        seaf_warning ("Failed to send handshake response: %s.\n",
                      evutil_socket_error_to_string(evutil_socket_geterror(server->data_fd)));
        return -1;
    }

    return 0;
}

static void
init_frame_parser (BlockTxServer *server)
{
    FrameParser *parser = &server->parser;

    if (server->version == 1) {
        memcpy (parser->key, server->key, ENC_BLOCK_SIZE);
        memcpy (parser->iv, server->iv, ENC_BLOCK_SIZE);
    } else if (server->version == 2) {
        memcpy (parser->key_v2, server->key_v2, ENC_KEY_SIZE);
        memcpy (parser->iv_v2, server->iv_v2, ENC_BLOCK_SIZE);
    }

    parser->version = server->version;
    parser->cbarg = server;
}

static int
process_session_key (BlockTxServer *server, unsigned char *enc_session_key)
{
    char *enc_key_b64 = NULL, *key_b64 = NULL;
    unsigned char *session_key = NULL;
    gsize len;
    SearpcClient *client = NULL;
    int ret = 0;

    client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                             NULL,
                                             "ccnet-rpcserver");
    if (!client) {
        seaf_warning ("Failed to create rpc client.\n");
        send_handshake_response (server, STATUS_INTERNAL_SERVER_ERROR);
        ret = -1;
        goto out;
    }

    enc_key_b64 = g_base64_encode (enc_session_key, server->session_key_len);

    key_b64 = ccnet_privkey_decrypt (client, enc_key_b64);
    if (!key_b64) {
        seaf_warning ("Failed to decrypt session key.\n");
        send_handshake_response (server, STATUS_INTERNAL_SERVER_ERROR);
        ret = -1;
        goto out;
    }

    session_key = g_base64_decode (key_b64, &len);

    if (server->version == 1)
        blocktx_generate_encrypt_key (session_key, len, server->key, server->iv);
    else if (server->version == 2)
        blocktx_generate_encrypt_key (session_key, len, server->key_v2, server->iv_v2);

    init_frame_parser (server);

out:
    g_free (enc_key_b64);
    g_free (key_b64);
    g_free (session_key);
    ccnet_rpc_client_free (client);

    return ret;
}

static int
handle_auth_req_content_cb (char *content, int clen, void *cbarg);

#define MAX_SESSION_KEY_SIZE 1024

static int
handle_handshake_request (BlockTxServer *server)
{
    HandshakeRequest req;
    struct evbuffer *input = server->recv_buf;
    unsigned char *enc_session_key;

    if (!server->session_key_len) {
        if (evbuffer_get_length (input) < sizeof(req))
            return 0;

        evbuffer_remove (input, &req, sizeof(req));

        req.version = ntohl (req.version);
        server->version = MIN (req.version, BLOCK_PROTOCOL_VERSION);
        if (server->version != 1 && server->version != 2) {
            seaf_warning ("Bad block protocol version %d.\n", server->version);
            send_handshake_response (server, STATUS_VERSION_MISMATCH);
            return -1;
        }

        seaf_debug ("Block protocol version %d.\n", server->version);

        server->session_key_len = ntohl (req.key_len);
        if (server->session_key_len > MAX_SESSION_KEY_SIZE) {
            seaf_warning ("Encrypted session key is too long: %d.\n",
                          server->session_key_len);
            send_handshake_response (server, STATUS_BAD_REQUEST);
            return -1;
        }
    }

    if (evbuffer_get_length (input) < server->session_key_len)
        return 0;

    enc_session_key = g_malloc (server->session_key_len);

    evbuffer_remove (input, enc_session_key, server->session_key_len);

    if (process_session_key (server, enc_session_key) < 0) {
        g_free (enc_session_key);
        return -1;
    }
    g_free (enc_session_key);

    if (send_handshake_response (server, STATUS_OK) < 0)
        return -1;

    seaf_debug ("recv_state set to AUTH.\n");

    server->parser.content_cb = handle_auth_req_content_cb;
    server->recv_state = RECV_STATE_AUTH;

    return 0;
}

/* Authentication */

static int
send_auth_response (BlockTxServer *server, int status)
{
    AuthResponse rsp;
    EVP_CIPHER_CTX ctx;
    int ret = 0;

    rsp.status = htonl (status);

    if (server->version == 1)
        blocktx_encrypt_init (&ctx, server->key, server->iv);
    else if (server->version == 2)
        blocktx_encrypt_init (&ctx, server->key_v2, server->iv_v2);

    if (send_encrypted_data_frame_begin (server->data_fd, sizeof(rsp)) < 0) {
        seaf_warning ("Send auth response: failed to begin.\n");
        ret = -1;
        goto out;
    }

    if (send_encrypted_data (&ctx, server->data_fd, &rsp, sizeof(rsp)) < 0)
    {
        seaf_warning ("Send auth response: failed to send data.\n");
        ret = -1;
        goto out;
    }

    if (send_encrypted_data_frame_end (&ctx, server->data_fd) < 0) {
        seaf_warning ("Send auth response: failed to end.\n");
        ret = -1;
        goto out;
    }

out:
    EVP_CIPHER_CTX_cleanup (&ctx);
    return ret;
}

static int
handle_block_header_content_cb (char *content, int clen, void *cbarg);

static int
handle_auth_req_content_cb (char *content, int clen, void *cbarg)
{
    BlockTxServer *server = cbarg;
    char *session_token = content;
    SearpcClient *client = NULL;
    char repo_id[37];
    SeafRepo *repo;

    if (session_token[clen - 1] != '\0') {
        seaf_warning ("Invalid session token format.\n");
        send_auth_response (server, STATUS_BAD_REQUEST);
        return -1;
    }

    client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                             NULL,
                                             "ccnet-rpcserver");
    if (!client) {
        seaf_warning ("Failed to create rpc client.\n");
        send_auth_response (server, STATUS_INTERNAL_SERVER_ERROR);
        return -1;
    }

    if (seaf_token_manager_verify_token (seaf->token_mgr, client, NULL,
                                         session_token, repo_id) < 0) {
        seaf_warning ("Session token check failed.\n");
        send_auth_response (server, STATUS_ACCESS_DENIED);
        ccnet_rpc_client_free (client);
        return -1;
    }

    ccnet_rpc_client_free (client);

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %.8s.\n", repo_id);
        return -1;
    }
    memcpy (server->store_id, repo->store_id, 36);
    server->repo_version = repo->version;
    seaf_repo_unref (repo);

    if (send_auth_response (server, STATUS_OK) < 0)
        return -1;

    seaf_debug ("recv_state set to HEADER.\n");

    server->parser.content_cb = handle_block_header_content_cb;
    server->recv_state = RECV_STATE_HEADER;

    return 0;
}

static int
handle_auth_request (BlockTxServer *server)
{
    return handle_one_frame (server->recv_buf, &server->parser);
}

/* Block header */

static int
send_block_response_header (BlockTxServer *server, int status)
{
    ResponseHeader header;
    EVP_CIPHER_CTX ctx;
    int ret = 0;

    header.status = htonl (status);

    if (server->version == 1)
        blocktx_encrypt_init (&ctx, server->key, server->iv);
    else if (server->version == 2)
        blocktx_encrypt_init (&ctx, server->key_v2, server->iv_v2);

    if (send_encrypted_data_frame_begin (server->data_fd, sizeof(header)) < 0) {
        seaf_warning ("Send block response header %s: failed to begin.\n",
                      server->curr_block_id);
        ret = -1;
        goto out;
    }

    if (send_encrypted_data (&ctx, server->data_fd,
                             &header, sizeof(header)) < 0)
    {
        seaf_warning ("Send block response header %s: failed to send data.\n",
                      server->curr_block_id);
        ret = -1;
        goto out;
    }

    if (send_encrypted_data_frame_end (&ctx, server->data_fd) < 0) {
        seaf_warning ("Send block response header %s: failed to end.\n",
                      server->curr_block_id);
        ret = -1;
        goto out;
    }

out:
    EVP_CIPHER_CTX_cleanup (&ctx);
    return ret;
}

static int
send_block_content (BlockTxServer *server, int block_size);

static int
save_block_content_cb (char *content, int clen, int end, void *cbarg);

static int
handle_block_header_content_cb (char *content, int clen, void *cbarg)
{
    BlockTxServer *server = cbarg;
    RequestHeader *hdr;

    if (clen != sizeof(RequestHeader)) {
        seaf_warning ("Invalid block request header length %d.\n", clen);
        send_block_response_header (server, STATUS_BAD_REQUEST);
        return -1;
    }

    hdr = (RequestHeader *)content;
    hdr->command = ntohl (hdr->command);

    if (hdr->command != REQUEST_COMMAND_GET &&
        hdr->command != REQUEST_COMMAND_PUT) {
        seaf_warning ("Unknow command %d.\n", hdr->command);
        send_block_response_header (server, STATUS_BAD_REQUEST);
        return -1;
    }

    server->command = hdr->command;
    memcpy (server->curr_block_id, hdr->block_id, 40);

    if (server->command == REQUEST_COMMAND_GET) {
        BlockMetadata *md;
        int block_size;

        seaf_debug ("Received GET request for block %s.\n", server->curr_block_id);

        md = seaf_block_manager_stat_block (seaf->block_mgr,
                                            server->store_id,
                                            server->repo_version,
                                            server->curr_block_id);
        if (!md) {
            seaf_warning ("Failed to stat block %s:%s.\n",
                          server->store_id, server->curr_block_id);
            send_block_response_header (server, STATUS_NOT_FOUND);
            return -1;
        }
        block_size = md->size;
        g_free (md);

        if (send_block_response_header (server, STATUS_OK) < 0)
            return -1;

        if (send_block_content (server, block_size) < 0)
            return -1;

        seaf_debug ("recv_state set to HEADER.\n");

        server->recv_state = RECV_STATE_HEADER;
    } else {
        seaf_debug ("Received PUT request for block %s.\n", server->curr_block_id);

        server->block = seaf_block_manager_open_block (seaf->block_mgr,
                                                       server->store_id,
                                                       server->repo_version,
                                                       server->curr_block_id,
                                                       BLOCK_WRITE);
        if (!server->block) {
            seaf_warning ("Failed to open block %s:%s for write.\n",
                          server->store_id, server->curr_block_id);
            send_block_response_header (server, STATUS_INTERNAL_SERVER_ERROR);
            return -1;
        }

        seaf_debug ("recv_state set to CONTENT.\n");

        server->parser.fragment_cb = save_block_content_cb;
        server->recv_state = RECV_STATE_CONTENT;
    }

    return 0;
}

static int
handle_block_header (BlockTxServer *server)
{
    return handle_one_frame (server->recv_buf, &server->parser);
}

/* Block content */

#define SEND_BUFFER_SIZE 4096

static int
send_encrypted_block (BlockTxServer *server,
                      BlockHandle *handle,
                      const char *block_id,
                      int size)
{
    int n, remain;
    int ret = 0;
    EVP_CIPHER_CTX ctx;
    char send_buf[SEND_BUFFER_SIZE];

    if (server->version == 1)
        blocktx_encrypt_init (&ctx, server->key, server->iv);
    else if (server->version == 2)
        blocktx_encrypt_init (&ctx, server->key_v2, server->iv_v2);

    if (send_encrypted_data_frame_begin (server->data_fd, size) < 0) {
        seaf_warning ("Send block %s: failed to begin.\n", block_id);
        ret = -1;
        goto out;
    }

    remain = size;
    while (remain > 0) {
        n = seaf_block_manager_read_block (seaf->block_mgr,
                                           handle,
                                           send_buf, SEND_BUFFER_SIZE);
        if (n < 0) {
            seaf_warning ("Failed to read block %s.\n", block_id);
            ret = -1;
            goto out;
        }

        if (send_encrypted_data (&ctx, server->data_fd, send_buf, n) < 0) {
            seaf_warning ("Send block %s: failed to send data.\n", block_id);
            ret = -1;
            goto out;
        }

        remain -= n;
    }

    if (send_encrypted_data_frame_end (&ctx, server->data_fd) < 0) {
        seaf_warning ("Send block %s: failed to end.\n", block_id);
        ret = -1;
        goto out;
    }

    seaf_debug ("Send block %s done.\n", server->curr_block_id);

out:
    EVP_CIPHER_CTX_cleanup (&ctx);
    return ret;
}

static int
send_block_content (BlockTxServer *server, int block_size)
{
    BlockHandle *handle = NULL;
    int ret = 0;

    handle = seaf_block_manager_open_block (seaf->block_mgr,
                                            server->store_id,
                                            server->repo_version,
                                            server->curr_block_id,
                                            BLOCK_READ);
    if (!handle) {
        seaf_warning ("Failed to open block %s:%s.\n",
                      server->store_id, server->curr_block_id);
        return -1;
    }

    ret = send_encrypted_block (server, handle, server->curr_block_id, block_size);

    seaf_block_manager_close_block (seaf->block_mgr, handle);
    seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
    return ret;
}

static int
save_block_content_cb (char *content, int clen, int end, void *cbarg)
{
    BlockTxServer *server = cbarg;
    int n;

    n = seaf_block_manager_write_block (seaf->block_mgr, server->block,
                                        content, clen);
    if (n < 0) {
        seaf_warning ("Failed to write block %s.\n", server->curr_block_id);
        send_block_response_header (server, STATUS_INTERNAL_SERVER_ERROR);
        return -1;
    }

    if (end) {
        if (seaf_block_manager_close_block (seaf->block_mgr, server->block) < 0) {
            seaf_warning ("Failed to close block %s.\n", server->curr_block_id);
            send_block_response_header (server, STATUS_INTERNAL_SERVER_ERROR);
            return -1;
        }

        if (seaf_block_manager_commit_block (seaf->block_mgr, server->block) < 0) {
            seaf_warning ("Failed to commit block %s.\n", server->curr_block_id);
            send_block_response_header (server, STATUS_INTERNAL_SERVER_ERROR);
            return -1;
        }

        seaf_block_manager_block_handle_free (seaf->block_mgr, server->block);
        /* Set this handle to invalid. */
        server->block = NULL;

        send_block_response_header (server, STATUS_OK);

        seaf_debug ("Receive block %s done.\n", server->curr_block_id);
        seaf_debug ("recv_state set to HEADER.\n");

        server->recv_state = RECV_STATE_HEADER;
    }

    return 0;
}

static int
handle_block_content (BlockTxServer *server)
{
    return handle_frame_fragments (server->recv_buf, &server->parser);
}

static void
recv_data_cb (BlockTxServer *server)
{
    int ret = 0;

    /* Let evbuffer determine how much data can be read. */
    int n = evbuffer_read (server->recv_buf, server->data_fd, -1);
    if (n == 0) {
        seaf_debug ("Data connection is closed by the client. Transfer done.\n");
        server->break_loop = TRUE;
        return;
    } else if (n < 0) {
        seaf_warning ("Read data connection error: %s.\n",
                      evutil_socket_error_to_string(evutil_socket_geterror(server->data_fd)));
        server->break_loop = TRUE;
        return;
    }

    switch (server->recv_state) {
    case RECV_STATE_HANDSHAKE:
        ret = handle_handshake_request (server);
        break;
    case RECV_STATE_AUTH:
        ret = handle_auth_request (server);
        break;
    case RECV_STATE_HEADER:
        ret = handle_block_header (server);
        if (ret < 0)
            break;

        if (server->recv_state == RECV_STATE_CONTENT &&
            server->command == REQUEST_COMMAND_PUT)
            ret = handle_block_content (server);

        break;
    case RECV_STATE_CONTENT:
        ret = handle_block_content (server);
        break;
    }

    if (ret < 0)
        server->break_loop = TRUE;
}

#define BLOCKTX_TIMEOUT 30

static void
server_thread_loop (BlockTxServer *server)
{
    fd_set fds;
    struct timeval tv = { BLOCKTX_TIMEOUT, 0 };
    int rc;

    while (1) {
        FD_ZERO (&fds);
        FD_SET (server->data_fd, &fds);
        tv.tv_sec = BLOCKTX_TIMEOUT;
        tv.tv_usec = 0;

        rc = select (server->data_fd + 1, &fds, NULL, NULL, &tv);
        if (rc < 0 && errno == EINTR) {
            continue;
        } else if (rc < 0) {
            seaf_warning ("select error: %s.\n", strerror(errno));
            break;
        }

        if (rc == 0) {
            seaf_warning ("Recv block timeout.\n");
            break;
        }

        if (FD_ISSET (server->data_fd, &fds)) {
            recv_data_cb (server);
            if (server->break_loop)
                break;
        }
    }
}

static void *
block_tx_server_thread (void *vdata)
{
    BlockTxServer *server = vdata;

    server->recv_buf = evbuffer_new ();

    server_thread_loop (server);

    if (server->block) {
        seaf_block_manager_close_block (seaf->block_mgr, server->block);
        seaf_block_manager_block_handle_free (seaf->block_mgr, server->block);
    }

    if (server->parser.enc_init)
        EVP_CIPHER_CTX_cleanup (&server->parser.ctx);

    evbuffer_free (server->recv_buf);
    evutil_closesocket (server->data_fd);

    return vdata;
}

static void
block_tx_server_thread_done (void *vdata)
{
    BlockTxServer *server = vdata;

    g_free (server);
}

int
block_tx_server_start (evutil_socket_t data_fd)
{
    BlockTxServer *server = g_new0 (BlockTxServer, 1);
    int ret = 0;

    int val = 1;
    ev_socklen_t optlen = sizeof(int);
    setsockopt (data_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, optlen);

    server->data_fd = data_fd;

    ret = ccnet_job_manager_schedule_job (seaf->job_mgr,
                                          block_tx_server_thread,
                                          block_tx_server_thread_done,
                                          server);
    if (ret < 0) {
        seaf_warning ("Failed to start block tx server thread.\n");
        return -1;
    }

    return 0;
}
