/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include "net.h"

#ifndef WIN32
#include <sys/select.h>
#endif
#include <event2/buffer.h>
#include <event2/util.h>

#include <ccnet/job-mgr.h>

#include "seafile-session.h"
#include "block-tx-client.h"
#include "block-tx-utils.h"
#include "utils.h"

/*
 * Handshake:
 * 
 * protocol-signature + version + session-key(encrypted with RSA public key)
 * -------------------------------->
 *
 * OK + version
 * <-------------------------------
 *
 * Following communication is encrypted with session-key
 *
 * session-token for authentication
 * -------------------------------->
 *
 * OK
 * <--------------------------------
 *
 * Reqeust header + content
 * --------------------------------->
 *
 * Response header + content
 * <--------------------------------
 *
 * ... ...
 *
 * Connection closed
 */

enum {
    RECV_STATE_HANDSHAKE = 0,
    RECV_STATE_AUTH,
    RECV_STATE_HEADER,
    RECV_STATE_CONTENT,
    RECV_STATE_DONE,
};

struct _BlockTxClient {
    BlockTxInfo *info;
    BlockTxClientDoneCB cb;

    evutil_socket_t data_fd;
    struct evbuffer *recv_buf;

    int recv_state;
    char *curr_block_id;

    /* Used by get block */
    BlockHandle *block;

    unsigned char key[ENC_KEY_SIZE];
    unsigned char iv[ENC_BLOCK_SIZE];

    unsigned char key_v2[ENC_KEY_SIZE];
    unsigned char iv_v2[ENC_BLOCK_SIZE];

    FrameParser parser;

    gboolean break_loop;

    int version;
};

typedef struct _BlockTxClient BlockTxClient;

/* Connection establishment. */

static int
dns_lookup (const char *addr_str, struct sockaddr_in *sa, ev_socklen_t *sa_len)
{
    struct evutil_addrinfo hints;
    struct evutil_addrinfo *answer = NULL;
    int err;

    /* Build the hints to tell getaddrinfo how to act. */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* only use IPv4 now. */
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP; /* We want a TCP socket */
    /* Only return addresses we can use. */
    hints.ai_flags = EVUTIL_AI_ADDRCONFIG;

    /* Look up the hostname. */
    err = evutil_getaddrinfo(addr_str, NULL, &hints, &answer);
    if (err != 0) {
          seaf_warning("Error while resolving '%s': %s\n",
                       addr_str, evutil_gai_strerror(err));
          return -1;
    }

    *sa = *((struct sockaddr_in *)answer->ai_addr);
    *sa_len = (ev_socklen_t)answer->ai_addrlen;

    evutil_freeaddrinfo (answer);
    return 0;
}

static evutil_socket_t
connect_chunk_server (ChunkServer *cs)
{
    struct sockaddr_in sa;
    ev_socklen_t sa_len;
    evutil_socket_t data_fd;
    ev_socklen_t optlen;

    if (dns_lookup (cs->addr, &sa, &sa_len) < 0) {
        return -1;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(cs->port);

    data_fd = socket (AF_INET, SOCK_STREAM, 0);
    if (data_fd < 0) {
        seaf_warning ("socket error: %s.\n", strerror(errno));
        return -1;
    }

#ifdef WIN32
    /* Set large enough TCP buffer size.
     * This greatly enhances sync speed for high latency network.
     * Windows by default use 8KB buffers, which is too small for such case.
     * Linux has auto-tuning for TCP buffers, so don't need to set manually.
     * OSX is TBD.
     */

#define DEFAULT_SNDBUF_SIZE (1 << 16) /* 64KB */

    /* Set send buffer size. */
    int sndbuf_size;
    optlen = sizeof(int);
    getsockopt (data_fd, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf_size, &optlen);

    if (sndbuf_size < DEFAULT_SNDBUF_SIZE) {
        sndbuf_size = DEFAULT_SNDBUF_SIZE;
        optlen = sizeof(int);
        setsockopt (data_fd, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf_size, optlen);
    }
#endif

    /* Disable Nagle's algorithm. */
    int val = 1;
    optlen = sizeof(int);
    setsockopt (data_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, optlen);

    if (connect (data_fd, (struct sockaddr *)&sa, sa_len) < 0) {
        seaf_warning ("connect error: %s.\n",
                      evutil_socket_error_to_string(evutil_socket_geterror(data_fd)));
        evutil_closesocket (data_fd);
        return -1;
    }

    return data_fd;
}

/* Handshake */

static int
send_handshake (evutil_socket_t data_fd, BlockTxInfo *info)
{
    HandshakeRequest *req;

    if (sendn (data_fd, BLOCK_PROTOCOL_SIGNATURE, 37) < 0) {
        seaf_warning ("Failed to send protocol signature: %s.\n",
                      evutil_socket_error_to_string(evutil_socket_geterror(data_fd)));
        info->result = BLOCK_CLIENT_NET_ERROR;
        return -1;
    }

    int req_size = sizeof(HandshakeRequest) + info->enc_key_len;
    req = (HandshakeRequest *) g_malloc (req_size);
    req->version = htonl(BLOCK_PROTOCOL_VERSION);
    req->key_len = htonl(info->enc_key_len);
    memcpy (req->enc_session_key, info->enc_session_key, info->enc_key_len);

    if (sendn (data_fd, req, req_size) < 0) {
        seaf_warning ("Failed to send handshake: %s.\n",
                      evutil_socket_error_to_string(evutil_socket_geterror(data_fd)));
        info->result = BLOCK_CLIENT_NET_ERROR;
        g_free (req);
        return -1;
    }

    g_free (req);

    return 0;
}

static void
init_frame_parser (BlockTxClient *client)
{
    FrameParser *parser = &client->parser;

    if (client->version == 1) {
        memcpy (parser->key, client->key, ENC_BLOCK_SIZE);
        memcpy (parser->iv, client->iv, ENC_BLOCK_SIZE);
    } else if (client->version == 2) {
        memcpy (parser->key_v2, client->key_v2, ENC_KEY_SIZE);
        memcpy (parser->iv_v2, client->iv_v2, ENC_BLOCK_SIZE);
    }

    parser->version = client->version;
    parser->cbarg = client;
}

static int
send_authentication (BlockTxClient *client);

static int
handle_handshake_response (BlockTxClient *client)
{
    BlockTxInfo *info = client->info;
    struct evbuffer *input = client->recv_buf;
    HandshakeResponse rsp;

    if (evbuffer_get_length (input) < sizeof(rsp))
        return 0;

    evbuffer_remove (input, &rsp, sizeof(rsp));

    rsp.status = ntohl(rsp.status);
    rsp.version = ntohl(rsp.version);

    if (rsp.status == STATUS_OK) {
        seaf_debug ("Handshake OK.\n");

        client->version = MIN (rsp.version, BLOCK_PROTOCOL_VERSION);

        if (client->version == 1)
            blocktx_generate_encrypt_key (info->session_key, sizeof(info->session_key),
                                          client->key, client->iv);
        else if (client->version == 2)
            blocktx_generate_encrypt_key (info->session_key, sizeof(info->session_key),
                                          client->key_v2, client->iv_v2);
        else {
            seaf_warning ("Bad block protocol version %d.\n", rsp.version);
            info->result = BLOCK_CLIENT_FAILED;
            return -1;
        }

        seaf_debug ("Block protocol version %d.\n", client->version);

        init_frame_parser (client);

        if (send_authentication (client) < 0)
            return -1;

        return 0;
    } else if (rsp.status == STATUS_VERSION_MISMATCH) {
        seaf_warning ("The server refuse to accpet protocol version %d.\n"
                      "Remote version is %d.\n",
                      BLOCK_PROTOCOL_VERSION, rsp.version);
        /* this is a hard error. */
        info->result = BLOCK_CLIENT_FAILED;
        return -1;
    } else if (rsp.status == STATUS_INTERNAL_SERVER_ERROR) {
        seaf_warning ("Internal server error.\n");
        info->result = BLOCK_CLIENT_SERVER_ERROR;
        return -1;
    }

    seaf_warning ("Bad status code %d in handshake.\n", rsp.status);
    info->result = BLOCK_CLIENT_FAILED;
    return -1;
}

/* Authentication */

static int
transfer_next_block (BlockTxClient *client);

static int
handle_auth_rsp_content_cb (char *content, int clen, void *cbarg)
{
    BlockTxClient *client = cbarg;
    AuthResponse *rsp;

    if (clen != sizeof(AuthResponse)) {
        seaf_warning ("Invalid auth respnose length %d.\n", clen);
        client->info->result = BLOCK_CLIENT_FAILED;
        return -1;
    }

    rsp = (AuthResponse *)content;
    rsp->status = ntohl (rsp->status);

    if (rsp->status == STATUS_OK) {
        seaf_debug ("Auth OK.\n");

        if (!client->info->transfer_once) {
            int rsp = BLOCK_CLIENT_READY;
            pipewrite (client->info->done_pipe[1], &rsp, sizeof(rsp));
        }

        /* If in interactive mode, wait for TRANSFER command to start transfer. */
        if (client->info->transfer_once)
            return transfer_next_block (client);
    } else if (rsp->status == STATUS_ACCESS_DENIED) {
        seaf_warning ("Authentication failed.\n");
        /* this is a hard error. */
        client->info->result = BLOCK_CLIENT_FAILED;
        return -1;
    } else if (rsp->status == STATUS_INTERNAL_SERVER_ERROR) {
        seaf_warning ("Server error when handling auth.\n");
        client->info->result = BLOCK_CLIENT_SERVER_ERROR;
        return -1;
    } else {
        seaf_warning ("Bad status code %d in handshake.\n", rsp->status);
        client->info->result = BLOCK_CLIENT_FAILED;
        return -1;
    }

    return 0;
}

static int
handle_auth_response (BlockTxClient *client)
{
    return handle_one_frame (client->recv_buf, &client->parser);
}

static int
send_authentication (BlockTxClient *client)
{
    TransferTask *task = client->info->task;
    EVP_CIPHER_CTX ctx;
    int ret = 0;

    if (client->version == 1)
        blocktx_encrypt_init (&ctx, client->key, client->iv);
    else if (client->version == 2)
        blocktx_encrypt_init (&ctx, client->key_v2, client->iv_v2);

    seaf_debug ("session token length is %d.\n", strlen(task->session_token));

    if (send_encrypted_data_frame_begin (client->data_fd,
                                         strlen(task->session_token) + 1) < 0) {
        seaf_warning ("Send auth request: failed to begin.\n");
        client->info->result = BLOCK_CLIENT_NET_ERROR;
        ret = -1;
        goto out;
    }

    if (send_encrypted_data (&ctx, client->data_fd,
                             task->session_token,
                             strlen(task->session_token) + 1) < 0)
    {
        seaf_warning ("Send auth request: failed to send data.\n");
        client->info->result = BLOCK_CLIENT_NET_ERROR;
        ret = -1;
        goto out;
    }

    if (send_encrypted_data_frame_end (&ctx, client->data_fd) < 0) {
        seaf_warning ("Send auth request: failed to end.\n");
        client->info->result = BLOCK_CLIENT_NET_ERROR;
        ret = -1;
        goto out;
    }

    seaf_debug ("recv_state set to AUTH.\n");

    client->parser.content_cb = handle_auth_rsp_content_cb;
    client->recv_state = RECV_STATE_AUTH;

out:
    EVP_CIPHER_CTX_cleanup (&ctx);
    return ret;
}

/* Block header */

static int
send_block_header (BlockTxClient *client, int command)
{
    RequestHeader header;
    EVP_CIPHER_CTX ctx;
    int ret = 0;

    header.command = htonl (command);
    memcpy (header.block_id, client->curr_block_id, 40);

    if (client->version == 1)
        blocktx_encrypt_init (&ctx, client->key, client->iv);
    else if (client->version == 2)
        blocktx_encrypt_init (&ctx, client->key_v2, client->iv_v2);

    if (send_encrypted_data_frame_begin (client->data_fd, sizeof(header)) < 0) {
        seaf_warning ("Send block header %s: failed to begin.\n",
                      client->curr_block_id);
        client->info->result = BLOCK_CLIENT_NET_ERROR;
        ret = -1;
        goto out;
    }

    if (send_encrypted_data (&ctx, client->data_fd,
                             &header, sizeof(header)) < 0)
    {
        seaf_warning ("Send block header %s: failed to send data.\n",
                      client->curr_block_id);
        client->info->result = BLOCK_CLIENT_NET_ERROR;
        ret = -1;
        goto out;
    }

    if (send_encrypted_data_frame_end (&ctx, client->data_fd) < 0) {
        seaf_warning ("Send block header %s: failed to end.\n",
                      client->curr_block_id);
        client->info->result = BLOCK_CLIENT_NET_ERROR;
        ret = -1;
        goto out;
    }

out:
    EVP_CIPHER_CTX_cleanup (&ctx);
    return ret;
}

static int
handle_block_header_content_cb (char *content, int clen, void *cbarg)
{
    BlockTxClient *client = cbarg;
    ResponseHeader *hdr;
    TransferTask *task = client->info->task;

    if (clen != sizeof(ResponseHeader)) {
        seaf_warning ("Invalid block response header length %d.\n", clen);
        client->info->result = BLOCK_CLIENT_FAILED;
        return -1;
    }

    hdr = (ResponseHeader *)content;
    hdr->status = ntohl (hdr->status);

    if (task->type == TASK_TYPE_UPLOAD) {
        switch (hdr->status) {
        case STATUS_OK:
            seaf_debug ("Put block %s succeeded.\n", client->curr_block_id);

            if (transfer_next_block (client) < 0)
                return -1;

            return 0;
        case STATUS_INTERNAL_SERVER_ERROR:
            client->info->result = BLOCK_CLIENT_SERVER_ERROR;
            return -1;
        default:
            seaf_warning ("Unexpected response: %d.\n", hdr->status);
            client->info->result = BLOCK_CLIENT_FAILED;
            return -1;
        }
    } else {
        switch (hdr->status) {
        case STATUS_OK:
            client->block = seaf_block_manager_open_block (seaf->block_mgr,
                                                           task->repo_id,
                                                           task->repo_version,
                                                           client->curr_block_id,
                                                           BLOCK_WRITE);
            if (!client->block) {
                seaf_warning ("Failed to open block %s for write.\n",
                              client->curr_block_id);
                client->info->result = BLOCK_CLIENT_FAILED;
                return -1;
            }

            seaf_debug ("recv_state set to CONTENT.\n");

            client->recv_state = RECV_STATE_CONTENT;

            return 0;
        case STATUS_INTERNAL_SERVER_ERROR:
            client->info->result = BLOCK_CLIENT_SERVER_ERROR;
            return -1;
        case STATUS_NOT_FOUND:
            seaf_warning ("Block %s is not found on server.\n",
                          client->curr_block_id);
            client->info->result = BLOCK_CLIENT_FAILED;
            return -1;
        default:
            seaf_warning ("Unexpected response: %d.\n", hdr->status);
            client->info->result = BLOCK_CLIENT_FAILED;
            return -1;
        }
    }
}

static int
handle_block_header (BlockTxClient *client)
{
    return handle_one_frame (client->recv_buf, &client->parser);
}

/* Block content */

#define SEND_BUFFER_SIZE 4096

static int
send_encrypted_block (BlockTxClient *client,
                      BlockHandle *handle,
                      const char *block_id)
{
    BlockTxInfo *info = client->info;
    BlockMetadata *md;
    int size, n, remain;
    int ret = 0;
    EVP_CIPHER_CTX ctx;
    char send_buf[SEND_BUFFER_SIZE];

    md = seaf_block_manager_stat_block_by_handle (seaf->block_mgr, handle);
    if (!md) {
        seaf_warning ("Failed to stat block %s.\n", block_id);
        client->info->result = BLOCK_CLIENT_FAILED;
        ret = -1;
        goto out;
    }
    size = md->size;
    g_free (md);

    if (client->version == 1)
        blocktx_encrypt_init (&ctx, client->key, client->iv);
    else if (client->version == 2)
        blocktx_encrypt_init (&ctx, client->key_v2, client->iv_v2);

    if (send_encrypted_data_frame_begin (client->data_fd, size) < 0) {
        seaf_warning ("Send block %s: failed to begin.\n", block_id);
        info->result = BLOCK_CLIENT_NET_ERROR;
        ret = -1;
        goto out;
    }

    remain = size;
    while (remain > 0) {
        if (info->task->state == TASK_STATE_CANCELED) {
            info->result = BLOCK_CLIENT_CANCELED;
            ret = -1;
            goto out;
        }

        n = seaf_block_manager_read_block (seaf->block_mgr,
                                           handle,
                                           send_buf, SEND_BUFFER_SIZE);
        if (n < 0) {
            seaf_warning ("Failed to read block %s.\n", block_id);
            info->result = BLOCK_CLIENT_FAILED;
            ret = -1;
            goto out;
        }

        if (send_encrypted_data (&ctx, client->data_fd, send_buf, n) < 0) {
            seaf_warning ("Send block %s: failed to send data.\n", block_id);
            info->result = BLOCK_CLIENT_NET_ERROR;
            ret = -1;
            goto out;
        }

        /* Update global transferred bytes. */
        g_atomic_int_add (&(info->task->tx_bytes), n);
        g_atomic_int_add (&(seaf->sync_mgr->sent_bytes), n);

        /* If uploaded bytes exceeds the limit, wait until the counter
         * is reset. We check the counter every 100 milliseconds, so we
         * can waste up to 100 milliseconds without sending data after
         * the counter is reset.
         */
        while (1) {
            gint sent = g_atomic_int_get(&(seaf->sync_mgr->sent_bytes));
            if (seaf->sync_mgr->upload_limit > 0 &&
                sent > seaf->sync_mgr->upload_limit)
                /* 100 milliseconds */
                g_usleep (100000);
            else
                break;
        }

        remain -= n;
    }

    if (send_encrypted_data_frame_end (&ctx, client->data_fd) < 0) {
        seaf_warning ("Send block %s: failed to end.\n", block_id);
        info->result = BLOCK_CLIENT_NET_ERROR;
        ret = -1;
        goto out;
    }

out:
    EVP_CIPHER_CTX_cleanup (&ctx);
    return ret;
}

static int
send_block_content (BlockTxClient *client)
{
    TransferTask *task = client->info->task;
    BlockHandle *handle = NULL;
    int ret = 0;

    handle = seaf_block_manager_open_block (seaf->block_mgr,
                                            task->repo_id,
                                            task->repo_version,
                                            client->curr_block_id,
                                            BLOCK_READ);
    if (!handle) {
        seaf_warning ("Failed to open block %s.\n", client->curr_block_id);
        client->info->result = BLOCK_CLIENT_FAILED;
        return -1;
    }

    ret = send_encrypted_block (client, handle, client->curr_block_id);

    seaf_block_manager_close_block (seaf->block_mgr, handle);
    seaf_block_manager_block_handle_free (seaf->block_mgr, handle);
    return ret;
}

static int
save_block_content_cb (char *content, int clen, int end, void *cbarg)
{
    BlockTxClient *client = cbarg;
    TransferTask *task = client->info->task;
    int n;

    n = seaf_block_manager_write_block (seaf->block_mgr, client->block,
                                        content, clen);
    if (n < 0) {
        seaf_warning ("Failed to write block %s.\n", client->curr_block_id);
        client->info->result = BLOCK_CLIENT_FAILED;
        return -1;
    }

    /* Update global transferred bytes. */
    g_atomic_int_add (&(task->tx_bytes), clen);
    g_atomic_int_add (&(seaf->sync_mgr->recv_bytes), clen);

    while (1) {
        gint recv_bytes = g_atomic_int_get (&(seaf->sync_mgr->recv_bytes));
        if (seaf->sync_mgr->download_limit > 0 &&
            recv_bytes > seaf->sync_mgr->download_limit) {
            g_usleep (100000);
        } else {
            break;
        }
    }

    if (end) {
        seaf_block_manager_close_block (seaf->block_mgr, client->block);

        if (seaf_block_manager_commit_block (seaf->block_mgr, client->block) < 0) {
            seaf_warning ("Failed to commit block %s.\n", client->curr_block_id);
            client->info->result = BLOCK_CLIENT_FAILED;
            return -1;
        }

        seaf_block_manager_block_handle_free (seaf->block_mgr, client->block);
        /* Set this handle to invalid. */
        client->block = NULL;

        seaf_debug ("Get block %s succeeded.\n", client->curr_block_id);

        if (transfer_next_block (client) < 0)
            return -1;
    }

    return 0;
}

static int
handle_block_content (BlockTxClient *client)
{
    return handle_frame_fragments (client->recv_buf, &client->parser);
}

static int
transfer_next_block (BlockTxClient *client)
{
    TransferTask *task = client->info->task;

    if (client->curr_block_id) {
        g_queue_pop_head (task->block_ids);
        g_free (client->curr_block_id);
        client->curr_block_id = NULL;
    }

    if (g_queue_get_length (task->block_ids) == 0) {
        seaf_debug ("Transfer blocks done.\n");
        client->info->result = BLOCK_CLIENT_SUCCESS;
        client->break_loop = TRUE;
        return 0;
    }

    client->curr_block_id = g_queue_peek_head (task->block_ids);

    if (task->type == TASK_TYPE_UPLOAD) {
        seaf_debug ("Put block %s.\n", client->curr_block_id);

        if (send_block_header (client, REQUEST_COMMAND_PUT) < 0) {
            seaf_warning ("Failed to send block header for PUT %s.\n",
                          client->curr_block_id);
            return -1;
        }

        if (send_block_content (client) < 0) {
            seaf_warning ("Failed to send block content for %s.\n",
                          client->curr_block_id);
            return -1;
        }

        seaf_debug ("recv_state set to HEADER.\n");

        client->parser.content_cb = handle_block_header_content_cb;
        client->recv_state = RECV_STATE_HEADER;
    } else {
        seaf_debug ("Get block %s.\n", client->curr_block_id);

        if (send_block_header (client, REQUEST_COMMAND_GET) < 0) {
            seaf_warning ("Failed to send block header for GET %s.\n",
                          client->curr_block_id);
            return -1;
        }

        seaf_debug ("recv_state set to HEADER.\n");

        client->parser.content_cb = handle_block_header_content_cb;
        client->parser.fragment_cb = save_block_content_cb;
        client->recv_state = RECV_STATE_HEADER;
    }

    return 0;
}

static void
recv_data_cb (BlockTxClient *client)
{
    int ret = 0;

    /* Let evbuffer determine how much data can be read. */
    int n = evbuffer_read (client->recv_buf, client->data_fd, -1);
    if (n == 0) {
        seaf_warning ("Data connection is closed by the server.\n");
        client->break_loop = TRUE;
        client->info->result = BLOCK_CLIENT_NET_ERROR;
        return;
    } else if (n < 0) {
        seaf_warning ("Read data connection error: %s.\n",
                      evutil_socket_error_to_string(evutil_socket_geterror(client->data_fd)));
        client->break_loop = TRUE;
        client->info->result = BLOCK_CLIENT_NET_ERROR;
        return;
    }

    switch (client->recv_state) {
    case RECV_STATE_HANDSHAKE:
        ret = handle_handshake_response (client);
        break;
    case RECV_STATE_AUTH:
        ret = handle_auth_response (client);
        break;
    case RECV_STATE_HEADER:
        ret = handle_block_header (client);
        if (ret < 0)
            break;

        if (client->recv_state == RECV_STATE_CONTENT &&
            client->info->task->type == TASK_TYPE_DOWNLOAD)
            ret = handle_block_content (client);

        break;
    case RECV_STATE_CONTENT:
        ret = handle_block_content (client);
        break;
    }

    if (ret < 0)
        client->break_loop = TRUE;
}

static void
shutdown_client (BlockTxClient *client)
{
    if (client->block) {
        seaf_block_manager_close_block (seaf->block_mgr, client->block);
        seaf_block_manager_block_handle_free (seaf->block_mgr, client->block);
        client->block = NULL;
    }

    if (client->parser.enc_init)
        EVP_CIPHER_CTX_cleanup (&client->parser.ctx);

    evbuffer_free (client->recv_buf);
    evutil_closesocket (client->data_fd);

    client->recv_state = RECV_STATE_DONE;
}

static gboolean
handle_command (BlockTxClient *client, int command)
{
    gboolean ret = FALSE;
    int rsp;

    switch (command) {
    case BLOCK_CLIENT_CMD_TRANSFER:
        /* Ignore TRANSFER command if client has been shutdown. */
        if (client->recv_state == RECV_STATE_DONE) {
            seaf_debug ("Client was shutdown, ignore transfer command.\n");
            break;
        }

        if (transfer_next_block (client) < 0) {
            rsp = client->info->result;
            pipewrite (client->info->done_pipe[1], &rsp, sizeof(rsp));

            shutdown_client (client);

            client->break_loop = FALSE;
        }
        break;
    case BLOCK_CLIENT_CMD_CANCEL:
        if (client->recv_state == RECV_STATE_DONE) {
            seaf_debug ("Client was shutdown, ignore cancel command.\n");
            break;
        }

        seaf_debug ("Canceled command received.\n");
        client->info->result = BLOCK_CLIENT_CANCELED;

        if (client->info->transfer_once) {
            shutdown_client (client);
            ret = TRUE;
        } else {
            rsp = client->info->result;
            pipewrite (client->info->done_pipe[1], &rsp, sizeof(rsp));

            shutdown_client (client);

            client->break_loop = FALSE;

            ret = FALSE;
        }

        break;
    case BLOCK_CLIENT_CMD_END:
        client->info->result = BLOCK_CLIENT_ENDED;

        rsp = client->info->result;
        pipewrite (client->info->done_pipe[1], &rsp, sizeof(rsp));

        /* Don't need to shutdown_client() if it's already called. */
        if (client->recv_state != RECV_STATE_DONE)
            shutdown_client (client);

        client->break_loop = FALSE;

        ret = TRUE;
        break;
    }

    return ret;
}

static gboolean
do_break_loop (BlockTxClient *client)
{
    if (client->info->transfer_once) {
        shutdown_client (client);
        return TRUE;
    } else {
        int rsp = client->info->result;
        pipewrite (client->info->done_pipe[1], &rsp, sizeof(rsp));

        if (client->info->result != BLOCK_CLIENT_SUCCESS)
            shutdown_client (client);

        client->break_loop = FALSE;

        return FALSE;
    }
}

#define RECV_TIMEOUT_SEC 45

static gboolean
client_thread_loop (BlockTxClient *client)
{
    BlockTxInfo *info = client->info;
    fd_set fds;
    int max_fd = MAX (info->cmd_pipe[0], client->data_fd);
    int rc;
    gboolean restart = FALSE;
    struct timeval tmo;

    while (1) {
        FD_ZERO (&fds);
        FD_SET (info->cmd_pipe[0], &fds);

        /* Stop receiving any data after the client was shutdown. */
        if (client->recv_state != RECV_STATE_DONE) {
            FD_SET (client->data_fd, &fds);
            max_fd = MAX (info->cmd_pipe[0], client->data_fd);
        } else
            max_fd = info->cmd_pipe[0];

        tmo.tv_sec = RECV_TIMEOUT_SEC;
        tmo.tv_usec = 0;

        rc = select (max_fd + 1, &fds, NULL, NULL, &tmo);
        if (rc < 0 && errno == EINTR) {
            continue;
        } else if (rc < 0) {
            seaf_warning ("select error: %s.\n", strerror(errno));
            client->info->result = BLOCK_CLIENT_FAILED;
            break;
        } else if (rc == 0){
            /* timeout */
            seaf_warning ("Recv timeout.\n");
            client->info->result = BLOCK_CLIENT_NET_ERROR;
            if (do_break_loop (client))
                break;
            continue;
        }

        if (client->recv_state != RECV_STATE_DONE &&
            FD_ISSET (client->data_fd, &fds)) {
            recv_data_cb (client);
            if (client->break_loop && do_break_loop (client))
                break;
        }

        if (FD_ISSET (info->cmd_pipe[0], &fds)) {
            int cmd;
            piperead (info->cmd_pipe[0], &cmd, sizeof(int));

            if (cmd == BLOCK_CLIENT_CMD_RESTART) {
                restart = TRUE;
                break;
            }

            if (handle_command (client, cmd))
                break;
        }
    }

    return restart;
}

static void *
block_tx_client_thread (void *vdata)
{
    BlockTxClient *client = vdata;
    BlockTxInfo *info = client->info;
    BlockTxClientDoneCB cb = client->cb;
    evutil_socket_t data_fd;
    gboolean restart;

retry:
    data_fd = connect_chunk_server (info->cs);
    if (data_fd < 0) {
        info->result = BLOCK_CLIENT_NET_ERROR;
        if (!info->transfer_once) {
            pipewrite (info->done_pipe[1], &info->result, sizeof(info->result));
            /* Transfer manager always expects an ENDED response. */
            int rsp = BLOCK_CLIENT_ENDED;
            pipewrite (info->done_pipe[1], &rsp, sizeof(rsp));
        }
        return vdata;
    }
    client->data_fd = data_fd;

    if (send_handshake (data_fd, info) < 0) {
        if (!info->transfer_once) {
            pipewrite (info->done_pipe[1], &info->result, sizeof(info->result));
            int rsp = BLOCK_CLIENT_ENDED;
            pipewrite (info->done_pipe[1], &rsp, sizeof(rsp));
        }
        evutil_closesocket (client->data_fd);
        return vdata;
    }

    client->recv_buf = evbuffer_new ();

    restart = client_thread_loop (client);

    if (restart) {
        seaf_message ("Restarting block tx client.\n");
        memset (client, 0, sizeof(BlockTxClient));
        client->info = info;
        client->cb = cb;
        client->info->result = BLOCK_CLIENT_UNKNOWN;
        goto retry;
    }

    return vdata;
}

static void
block_tx_client_thread_done (void *vdata)
{
    BlockTxClient *client = vdata;

    client->cb (client->info);

    g_free (client);
}

int
block_tx_client_start (BlockTxInfo *info, BlockTxClientDoneCB cb)
{
    BlockTxClient *client = g_new0 (BlockTxClient, 1);
    int ret = 0;

    client->info = info;
    client->cb = cb;

    ret = ccnet_job_manager_schedule_job (seaf->job_mgr,
                                          block_tx_client_thread,
                                          block_tx_client_thread_done,
                                          client);
    if (ret < 0) {
        seaf_warning ("Failed to start block tx client thread.\n");
        return -1;
    }

    return 0;
}

void
block_tx_client_run_command (BlockTxInfo *info, int command)
{
    pipewrite (info->cmd_pipe[1], &command, sizeof(int));
}
