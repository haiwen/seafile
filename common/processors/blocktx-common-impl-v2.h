#ifndef BLOCKTX_COMMON_IMPL_V2_H
#define BLOCKTX_COMMON_IMPL_V2_H

#include "common.h"
#include "utils.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#define SC_SEND_PORT    "301"
#define SS_SEND_PORT    "PORT"
#define SC_GET_PORT     "302"
#define SS_GET_PORT     "GET PORT"
#define SC_GET_BLOCK    "303"
#define SS_GET_BLOCK    "GET BLOCK"
#define SC_BBITMAP      "304"
#define SS_BBITMAP      "BLOCK BITMAP"
#define SC_ACK          "305"
#define SS_ACK          "BLOCK OK"
#define SC_BLOCKLIST    "306"
#define SS_BLOCKLIST    "BLOCK LIST"

#define SC_BAD_BLK_REQ      "405"
#define SS_BAD_BLK_REQ      "BAD BLOCK REQUEST"
#define SC_BAD_BL           "408"
#define SS_BAD_BL           "BAD BLOCK LIST"

#define SC_ACCESS_DENIED "410"
#define SS_ACCESS_DENIED "Access denied"

#define MAX_BL_LEN 1024
#define IO_BUF_LEN 1024
#define DEFAULT_SNDBUF_SIZE (1 << 16) /* 64KB */
#define DEFAULT_RCVBUF_SIZE (1 << 16) /* 64KB */
#define ENC_BLOCK_SIZE 16
#define TOKEN_TIMEOUT 180
#define BLOCKTX_TIMEOUT 30

typedef struct {
    int     block_idx;
    char    block_id[41];
} BlockRequest;

typedef struct {
    int      block_idx;
    int      tx_bytes;
    int      tx_time;
    char     block_id[41];
} BlockResponse;

typedef struct {
    uint32_t block_size;
    uint32_t block_idx;
    char     block_id[41];
} __attribute__((__packed__)) BlockPacket;

typedef struct BLInfo {
    char *block_list;
    int n_blocks;
} BLInfo;

typedef struct ThreadData ThreadData;

/* function called when receiving event from transfer thread via pipe. */
typedef void (*ThreadEventHandler) (CEvent *event, void *vprocessor);
typedef int  (*TransferFunc) (ThreadData *tdata);

struct ThreadData {
    int                  ref_count;

    CcnetPeer           *peer;
    /* Never dereference this processor in the worker thread */
    CcnetProcessor      *processor;
#if defined SENDBLOCK_PROC || defined GETBLOCK_PROC
    TransferTask        *task;
#endif
    uint32_t             cevent_id;
    ccnet_pipe_t         task_pipe[2];
    int                  port;
    evutil_socket_t      data_fd;

    gboolean             encrypt_channel;
    unsigned char        key[ENC_BLOCK_SIZE];
    unsigned char        iv[ENC_BLOCK_SIZE];

    gboolean             processor_done;
    char                *token;
    TransferFunc         transfer_func;
    int                  thread_ret;

    /* Use this state instead of processor->state, since
     * both the main thread and the worker thread need to
     * access it.
     */
    int                  state;

    /* For checking block list. */
    BLInfo              *blinfo;
    Bitfield             bitmap;
    GQueue              *bl_queue;
    gboolean             checking_bl;
};

typedef struct {
    ThreadData      *tdata;
    int              bm_offset;
    GHashTable      *block_hash;
    char             repo_id[37];
} BlockProcPriv;

/*
 * Common code for processor start and release_resource functions.
 */

static void
send_error (CcnetProcessor *processor)
{
    if (IS_SLAVE(processor))
        ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                       NULL, 0);
    else
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                     NULL, 0);
}

static void
thread_data_ref (ThreadData *tdata)
{
    ++(tdata->ref_count);
}

static void
thread_data_unref (ThreadData *tdata)
{
    if (!tdata)
        return;

    if (--(tdata->ref_count) <= 0) {
        if (tdata->bl_queue)
            g_queue_free (tdata->bl_queue);
        g_free (tdata->token);
        g_free (tdata);
    }
}

static void
prepare_thread_data (CcnetProcessor *processor,
                     TransferFunc tranfer_func,
                     ThreadEventHandler handler)
{
    USE_PRIV;

    priv->tdata = g_new0 (ThreadData, 1);
    thread_data_ref (priv->tdata);

    priv->tdata->task_pipe[0] = -1;
    priv->tdata->task_pipe[1] = -1;
    priv->tdata->transfer_func = tranfer_func;
    priv->tdata->processor = processor;

    priv->tdata->cevent_id = cevent_manager_register (seaf->ev_mgr,
                                                      handler,
                                                      processor);
}

static void
release_thread (CcnetProcessor *processor)
{
    USE_PRIV;

    if (priv->tdata) {
        /* The read end will be closed by worker thread. */
        if (priv->tdata->task_pipe[1] >= 0)
            pipeclose (priv->tdata->task_pipe[1]);

        priv->tdata->processor_done = TRUE;
        cevent_manager_unregister (seaf->ev_mgr, priv->tdata->cevent_id);

        thread_data_unref (priv->tdata);
    }
}

static void
thread_done (void *vtdata)
{
    ThreadData *tdata = vtdata;

    /* When the worker thread returns, the processor may have been
     * released. tdata->processor_done will be set to TRUE in
     * release_resource().
     *
     * Note: thread_done() and release_thread() are both called
     * in main thread, so there are only two cases:
     * 1) thread_done() is called before release_resource(), then release_thread()
     *    is called within thread_done()
     * 2) release_thread() is called before thread_done(), then tdata->processor_done
     *    is set.
     */
    if (!tdata->processor_done) {
        seaf_debug ("Processor is not released. Release it now.\n");
        if (tdata->thread_ret == 0) {
            ccnet_processor_done (tdata->processor, TRUE);
        } else {
            send_error (tdata->processor);
            ccnet_processor_done (tdata->processor, FALSE);
        }
    }

    thread_data_unref (tdata);
}


/*
 * Common code for block transfer.
 */

static void
send_block_rsp (int cevent_id, int block_idx, const char *block_id,
                int tx_bytes, int tx_time)
{
    BlockResponse *blk_rsp = g_new0 (BlockResponse, 1);
    blk_rsp->block_idx = block_idx;
    memcpy(blk_rsp->block_id, block_id, 40);
    blk_rsp->block_id[40] = '\0';
    blk_rsp->tx_bytes = tx_bytes;
    blk_rsp->tx_time = tx_time;
    cevent_manager_add_event (seaf->ev_mgr, 
                              cevent_id,
                              (void *)blk_rsp);
}

/* Encryption utilities. */

static void
generate_encrypt_key (ThreadData *tdata, CcnetPeer *peer)
{
    EVP_BytesToKey (EVP_aes_256_cbc(), /* cipher mode */
                    EVP_sha1(),        /* message digest */
                    NULL,              /* salt */
                    (unsigned char*)peer->session_key,
                    strlen(peer->session_key),
                    3,   /* iteration times */
                    tdata->key, /* the derived key */
                    tdata->iv); /* IV, initial vector */

    tdata->encrypt_channel = TRUE;
}

#if defined SENDBLOCK_PROC || defined PUTBLOCK_PROC

static int
encrypt_init (EVP_CIPHER_CTX *ctx,
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

static int
send_encrypted_data (EVP_CIPHER_CTX *ctx, int sockfd,
                     const char *buf, int len, uint32_t remain)
{
    char out_buf[IO_BUF_LEN + ENC_BLOCK_SIZE];
    int out_len;

    if (EVP_EncryptUpdate (ctx,
                           (unsigned char *)out_buf, &out_len,
                           (unsigned char *)buf, len) == 0) {
        seaf_warning ("Failed to encrypt data.\n");
        return -1;
    }

    if (sendn (sockfd, out_buf, out_len) < 0) {
        seaf_warning ("Failed to write data: %s.\n",
                      evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        return -1;
    }

    if (remain == 0) {
        if (EVP_EncryptFinal_ex (ctx, (unsigned char *)out_buf, &out_len) == 0) {
            seaf_warning ("Failed to encrypt data.\n");
            return -1;
        }
        if (sendn (sockfd, out_buf, out_len) < 0) {
            seaf_warning ("Failed to write data: %s.\n",
                          evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            return -1;
        }
    }

    return 0;
}

static int
send_block_packet (ThreadData *tdata,
                   int block_idx,
                   const char *block_id,
                   BlockHandle *handle, 
                   evutil_socket_t sockfd)
{
    SeafBlockManager *block_mgr = seaf->block_mgr;
    BlockMetadata *md;
    uint32_t size, remain;
    BlockPacket pkt;
    char buf[IO_BUF_LEN];
    int n;
    int ret = 0;
    EVP_CIPHER_CTX ctx;

    md = seaf_block_manager_stat_block_by_handle (block_mgr, handle);
    if (!md) {
        seaf_warning ("Failed to stat block %s.\n", block_id);
        return -1;
    }
    size = md->size;
    g_free (md);

    remain = size;
    /* Compute data size after encryption.
     * Block size is 16 bytes and AES always add one padding block.
     */
    if (tdata->encrypt_channel) {
        size = ((size >> 4) + 1) << 4;
        encrypt_init (&ctx, tdata->key, tdata->iv);
    }

    pkt.block_size = htonl (size);
    pkt.block_idx = htonl ((uint32_t) block_idx);
    memcpy (pkt.block_id, block_id, 41);
    if (sendn (sockfd, &pkt, sizeof(pkt)) < 0) {
        seaf_warning ("Failed to write socket: %s.\n", 
                   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        ret = -1;
        goto out;
    }

    while (1) {
        n = seaf_block_manager_read_block (block_mgr, handle, buf, IO_BUF_LEN);
        if (n <= 0)
            break;
        remain -= n;

        if (tdata->encrypt_channel)
            ret = send_encrypted_data (&ctx, sockfd, buf, n, remain);
        else
            ret = sendn (sockfd, buf, n);

        if (ret < 0) {
            seaf_warning ("Failed to write block %s\n", block_id);
            goto out;
        }
#ifdef SENDBLOCK_PROC
        /* Update global transferred bytes. */
        g_atomic_int_add (&(tdata->task->tx_bytes), n);
        g_atomic_int_add (&(seaf->transfer_mgr->sent_bytes), n);

        /* If uploaded bytes exceeds the limit, wait until the counter
         * is reset. We check the counter every 100 milliseconds, so we
         * can waste up to 100 milliseconds without sending data after
         * the counter is reset.
         */
        while (1) {
            gint sent = g_atomic_int_get(&(seaf->transfer_mgr->sent_bytes));
            if (seaf->transfer_mgr->upload_limit > 0 &&
                sent > seaf->transfer_mgr->upload_limit)
                /* 100 milliseconds */
                g_usleep (100000);
            else
                break;
        }
#endif
    }
    if (n < 0) {
        seaf_warning ("Failed to write block %s\n", block_id);
        ret = -1;
        goto out;
    }

    send_block_rsp (tdata->cevent_id, block_idx, block_id, size, 0);


out:
    if (tdata->encrypt_channel)
        EVP_CIPHER_CTX_cleanup (&ctx);

    return ret;
}

static int
send_blocks (ThreadData *tdata)
{
    SeafBlockManager *block_mgr = seaf->block_mgr;
    BlockRequest blk_req;
    BlockHandle *handle;
    int         n;
    int         ret;
    fd_set      fds;
    int max_fd = tdata->task_pipe[0];
    struct timeval tv = { BLOCKTX_TIMEOUT, 0 };

    while (1) {
        FD_ZERO (&fds);
        FD_SET (tdata->task_pipe[0], &fds);
        tv.tv_sec = BLOCKTX_TIMEOUT;
        tv.tv_usec = 0;

        n = select (max_fd + 1, &fds, NULL, NULL, &tv);
        if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0) {
            seaf_warning ("select error: %s.\n", strerror(errno));
            return -1;
        }

#ifdef PUTBLOCK_PROC
        if (n == 0) {
            seaf_warning ("timeout before GET_BLOCK command arrives.\n");
            return -1;
        }
#endif

#ifdef SENDBLOCK_PROC
        if (n == 0)
            continue;
#endif

        n = pipereadn (tdata->task_pipe[0], &blk_req, sizeof(blk_req));
        if (n == 0) {
            seaf_debug ("Processor exited. Worker thread exits now.\n");
            return -1;
        }
        if (n != sizeof(blk_req)) {
            seaf_warning ("read task pipe incorrect.\n");
            return -1;
        }

        handle = seaf_block_manager_open_block (block_mgr, 
                                                blk_req.block_id, BLOCK_READ);
        if (!handle) {
            seaf_warning ("[send block] failed to open block %s.\n", 
                       blk_req.block_id);
            return -1;
        }

        ret = send_block_packet (tdata, blk_req.block_idx, blk_req.block_id, 
                                 handle, tdata->data_fd);

        seaf_block_manager_close_block (block_mgr, handle);
        seaf_block_manager_block_handle_free (block_mgr, handle);

        if (ret < 0)
            return -1;
    }

    return 0;
}

#endif  /* defined SENDBLOCK_PROC || defined PUTBLOCK_PROC */

#if defined GETBLOCK_PROC || defined RECVBLOCK_PROC

enum {
    RECV_STATE_HEADER,
    RECV_STATE_BLOCK,
};

typedef struct {
    ThreadData *tdata;
    int state;
    BlockPacket hdr;
    int remain;
    BlockHandle *handle;
    uint32_t cevent_id;
    EVP_CIPHER_CTX ctx;
    gboolean enc_init;
} RecvFSM;

static int
decrypt_init (EVP_CIPHER_CTX *ctx,
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

static int
write_decrypted_data (const char *buf, int len,
                      RecvFSM *fsm)
{
    char out_buf[IO_BUF_LEN + ENC_BLOCK_SIZE];
    int out_len;

    if (EVP_DecryptUpdate (&fsm->ctx,
                           (unsigned char *)out_buf, &out_len,
                           (unsigned char *)buf, len) == 0) {
        seaf_warning ("Failed to decrypt data.\n");
        return -1;
    }

    if (seaf_block_manager_write_block (seaf->block_mgr, fsm->handle,
                                        out_buf, out_len) < 0) {
        seaf_warning ("Failed to write block %s.\n", fsm->hdr.block_id);
        return -1;
    }

    if (fsm->remain == 0) {
        if (EVP_DecryptFinal_ex (&fsm->ctx, (unsigned char *)out_buf, &out_len) == 0)
        {
            seaf_warning ("Failed to decrypt data.\n");
            return -1;
        }

        if (seaf_block_manager_write_block (seaf->block_mgr, fsm->handle,
                                            out_buf, out_len) < 0) {
            seaf_warning ("Failed to write block %s.\n", fsm->hdr.block_id);
            return -1;
        }
    }

    return 0;
}

static int
recv_tick (RecvFSM *fsm, evutil_socket_t sockfd)
{
    SeafBlockManager *block_mgr = seaf->block_mgr;
    char *block_id;
    BlockHandle *handle;
    int n, round;
    char buf[IO_BUF_LEN];
#ifdef GETBLOCK_PROC
    gint recv_bytes;
#endif

    switch (fsm->state) {
    case RECV_STATE_HEADER:
        n = recv (sockfd, 
                  (char *)&fsm->hdr + sizeof(BlockPacket) - fsm->remain, 
                  fsm->remain, 0);
        if (n < 0) {
            seaf_warning ("Failed to read block pkt: %s.\n",
                       evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            return -1;
        } else if (n == 0) {
            seaf_debug ("data connection closed.\n");
            return -1;
        }

        fsm->remain -= n;
        if (fsm->remain == 0) {
            fsm->remain = (int) ntohl (fsm->hdr.block_size);
            block_id = fsm->hdr.block_id;
            block_id[40] = 0;

            handle = seaf_block_manager_open_block (block_mgr, 
                                                    block_id, BLOCK_WRITE);
            if (!handle) {
                seaf_warning ("failed to open block %s.\n", block_id);
                return -1;
            }
            fsm->handle = handle; 
            fsm->state = RECV_STATE_BLOCK;

            if (fsm->tdata->encrypt_channel) {
                decrypt_init (&fsm->ctx, fsm->tdata->key, fsm->tdata->iv);
                fsm->enc_init = TRUE;
            }
        }
        break;
    case RECV_STATE_BLOCK:
#ifdef GETBLOCK_PROC
        recv_bytes = g_atomic_int_get (&(seaf->transfer_mgr->recv_bytes));
        if (seaf->transfer_mgr->download_limit > 0 &&
            recv_bytes > seaf->transfer_mgr->download_limit) {
            g_usleep (100000);
            return 0;
        }
#endif

        handle = fsm->handle;
        block_id = fsm->hdr.block_id;

        round = MIN (fsm->remain, IO_BUF_LEN);
        n = recv (sockfd, buf, round, 0);
        if (n < 0) {
            seaf_warning ("failed to read data: %s.\n",
                       evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            return -1;
        } else if (n == 0) {
            seaf_debug ("data connection closed.\n");
            return -1;
        }
        fsm->remain -= n;

        int ret;
        if (fsm->tdata->encrypt_channel)
            ret = write_decrypted_data (buf, n, fsm);
        else
            ret = seaf_block_manager_write_block (block_mgr, handle, buf, n);

        if (ret < 0) {
            seaf_warning ("Failed to write block %s.\n", fsm->hdr.block_id);
            return -1;
        }

#ifdef GETBLOCK_PROC
        /* Update global transferred bytes. */
        g_atomic_int_add (&(fsm->tdata->task->tx_bytes), n);
        g_atomic_int_add (&(seaf->transfer_mgr->recv_bytes), n);
#endif

        if (fsm->remain == 0) {
            if (fsm->tdata->encrypt_channel) {
                EVP_CIPHER_CTX_cleanup (&fsm->ctx);
                fsm->enc_init = FALSE;
            }

            if (seaf_block_manager_close_block (block_mgr, handle) < 0) {
                seaf_warning ("Failed to close block %s.\n", fsm->hdr.block_id);
                return -1;
            }

            if (seaf_block_manager_commit_block (block_mgr, handle) < 0) {
                seaf_warning ("Failed to commit block %s.\n", fsm->hdr.block_id);
                return -1;
            }

            seaf_block_manager_block_handle_free (block_mgr, handle);
            /* Set this handle to invalid. */
            fsm->handle = NULL;

            /* Notify finish receiving this block. */
            send_block_rsp (fsm->cevent_id,
                            (int)ntohl (fsm->hdr.block_idx),
                            block_id,
                            (int)ntohl (fsm->hdr.block_size), 0);

            /* Prepare for the next packet. */
            fsm->state = RECV_STATE_HEADER;
            fsm->remain = sizeof(BlockPacket);
        }
        break;
    }

    return 0;
}

static int
recv_blocks (ThreadData *tdata)
{
    fd_set fds;
    int max_fd = MAX (tdata->task_pipe[0], tdata->data_fd);
    struct timeval tv = { BLOCKTX_TIMEOUT, 0 };
    int rc;

    RecvFSM *fsm = g_new0 (RecvFSM, 1);
    fsm->remain = sizeof (BlockPacket);
    fsm->cevent_id = tdata->cevent_id;
    fsm->tdata = tdata;

    while (1) {
        FD_ZERO (&fds);
        FD_SET (tdata->task_pipe[0], &fds);
        FD_SET (tdata->data_fd, &fds);
        tv.tv_sec = BLOCKTX_TIMEOUT;
        tv.tv_usec = 0;

        rc = select (max_fd + 1, &fds, NULL, NULL, &tv);
        if (rc < 0 && errno == EINTR) {
            continue;
        } else if (rc < 0) {
            seaf_warning ("select error: %s.\n", strerror(errno));
            goto error;
        }

#ifdef RECVBLOCK_PROC
        if (rc == 0) {
            seaf_warning ("Recv block timeout.\n");
            goto error;
        }
#endif

#ifdef GETBLOCK_PROC
        if (rc == 0)
            continue;
#endif

        if (FD_ISSET (tdata->data_fd, &fds)) {
            if (recv_tick (fsm, tdata->data_fd) < 0) {
                goto error;
            }
        }

        if (FD_ISSET (tdata->task_pipe[0], &fds)) {
            /* task_pipe becomes readable only when the write end
             * is closed, in this case 0 is returned.
             * This means the processor was done.
             */
            char buf[1];
            piperead (tdata->task_pipe[0], buf, sizeof(buf));
            seaf_debug ("Task pipe closed. Worker thread exits now.\n");
            goto error;
        }
    }

    g_free (fsm);
    return 0;

error:
    if (fsm->tdata->encrypt_channel && fsm->enc_init)
        EVP_CIPHER_CTX_cleanup (&fsm->ctx);
    if (fsm->handle) {
        seaf_block_manager_close_block (seaf->block_mgr, fsm->handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, fsm->handle);
    }
    g_free (fsm);
    return -1;
}

#endif  /* defined GETBLOCK_PROC || defined RECVBLOCK_PROC */

#if defined GETBLOCK_PROC || defined SENDBLOCK_PROC

static int
master_block_proc_start (CcnetProcessor *processor,
                         TransferTask *tx_task,
                         const char *remote_processor_name,
                         Bitfield *active,
                         Bitfield *block_bitmap)
{
    GString *buf;
    if (!tx_task || !tx_task->session_token) {
        seaf_warning ("transfer task not set.\n");
        return -1;
    }

    BitfieldConstruct (active,
                       tx_task->block_list->block_map.bitCount);
    BitfieldConstruct (block_bitmap,
                       tx_task->block_list->block_map.bitCount);

    buf = g_string_new (NULL);
    g_string_printf (buf, "remote %s %s %s", 
                     processor->peer_id,
                     remote_processor_name,
                     tx_task->session_token);
                         
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

static void
descruct_bitfield (Bitfield *block_bitmap,
                   Bitfield *active,
                   TransferTask *tx_task)
{
    BitfieldDestruct (block_bitmap);
    /*
     * Set all the queued blocks to inactive so that they can be rescheduled.
     */
    if (tx_task->state == TASK_STATE_NORMAL)
        BitfieldDifference (&tx_task->active, active);
    BitfieldDestruct (active);
}

static void* do_transfer(void *vtdata)
{
    ThreadData *tdata = vtdata;

    struct sockaddr_storage addr;
    struct sockaddr *sa  = (struct sockaddr*) &addr;
    socklen_t sa_len = sizeof (addr);
    evutil_socket_t data_fd;

    CcnetPeer *peer = tdata->peer;

    if (peer->addr_str == NULL) {
        seaf_warning ("peer address is NULL\n");
        tdata->thread_ret = -1;
        goto out;
    }

    if (sock_pton(peer->addr_str, tdata->port, &addr) < 0) {
        seaf_warning ("wrong address format %s\n", peer->addr_str);
        tdata->thread_ret = -1;
        goto out;
    }

    if ((data_fd = socket(sa->sa_family, SOCK_STREAM, 0)) < 0) {
        seaf_warning ("socket error: %s\n", strerror(errno));
        tdata->thread_ret = -1;
        goto out;
    }

#if defined SENDBLOCK_PROC && defined WIN32
    /* Set large enough TCP buffer size.
     * This greatly enhances sync speed for high latency network.
     * Windows by default use 8KB buffers, which is too small for such case.
     * Linux has auto-tuning for TCP buffers, so don't need to set manually.
     * OSX is TBD.
     */

    /* Set send buffer size. */
    int sndbuf_size;
    ev_socklen_t optlen = sizeof(int);
    getsockopt (data_fd, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf_size, &optlen);

    if (sndbuf_size < DEFAULT_SNDBUF_SIZE) {
        sndbuf_size = DEFAULT_SNDBUF_SIZE;
        optlen = sizeof(int);
        setsockopt (data_fd, SOL_SOCKET, SO_SNDBUF, (char *)&sndbuf_size, optlen);
    }
#endif

#ifdef __APPLE__
    if (sa->sa_family == AF_INET)
        sa_len = sizeof(struct sockaddr_in);
    else if (sa->sa_family == PF_INET6)
        sa_len = sizeof(struct sockaddr_in6);
#endif

    if (connect(data_fd, sa, sa_len) < 0) {
        seaf_warning ("connect error: %s\n", strerror(errno));
        evutil_closesocket (data_fd);
        tdata->thread_ret = -1;
        goto out;
    }

    int token_len = strlen(tdata->token) + 1;
    if (sendn (data_fd, tdata->token, token_len) != token_len) {
        seaf_warning ("send connection token error: %s\n", strerror(errno));
        evutil_closesocket (data_fd);
        tdata->thread_ret = -1;
        goto out;
    }

    tdata->data_fd = data_fd;

    /* The client can send block requests now. */
    g_atomic_int_set (&tdata->state, READY);

    tdata->thread_ret = tdata->transfer_func(tdata);

    evutil_closesocket (tdata->data_fd);

out:
    pipeclose (tdata->task_pipe[0]);
    g_object_unref (peer);

    return vtdata;
}

static void
get_port (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;
    ThreadData *tdata = priv->tdata;
    char *p, *port_str, *token;
    CcnetPeer *peer = NULL;

    if (content[clen-1] != '\0') {
        seaf_warning ("Bad port and token\n");
        goto fail;
    }

    p = strchr (content, '\t');
    if (!p) {
        seaf_warning ("Bad port and token\n");
        goto fail;
    }

    *p = '\0';
    port_str = content; token = p + 1;

    peer = ccnet_get_peer (seaf->ccnetrpc_client, processor->peer_id);
    if (!peer) {
        seaf_warning ("Invalid peer %s.\n", processor->peer_id);
        goto fail;
    }
    /* Store peer address so that we don't need to call ccnet_get_peer()
     * in the worker thread later.
     */
    if (ccnet_pipe (tdata->task_pipe) < 0) {
        seaf_warning ("failed to create task pipe.\n");
        goto fail;
    }
    
    tdata->port = atoi (port_str);
    tdata->token = g_strdup(token);
    tdata->peer = peer;

    if (peer->encrypt_channel)
        generate_encrypt_key (tdata, peer);

    thread_data_ref (tdata);
    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    do_transfer,
                                    thread_done,
                                    tdata);

    return;

fail:
    if (peer)
        g_object_unref (peer);
    ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                 NULL, 0);
    ccnet_processor_done (processor, FALSE);
}

static void
send_block_list (CcnetProcessor *processor)
{
#ifdef SENDBLOCK_PROC
    SeafileSendblockV2Proc *proc = (SeafileSendblockV2Proc *)processor;
#else
    SeafileGetblockV2Proc *proc = (SeafileGetblockV2Proc *)processor;
#endif
    BlockList *bl = proc->tx_task->block_list;
    int i, n = 0;
    char buf[MAX_BL_LEN * 41];
    int len = 0;

    for (i = 0; i < bl->n_blocks; ++i) {
        memcpy (&buf[len], g_ptr_array_index(bl->block_ids, i), 41);
        len += 41;

        if (++n == MAX_BL_LEN) {
            ccnet_processor_send_update (processor, SC_BLOCKLIST, SS_BLOCKLIST,
                                         (char *)buf, len);
            n = 0;
            len = 0;
        }
    }

    if (n != 0)
        ccnet_processor_send_update (processor, SC_BLOCKLIST, SS_BLOCKLIST,
                                     (char *)buf, len);
}

static int
process_block_bitmap (CcnetProcessor *processor, char *content, int clen)
{
#ifdef SENDBLOCK_PROC
    SeafileSendblockV2Proc *proc = (SeafileSendblockV2Proc *)processor;
#else
    SeafileGetblockV2Proc *proc = (SeafileGetblockV2Proc *)processor;
#endif
    USE_PRIV;

    if (proc->block_bitmap.byteCount < priv->bm_offset + clen) {
        seaf_warning ("Received block bitmap is too large.\n");
        ccnet_processor_send_update (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                     NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
    memcpy (proc->block_bitmap.bits + priv->bm_offset, content, clen);

    priv->bm_offset += clen;
    if (priv->bm_offset == proc->block_bitmap.byteCount) {
#ifdef SENDBLOCK_PROC
        /* Update global uploaded bitmap. */
        BitfieldOr (&proc->tx_task->uploaded, &proc->block_bitmap);
        proc->tx_task->n_uploaded = BitfieldCountTrueBits (&proc->tx_task->uploaded);
#endif
        ccnet_processor_send_update (processor, SC_GET_PORT, SS_GET_PORT,
                                     NULL, 0);
        priv->tdata->state = GET_PORT;
    }

    return 0;
}

#endif  /* defined SENDBLOCK_PROC || GETBLOCK_PROC */

#if defined RECVBLOCK_PROC || defined PUTBLOCK_PROC

static int
verify_session_token (CcnetProcessor *processor, char *ret_repo_id,
                      int argc, char **argv)
{
    if (argc != 1) {
        return -1;
    }

    char *session_token = argv[0];
    if (seaf_token_manager_verify_token (seaf->token_mgr,
                                         NULL,
                                         processor->peer_id,
                                         session_token, ret_repo_id) < 0) {
        return -1;
    }

    return 0;
}


static void* do_passive_transfer(void *vtdata)
{
    ThreadData *tdata = vtdata;

    tdata->thread_ret = tdata->transfer_func (tdata);
    
    pipeclose (tdata->task_pipe[0]);
    evutil_closesocket (tdata->data_fd);
    
    return vtdata;
}

static void
accept_connection (evutil_socket_t connfd, void *vdata)
{
    ThreadData *tdata = vdata;
    CcnetProcessor *processor;
    CcnetPeer *peer = NULL;

    /* 
     * The processor may have been shutdown since accept_connection()
     * is run outside of the processor's context.
     */
    if (tdata->processor_done) {
        thread_data_unref (tdata);
        if (connfd >= 0)
            evutil_closesocket (connfd);
        return;
    }

    processor = tdata->processor;

    if (connfd < 0)
        goto fail;

    peer = ccnet_get_peer (seaf->ccnetrpc_client, processor->peer_id);
    if (!peer) {
        seaf_warning ("Invalid peer %s.\n", processor->peer_id);
        evutil_closesocket (tdata->data_fd);
        goto fail;
    }

    tdata->data_fd = connfd;

    /* Start to accept block requests from the client */
    tdata->state = READY;

    if (ccnet_pipe (tdata->task_pipe) < 0) {
        seaf_warning ("failed to create task pipe.\n");
        evutil_closesocket (tdata->data_fd);
        goto fail;
    }

    if (peer->encrypt_channel)
        generate_encrypt_key (tdata, peer);
    g_object_unref (peer);

    /* Don't need to ref thread data again. We're already holding one.
     */
    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    do_passive_transfer,
                                    thread_done,
                                    tdata);
    return;

fail:
    if (peer)
        g_object_unref (peer);
    ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                   NULL, 0);
    ccnet_processor_done (processor, FALSE);
    thread_data_unref (tdata);
}

static void
send_port (CcnetProcessor *processor)
{
    USE_PRIV;
    char buf[256];
    char *token = NULL;
    int len;

    token = seaf_listen_manager_generate_token (seaf->listen_mgr);
    if (seaf_listen_manager_register_token (seaf->listen_mgr, token,
                        (ConnAcceptedCB)accept_connection,
                        priv->tdata, TOKEN_TIMEOUT) < 0) {
        seaf_warning ("failed to register token\n");
        g_free (token);
        ccnet_processor_send_response (processor, SC_SHUTDOWN, SS_SHUTDOWN,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }

    /* We're leaving processor context, make sure tdata is still available
     * when the callback is run.
     */
    thread_data_ref (priv->tdata);

    len = snprintf (buf, sizeof(buf), "%d\t%s", seaf->listen_mgr->port, token);
    ccnet_processor_send_response (processor,
                                   SC_SEND_PORT, SS_SEND_PORT,
                                   buf, len+1);

    g_free (token);
}

#ifdef RECVBLOCK_PROC
static void *
check_block_list (void *vtdata)
{
    ThreadData *tdata = vtdata;
    char *block_list = tdata->blinfo->block_list;
    int n_blocks = tdata->blinfo->n_blocks;
    char *block_id;
    int i;

    BitfieldConstruct (&tdata->bitmap, n_blocks);

    block_id = block_list;
    for (i = 0; i < n_blocks; ++i) {
        block_id[40] = '\0';
        if (seaf_block_manager_block_exists(seaf->block_mgr, block_id))
            BitfieldAdd (&tdata->bitmap, i);
        block_id += 41;
    }

    g_free (tdata->blinfo->block_list);
    g_free (tdata->blinfo);

    return vtdata;
}

static void
check_block_list_done (void *vtdata)
{
    ThreadData *tdata = vtdata;
    Bitfield *pbitmap = &tdata->bitmap;

    tdata->checking_bl = FALSE;

    if (tdata->processor_done) {
        BitfieldDestruct (pbitmap);
        thread_data_unref (tdata);
        return;
    }

    ccnet_processor_send_response (tdata->processor, SC_BBITMAP, SS_BBITMAP,
                                   (char *)(pbitmap->bits), pbitmap->byteCount);
    BitfieldDestruct (pbitmap);

    /* Process next block list segment, or exit. */
    if (tdata->bl_queue != NULL) {
        BLInfo *blinfo = g_queue_pop_head (tdata->bl_queue);
        if (blinfo != NULL) {
            tdata->checking_bl = TRUE;
            tdata->blinfo = blinfo;
            thread_data_ref (tdata);
            ccnet_job_manager_schedule_job (seaf->job_mgr,
                                            check_block_list,
                                            check_block_list_done,
                                            tdata);
        }
    }

    thread_data_unref (tdata);
}
#endif  /* RECVBLOCK_PROC */

static void
process_block_list (CcnetProcessor *processor, char *content, int clen)
{
    int n_blocks;

    if (clen % 41 != 0) {
        seaf_warning ("Bad block list.\n");
        ccnet_processor_send_response (processor, SC_BAD_BL, SS_BAD_BL, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    n_blocks = clen/41;

#ifdef PUTBLOCK_PROC
    Bitfield bitmap;

    /* If it's a download, we can assume all the blocks are present
     * on the server. So no need to check.
     */
    BitfieldConstruct (&bitmap, n_blocks);

    BitfieldAddRange (&bitmap, 0, n_blocks);
    ccnet_processor_send_response (processor, SC_BBITMAP, SS_BBITMAP,
                                   (char *)(bitmap.bits), bitmap.byteCount);
    BitfieldDestruct (&bitmap);
#endif

#ifdef RECVBLOCK_PROC
    USE_PRIV;
    ThreadData *tdata = priv->tdata;
    BLInfo *blinfo;

    /* If a worker thread is already running, push this block list to queue.
     * It will be processed after the worker thread finishes the current one.
     * Otherwise start a new worker thread.
     */
    blinfo = g_new0 (BLInfo, 1);
    blinfo->block_list = g_memdup (content, clen);
    blinfo->n_blocks = n_blocks;

    if (!tdata->checking_bl) {
        tdata->checking_bl = TRUE;
        tdata->blinfo = blinfo;
        thread_data_ref (tdata);
        ccnet_job_manager_schedule_job (seaf->job_mgr,
                                        check_block_list,
                                        check_block_list_done,
                                        tdata);
    } else {
        if (!tdata->bl_queue)
            tdata->bl_queue = g_queue_new ();
        g_queue_push_tail (tdata->bl_queue, blinfo);
    }
#endif
}

#endif  /* defined RECVBLOCK_PROC || defined PUTBLOCK_PROC */

#endif  /* BLOCKTX_COMMON_IMPL_V2_H */
