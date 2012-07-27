/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef BLOCKTX_COMMON_H
#define BLOCKTX_COMMON_H


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

typedef struct {
    int     block_idx;
    char    block_id[41];
} BlockRequest;

typedef struct {
    int      block_idx;
    int      tx_bytes;
    int      tx_time;
} BlockResponse;

typedef struct {
    uint32_t block_size;
    uint32_t block_idx;
    char     block_id[41];
} __attribute__((__packed__)) BlockPacket;

#define MAX_BL_LEN 1024

typedef struct {
    CcnetPeer *peer;
    CcnetProcessor *processor;
    uint32_t cevent_id;
    ccnet_pipe_t  task_pipe[2];
    int      port;
    evutil_socket_t data_fd;

    gboolean processor_done;
    int      thread_ret;
} ThreadData;

typedef struct  {
    ThreadData *tdata;
    int     bm_offset;
    GHashTable *block_hash;
} BlockProcPriv;


#endif
