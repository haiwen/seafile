#ifndef BLOCK_TX_CLIENT_H
#define BLOCK_TX_CLIENT_H

#include "transfer-mgr.h"

typedef void (*BlockTxClientDoneCB) (BlockTxInfo *);

/*
 * There are two modes to use block-tx-client:
 *
 * 1. In upload, the client is set to one-time mode.
 * After all blocks are uploaded, the client done callback is called.
 * 
 * 2. In download, the client is set to interactive mode.
 * Transfer manager initiates multiple batches of blocks for download.
 * After each batch is downloaded, the block client writes to info->done_pipe
 * to notify transfer manager.
 * After all blocks are downloaded, transfer manager send a END command to
 * block client. The block client exits and calls the client done callback.
 */

int
block_tx_client_start (BlockTxInfo *info, BlockTxClientDoneCB cb);

enum {
    BLOCK_CLIENT_CMD_TRANSFER = 0,
    BLOCK_CLIENT_CMD_CANCEL,
    BLOCK_CLIENT_CMD_END,
};

void
block_tx_client_run_command (BlockTxInfo *info, int command);

#endif
