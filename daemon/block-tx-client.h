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
 * The block tx client first has to connect to the server and do authentication.
 * After authentication is done, block-tx-client writes a READY reply to done_pipe.
 * Transfer manager waits on the done_pipe for the READY reply.
 * Transfer manager then initiates multiple batches of blocks for download.
 * After each batch is downloaded, the block client writes to info->done_pipe
 * to notify transfer manager.
 * After all blocks are downloaded, transfer manager send a END command to
 * block client. The block client exits and returns an ENDED response code.
 */

int
block_tx_client_start (BlockTxInfo *info, BlockTxClientDoneCB cb);

enum {
    BLOCK_CLIENT_CMD_TRANSFER = 0,
    BLOCK_CLIENT_CMD_CANCEL,
    BLOCK_CLIENT_CMD_END,
    BLOCK_CLIENT_CMD_RESTART,
};

void
block_tx_client_run_command (BlockTxInfo *info, int command);

#endif
