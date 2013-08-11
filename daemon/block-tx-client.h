#ifndef BLOCK_TX_CLIENT_H
#define BLOCK_TX_CLIENT_H

#include "transfer-mgr.h"

typedef void (*BlockTxClientDoneCB) (BlockTxInfo *);

int
block_tx_client_start (BlockTxInfo *info, BlockTxClientDoneCB cb);

void
block_tx_client_cancel (BlockTxInfo *info);

#endif
