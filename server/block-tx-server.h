#ifndef BLOCK_TX_SERVER_H
#define BLOCK_TX_SERVER_H

#include <event2/util.h>

int
block_tx_server_start (evutil_socket_t data_fd);

#endif
