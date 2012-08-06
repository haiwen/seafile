/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef RPC_COMMON_H
#define RPC_COMMON_H

#include "ccnet/packet.h"

#define SC_CLIENT_CALL  "301"
#define SS_CLIENT_CALL  "CLIENT CALL"
#define SC_CLIENT_MORE  "302"
#define SS_CLIENT_MORE  "MORE"
#define SC_SERVER_RET   "311"
#define SS_SERVER_RET   "SERVER RET"
#define SC_SERVER_MORE  "312"
#define SS_SERVER_MORE  "HAS MORE"
#define SC_SERVER_ERR   "411"
#define SS_SERVER_ERR   "Fail to invoke the function, check the function"

/* MESSAGE_HEADER = SC_SERVER_RET(3) + " " + SS_SERVER_RET(10) + "\n"(1) + "\n"(1) */
#define MESSAGE_HEADER 64                  /* leave enough space */
#define MAX_TRANSFER_LENGTH (CCNET_PACKET_MAX_PAYLOAD_LEN - MESSAGE_HEADER)

/* 
   Client                       Server
              <xxx>-rpcserver
         ---------------------->

              200    OK
        <----------------------
            301 Func String
         ---------------------->

            312  HAS MORE
        <-----------------------
            302  MORE
         ---------------------->
            311 SERVER RET
        <-----------------------
 */

#endif
