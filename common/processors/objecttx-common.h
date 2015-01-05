/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef OBJECTTX_COMMON_H
#define OBJECTTX_COMMON_H

#define SC_GET_OBJECT   "301"
#define SS_GET_OBJECT   "Get Object"
#define SC_OBJECT       "302"
#define SS_OBJECT       "Object"
#define SC_END          "303"
#define SS_END          "END"
#define SC_COMMIT_IDS   "304"
#define SS_COMMIT_IDS   "Commit IDs"
#define SC_ACK          "305"
#define SS_ACK          "Ack"

#define SC_OBJ_SEG      "306"
#define SS_OBJ_SEG      "Object Segment"
#define SC_OBJ_SEG_END  "307"
#define SS_OBJ_SEG_END  "Object Segment End"

#define SC_OBJ_LIST_SEG "308"
#define SS_OBJ_LIST_SEG "Object List Segment"
#define SC_OBJ_LIST_SEG_END "309"
#define SS_OBJ_LIST_SEG_END "Object List Segment End"

#define SC_NOT_FOUND    "401"
#define SS_NOT_FOUND    "Object not found"
#define SC_BAD_OL       "402"
#define SS_BAD_OL       "Bad Object List"
#define SC_BAD_OBJECT   "403"
#define SS_BAD_OBJECT   "Bad Object"

#define SC_ACCESS_DENIED "410"
#define SS_ACCESS_DENIED "Access denied"

/* for fs transfer */
#define SC_ROOT         "304"
#define SS_ROOT         "FS Root"
#define SC_ROOT_END     "305"
#define SS_ROOT_END     "FS Root End"

/* max fs object segment size */
#define MAX_OBJ_SEG_SIZE 64000


typedef struct {
    char    id[41];
    uint8_t object[0];
} __attribute__((__packed__)) ObjectPack;

#endif
