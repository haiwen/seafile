#ifndef SEAFILE_ERROR_H
#define SEAFILE_ERROR_H

/* Error codes used in RPC. */

#define SEAF_ERR_GENERAL        500
#define SEAF_ERR_BAD_REPO       501
#define SEAF_ERR_BAD_COMMIT     502
#define SEAF_ERR_BAD_ARGS       503
#define SEAF_ERR_INTERNAL       504
#define SEAF_ERR_BAD_FILE       505
#define SEAF_ERR_BAD_RELAY      506
#define SEAF_ERR_LIST_COMMITS   507
#define SEAF_ERR_REPO_AUTH      508
#define SEAF_ERR_GC_NOT_STARTED 509
#define SEAF_ERR_MONITOR_NOT_CONNECTED 510
#define SEAF_ERR_BAD_DIR_ID     511
#define SEAF_ERR_NO_WORKTREE    512
#define SEAF_ERR_BAD_PEER_ID    513
#define SEAF_ERR_REPO_LOCKED    514
#define SEAF_ERR_DIR_MISSING    515
#define SEAF_ERR_PATH_NO_EXIST  516 /* the dir or file pointed by this path not exists */

/* Sync errors. */

#define SYNC_ERROR_ID_FILE_LOCKED_BY_APP        0
#define SYNC_ERROR_ID_FOLDER_LOCKED_BY_APP      1
/* When file is locked on server. Returned in update-branch. */
#define SYNC_ERROR_ID_FILE_LOCKED               2
#define SYNC_ERROR_ID_INVALID_PATH              3
#define SYNC_ERROR_ID_INDEX_ERROR               4
#define SYNC_ERROR_ID_PATH_END_SPACE_PERIOD     5
#define SYNC_ERROR_ID_PATH_INVALID_CHARACTER    6
/* Returned in update-branch */
#define SYNC_ERROR_ID_FOLDER_PERM_DENIED        7
/* When there is no sync permission to library */
#define SYNC_ERROR_ID_PERM_NOT_SYNCABLE         8
/* Local error when updating a file in readonly library. */
#define SYNC_ERROR_ID_UPDATE_TO_READ_ONLY_REPO  9
/* When there is no read access to library. */
#define SYNC_ERROR_ID_ACCESS_DENIED             10
/* When there is no write access to library */
#define SYNC_ERROR_ID_NO_WRITE_PERMISSION       11
#define SYNC_ERROR_ID_QUOTA_FULL                12
#define SYNC_ERROR_ID_NETWORK                   13
#define SYNC_ERROR_ID_RESOLVE_PROXY             14
#define SYNC_ERROR_ID_RESOLVE_HOST              15
#define SYNC_ERROR_ID_CONNECT                   16
#define SYNC_ERROR_ID_SSL                       17
#define SYNC_ERROR_ID_TX                        18
#define SYNC_ERROR_ID_TX_TIMEOUT                19
#define SYNC_ERROR_ID_UNHANDLED_REDIRECT        20
#define SYNC_ERROR_ID_SERVER                    21
#define SYNC_ERROR_ID_LOCAL_DATA_CORRUPT        22
#define SYNC_ERROR_ID_WRITE_LOCAL_DATA          23
#define SYNC_ERROR_ID_SERVER_REPO_DELETED       24
#define SYNC_ERROR_ID_SERVER_REPO_CORRUPT       25
#define SYNC_ERROR_ID_NOT_ENOUGH_MEMORY         26
#define SYNC_ERROR_ID_CONFLICT                  27
#define SYNC_ERROR_ID_GENERAL_ERROR             28
#define SYNC_ERROR_ID_NO_ERROR                  29
#define SYNC_ERROR_ID_REMOVE_UNCOMMITTED_FOLDER 30
#define SYNC_ERROR_ID_INVALID_PATH_ON_WINDOWS   31
#define SYNC_ERROR_ID_LIBRARY_TOO_LARGE         32
#define N_SYNC_ERROR_ID                         33

#endif
