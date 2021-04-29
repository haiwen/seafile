#include "common.h"

#include "seafile-error-impl.h"

typedef struct SyncErrorInfo {
    int error_id;
    int error_level;
    const char *err_str;
} SyncErrorInfo;

static SyncErrorInfo sync_error_info_tbl[] = {
    {
        SYNC_ERROR_ID_FILE_LOCKED_BY_APP,
        SYNC_ERROR_LEVEL_FILE,
        "File is locked by another application"
    },
    {
        SYNC_ERROR_ID_FOLDER_LOCKED_BY_APP,
        SYNC_ERROR_LEVEL_FILE,
        "Folder is locked by another application"
    },
    {
        SYNC_ERROR_ID_FILE_LOCKED,
        SYNC_ERROR_LEVEL_FILE,
        "File is locked by another user"
    },
    {
        SYNC_ERROR_ID_INVALID_PATH,
        SYNC_ERROR_LEVEL_FILE,
        "Path is invalid"
    },
    {
        SYNC_ERROR_ID_INDEX_ERROR,
        SYNC_ERROR_LEVEL_FILE,
        "Error when indexing"
    },
    {
        SYNC_ERROR_ID_PATH_END_SPACE_PERIOD,
        SYNC_ERROR_LEVEL_FILE,
        "Path ends with space or period character"
    },
    {
        SYNC_ERROR_ID_PATH_INVALID_CHARACTER,
        SYNC_ERROR_LEVEL_FILE,
        "Path contains invalid characters like '|' or ':'"
    },
    {
        SYNC_ERROR_ID_FOLDER_PERM_DENIED,
        SYNC_ERROR_LEVEL_FILE,
        "Update to file denied by folder permission setting"
    },
    {
        SYNC_ERROR_ID_PERM_NOT_SYNCABLE,
        SYNC_ERROR_LEVEL_FILE,
        "No permission to sync this folder"
    },
    {
        SYNC_ERROR_ID_UPDATE_TO_READ_ONLY_REPO,
        SYNC_ERROR_LEVEL_FILE,
        "Created or updated a file in a non-writable library or folder"
    },
    {
        SYNC_ERROR_ID_ACCESS_DENIED,
        SYNC_ERROR_LEVEL_REPO,
        "Permission denied on server"
    },
    {
        SYNC_ERROR_ID_NO_WRITE_PERMISSION,
        SYNC_ERROR_LEVEL_REPO,
        "Do not have write permission to the library"
    },
    {
        SYNC_ERROR_ID_QUOTA_FULL,
        SYNC_ERROR_LEVEL_REPO,
        "Storage quota full"
    },
    {
        SYNC_ERROR_ID_NETWORK,
        SYNC_ERROR_LEVEL_NETWORK,
        "Network error",
    },
    {
        SYNC_ERROR_ID_RESOLVE_PROXY,
        SYNC_ERROR_LEVEL_NETWORK,
        "Cannot resolve proxy address"
    },
    {
        SYNC_ERROR_ID_RESOLVE_HOST,
        SYNC_ERROR_LEVEL_NETWORK,
        "Cannot resolve server address"
    },
    {
        SYNC_ERROR_ID_CONNECT,
        SYNC_ERROR_LEVEL_NETWORK,
        "Cannot connect to server"
    },
    {
        SYNC_ERROR_ID_SSL,
        SYNC_ERROR_LEVEL_NETWORK,
        "Failed to establish secure connection. Please check server SSL certificate"
    },
    {
        SYNC_ERROR_ID_TX,
        SYNC_ERROR_LEVEL_NETWORK,
        "Data transfer was interrupted. Please check network or firewall"
    },
    {
        SYNC_ERROR_ID_TX_TIMEOUT,
        SYNC_ERROR_LEVEL_NETWORK,
        "Data transfer timed out. Please check network or firewall"
    },
    {
        SYNC_ERROR_ID_UNHANDLED_REDIRECT,
        SYNC_ERROR_LEVEL_NETWORK,
        "Unhandled http redirect from server. Please check server cofiguration"
    },
    {
        SYNC_ERROR_ID_SERVER,
        SYNC_ERROR_LEVEL_REPO,
        "Server error"
    },
    {
        SYNC_ERROR_ID_LOCAL_DATA_CORRUPT,
        SYNC_ERROR_LEVEL_REPO,
        "Internal data corrupt on the client. Please try to resync the library"
    },
    {
        SYNC_ERROR_ID_WRITE_LOCAL_DATA,
        SYNC_ERROR_LEVEL_REPO,
        "Failed to write data on the client. Please check disk space or folder permissions"
    },
    {
        SYNC_ERROR_ID_SERVER_REPO_DELETED,
        SYNC_ERROR_LEVEL_REPO,
        "Library deleted on server"
    },
    {
        SYNC_ERROR_ID_SERVER_REPO_CORRUPT,
        SYNC_ERROR_LEVEL_REPO,
        "Library damaged on server"
    },
    {
        SYNC_ERROR_ID_NOT_ENOUGH_MEMORY,
        SYNC_ERROR_LEVEL_REPO,
        "Not enough memory"
    },
    {
        SYNC_ERROR_ID_CONFLICT,
        SYNC_ERROR_LEVEL_FILE,
        "Concurrent updates to file. File is saved as conflict file"
    },
    {
        SYNC_ERROR_ID_GENERAL_ERROR,
        SYNC_ERROR_LEVEL_REPO,
        "Unknown error"
    },
    {
        SYNC_ERROR_ID_NO_ERROR,
        SYNC_ERROR_LEVEL_REPO,
        "No error"
    },
    {
        SYNC_ERROR_ID_REMOVE_UNCOMMITTED_FOLDER,
        SYNC_ERROR_LEVEL_FILE,
        "A folder that may contain not-yet-uploaded files is moved to seafile-recycle-bin folder"
    },
    {
        SYNC_ERROR_ID_INVALID_PATH_ON_WINDOWS,
        SYNC_ERROR_LEVEL_FILE,
        "File or directory is invalid on Windows"
    },
    {
        SYNC_ERROR_ID_LIBRARY_TOO_LARGE,
        SYNC_ERROR_LEVEL_REPO,
        "Library is too large to sync"
    },
};

const char *
sync_error_id_to_str (int error)
{
    g_return_val_if_fail ((error >= 0 && error < N_SYNC_ERROR_ID), "Unknown error");

    return sync_error_info_tbl[error].err_str;
}

int
sync_error_level (int error)
{
    g_return_val_if_fail ((error >= 0 && error < N_SYNC_ERROR_ID), -1);

    return sync_error_info_tbl[error].error_level;
}
