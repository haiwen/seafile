/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "common.h"

#include <windows.h>

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <ccnet/job-mgr.h>
#include "seafile-session.h"
#include "utils.h"
#include "wt-monitor.h"
#define DEBUG_FLAG SEAFILE_DEBUG_WATCH
#include "log.h"

typedef enum CommandType {
    CMD_ADD_WATCH,
    CMD_DELETE_WATCH,
    CMD_REFRESH_WATCH,
    N_CMD_TYPES,
} CommandType;

typedef struct WatchCommand {
    CommandType type;
    char repo_id[37];
} WatchCommand;

#define DIR_WATCH_MASK                                            \
    FILE_NOTIFY_CHANGE_FILE_NAME |  FILE_NOTIFY_CHANGE_LAST_WRITE \
    | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE 

#define DIR_WATCH_BUFSIZE (sizeof(FILE_NOTIFY_INFORMATION) + SEAF_PATH_MAX * 2)

/* Hold the OVERLAPPED struct for asynchronous ReadDirectoryChangesW(), and
   the buf to receive dir change info. */
typedef struct DirWatchAux {
    OVERLAPPED ol;
    char buf[DIR_WATCH_BUFSIZE];
    gboolean unused;
} DirWatchAux;

struct SeafWTMonitorPriv {
    GHashTable *handle_hash;    /* repo_id -> dir handle */
    GHashTable *status_hash;    /* handle -> status  */
    GHashTable *buf_hash;       /* handle -> aux buf */

    int cmd_pipe[2];
    int res_pipe[2];

    HANDLE iocp_handle;
    WatchCommand cmd;           /* latest received command */
    
};

static void handle_watch_command (SeafWTMonitorPriv *priv, WatchCommand *cmd);

static inline void
init_overlapped(OVERLAPPED *ol)
{
    ol->Offset = ol->OffsetHigh = 0;
}


static inline void
reset_overlapped(OVERLAPPED *ol)
{
    ol->Offset = ol->OffsetHigh = 0;
}


/* Every time after a read event is processed, we should call
 * ReadDirectoryChangesW() on the dir handle asynchronously for the IOCP to
 * detect the change of the workthree.
 */
static BOOL
start_watch_dir_change(SeafWTMonitorPriv *priv, HANDLE dir_handle)
{
    if (!dir_handle)
        return FALSE;

    BOOL first_alloc = FALSE;
    DirWatchAux *aux = g_hash_table_lookup (priv->buf_hash, dir_handle);

    /* allocate aux buffer at the first watch, it would be freed if the repo
       is removed
    */
    if (!aux) {
        first_alloc = TRUE;
        aux = g_new0(DirWatchAux, 1);
        init_overlapped(&aux->ol);
    }

    /* The ending W of this function indicates that the info recevied about
       the change would be in Unicode(specifically, the name of the file that
       is changed would be encoded in wide char), but we don't care it right
       now. Maybe in the future.
    */
    BOOL ret = ReadDirectoryChangesW
        (dir_handle,            /* dir handle */
         &aux->buf,              /* buf to hold change info */
         DIR_WATCH_BUFSIZE,     /* buf size */
         TRUE,                  /* watch subtree */
         DIR_WATCH_MASK,        /* notify filter */
         NULL,                  /* bytes returned */
         &aux->ol,              /* pointer to overlapped */
         NULL);                 /* completion routine */

    if (!ret) {
        if (first_alloc)
            /* if failed at the first watch, free the aux buffer */
            g_free(aux);

        seaf_warning("Failed to ReadDirectoryChangesW, "
                     "error code %lu", GetLastError());
    } else {
        if (first_alloc)
            /* insert the aux buffer into hash table at the first watch */
            g_hash_table_insert (priv->buf_hash,
                                 (gpointer)dir_handle, (gpointer)aux);
    }

    return ret;
}


/* Every time after a read event is processed, we should call ReadFile() on
 * the pipe handle asynchronously for the IOCP to detect when it's readable.
 */
static BOOL
start_watch_cmd_pipe (SeafWTMonitorPriv *priv, OVERLAPPED *ol_in)
{
    OVERLAPPED *ol = ol_in; 

    if (!ol) {
        ol = g_new0(OVERLAPPED, 1);
        init_overlapped(ol);
    }

    HANDLE hPipe = (HANDLE)priv->cmd_pipe[0];

    BOOL sts = ReadFile
        (hPipe,                 /* file handle */
         &priv->cmd,            /* buffer */
         sizeof(WatchCommand),  /* bytes to read */
         NULL,                  /* bytes read */
         ol);                   /* overlapped */

    if (!sts && (GetLastError() != ERROR_IO_PENDING)) {
        seaf_warning ("failed to ReadFile, error code %lu\n",
                      GetLastError());
        if (!ol_in)
            /* free the overlapped struct if failed at the first watch */
            g_free(ol);

        return FALSE;
    }

    return TRUE;
}


/* Add a specific HANDLE to an I/O Completion Port. If it's the cmd pipe
 * handle, call ReadFile() on it; If it's a dir handle, call
 * ReadDirectoryChangesW() on it.
 */
static BOOL
add_handle_to_iocp (SeafWTMonitorPriv *priv, HANDLE hAdd)
{
    
    if (!priv || !hAdd)
        return FALSE;

    /* CreateIoCompletionPort() will add the handle to an I/O Completion Port
      if the iocp handle is not NULL. Otherwise it will create a new IOCP
      handle.

      The `key' parameter is used by th IOCP to tell us which handle watched
      by the I/O Completion Port triggeed a return of the
      GetQueuedCompletionStatus() function.

      Here we use the value of the handle itself as the key for this handle
      in the I/O Completion Port.
    */
    priv->iocp_handle = CreateIoCompletionPort
        (hAdd,                  /* handle to add */
         priv->iocp_handle,     /* iocp handle */
         (ULONG_PTR)hAdd,       /* key for this handle */
         1);                    /* Num of concurrent threads */

    if (!priv->iocp_handle) {
        seaf_warning ("failed to create/add iocp, error code %lu",
                      GetLastError());
        return FALSE;
    }

    if (hAdd == (HANDLE)priv->cmd_pipe[0]) {
        /* HANDLE is cmd_pipe */
        return start_watch_cmd_pipe (priv, NULL);
    } else {
        /* HANDLE is a dir handle */
        return start_watch_dir_change (priv, hAdd);
    }

}


/* Add the pipe handle and all repo wt handles to IO Completion Port. */
static BOOL
add_all_to_iocp (SeafWTMonitorPriv *priv)
{
    if (!add_handle_to_iocp(priv, (HANDLE)priv->cmd_pipe[0])) {

        seaf_warning("Failed to add cmd_pipe to iocp, "
                     "error code %lu", GetLastError());
        return FALSE;
    }

    GHashTableIter iter;
    gpointer value = NULL;
    gpointer key = NULL;

    g_hash_table_iter_init (&iter, priv->handle_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        if (!add_handle_to_iocp(priv, (HANDLE)value)) {
            seaf_warning("Failed to add dir handle to iocp, "
                         "repo %s, error code %lu", (char *)key,
                         GetLastError());
            continue;
        }
    }

    seaf_debug("Done: add_all_to_iocp\n");
    return TRUE;
}


/* Get the HANDLE of a repo directory, for latter use in
 * ReadDirectoryChangesW(). This handle should be closed when the repo is
 * unwatched.
 */
static HANDLE
get_handle_of_path(const wchar_t *path)
{
    HANDLE dir_handle = NULL;

    dir_handle = CreateFileW
        (path,                  /* file name */
         FILE_LIST_DIRECTORY,   /* desired access */
         FILE_SHARE_DELETE | FILE_SHARE_READ
         | FILE_SHARE_WRITE,    /* share mode */
         NULL,                  /* securitry attr */
         OPEN_EXISTING,         /* open options */
         FILE_FLAG_BACKUP_SEMANTICS |
         FILE_FLAG_OVERLAPPED,  /* flags needed for asynchronous IO*/
         NULL);                 /* template file */

    if (dir_handle == INVALID_HANDLE_VALUE) {
        char *path_utf8 = g_utf16_to_utf8 (path, -1, NULL, NULL, NULL);
        seaf_warning("failed to create dir handle for path %s, "
                     "error code %lu", path_utf8, GetLastError());
        g_free (path_utf8);
        return NULL;
    }

    return dir_handle;
}

/* Free the aux buffer when a repo is unwatched. */
static void
rm_from_buf_hash (SeafWTMonitorPriv *priv, HANDLE dir_handle)
{
    DirWatchAux *aux = g_hash_table_lookup(priv->buf_hash,
                                           (gconstpointer)dir_handle);

    if (!aux)
        return;

    g_hash_table_remove(priv->buf_hash, dir_handle);

    /* `aux' can't be freed here. Once we we close the dir_handle, its
     *  outstanding io would cause GetQueuedCompletionStatus() to return some
     *  information in aux->buf. If we free it here, it would cause seg fault.
     *  So we just mark it here and scheduled it to be freed in the completion
     *  code of GetQueuedCompletionStatus().
     */
    aux->unused = TRUE;
    CloseHandle(dir_handle);
}

static HANDLE add_watch (const char* repo_id)
{
    SeafRepo *repo = NULL;
    HANDLE dir_handle = NULL;
    wchar_t *path = NULL;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);

    if (!repo) {
        seaf_warning ("[wt mon] cannot find repo %s.\n", repo_id);
        return NULL;
    }

    /* repo->worktree is in utf8, need to convert to wchar in win32 */
    path = wchar_from_utf8 (repo->worktree);

    dir_handle = get_handle_of_path (path);
    if (!dir_handle) {
        seaf_warning ("failed to open handle for worktree "
                      "of repo  %s\n", repo_id);
    } else {
        seaf_debug ("opened handle for worktree %s\n", path);
    }

    g_free (path);

    return dir_handle;
}

static void *
wt_monitor_job (void *vmonitor)
{
    SeafWTMonitor *monitor = vmonitor;
    SeafWTMonitorPriv *priv = monitor->priv;
    /* 2 * sizeof(inotify_event) + 256, should be large enough for one event.*/
    WTStatus *status;


    DWORD bytesRead = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *ol = NULL;

    /* Use I/O Completion Port to watch asynchronous events on:

     * 1) dir watch handles(events created by ReadDirectoryChangesW)
     * 2) the cmd pipe (which is a socket indeed)
     
     */

    if (!add_all_to_iocp(priv)) {
        seaf_warning("Failed to add all to iocp\n");
        return NULL;
    }
    
    while (1) {

        BOOL ret = GetQueuedCompletionStatus
            (priv->iocp_handle,           /* iocp handle */
             &bytesRead,                  /* length of info */
             &key,                        /* completion key */
             &ol,                         /* OVERLAPPED */
             INFINITE);                   /* timeout */

        static int retry;

        if (!ret) {
            seaf_warning ("GetQueuedCompletionStatus failed, "
                          "error code %lu", GetLastError());

            if (retry++ < 3)
                continue;
            else
                break;
        } else {
            /* clear the retry counter on success */
            retry = 0;
        }

        if (key == (ULONG_PTR)priv->cmd_pipe[0]) {     
            /* Triggered by a cmd pipe event */

            if (bytesRead != sizeof(WatchCommand)) {
                seaf_warning ("broken cmd from pipe: get"
                              " %d(expected: %d) bytes\n",
                              (int)bytesRead, sizeof(WatchCommand));
                continue;
            }

            seaf_debug ("recevied a pipe cmd, type %d for repo %s\n",
                        priv->cmd.type, priv->cmd.repo_id);

            handle_watch_command (priv, &priv->cmd);

            reset_overlapped(ol);
            start_watch_cmd_pipe (priv, ol);

        } else {
            /* Trigger by one of the dir watch handles */

            HANDLE hTriggered = (HANDLE)key;
            status = (WTStatus *)g_hash_table_lookup
                (priv->status_hash, (gconstpointer)hTriggered); 

            char *repo_id = NULL;

            if (status && status->repo_id)
                repo_id = status->repo_id;
            else
                repo_id = "Unknown-repo-id";

            if (status) {
                g_atomic_int_set (&status->last_changed, (gint)time(NULL));

                seaf_debug("worktree change detected, repo %s\n", repo_id);

                reset_overlapped(ol);
                if (!start_watch_dir_change(priv, hTriggered)) {

                    seaf_warning ("start_watch_dir_change failed"
                                  "for repo %s, error code %lu\n",
                                  repo_id, GetLastError());
                }
            } else {
                /* A previously unwatched dir_handle's DirWatchAux buf was
                   scheduled to be freed. */
                DirWatchAux *aux = g_hash_table_lookup (priv->buf_hash, (gconstpointer)hTriggered);
                if (aux && aux->unused)
                    g_free (aux);
            }
        }
    }
    return NULL;
}

static int handle_add_repo (SeafWTMonitorPriv *priv, const char *repo_id, long *handle)
{
    HANDLE inotify_fd;

    g_return_if_fail (handle != NULL, -1);

    inotify_fd = add_watch (repo_id);
    if (inotify_fd == NULL ||
        !add_handle_to_iocp(priv, inotify_fd)) {
        return -1;
    }

    *handle = (long)inotify_fd;

    return 0;
}

static int handle_rm_repo (SeafWTMonitorPriv *priv, gpointer handle)
{
    HANDLE inotify_fd = (HANDLE)handle;

    rm_from_buf_hash(priv, inotify_fd);

    return 0;
}

static int handle_refresh_repo (SeafWTMonitorPriv *priv, const char *repo_id)
{
    return 0;
}

#include "wt-monitor-common.h"
