/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "common.h"

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x500
#endif

#include <windows.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#endif
#include <sys/types.h>

#include "job-mgr.h"
#include "seafile-session.h"
#include "utils.h"
#include "wt-monitor.h"
#define DEBUG_FLAG SEAFILE_DEBUG_WATCH
#include "log.h"

#define DIR_WATCH_MASK                                            \
    FILE_NOTIFY_CHANGE_FILE_NAME |  FILE_NOTIFY_CHANGE_LAST_WRITE \
    | FILE_NOTIFY_CHANGE_DIR_NAME | FILE_NOTIFY_CHANGE_SIZE 

/* Use large buffer to prevent events overflow. */
#define DIR_WATCH_BUFSIZE 1 << 20 /* 1MB */

/* Hold the OVERLAPPED struct for asynchronous ReadDirectoryChangesW(), and
   the buf to receive dir change info. */
typedef struct DirWatchAux {
    OVERLAPPED ol;
    char buf[DIR_WATCH_BUFSIZE];
    gboolean unused;
} DirWatchAux;

typedef struct RenameInfo {
    char *old_path;
    gboolean processing;        /* Are we processing a rename event? */
} RenameInfo;

typedef struct EventInfo {
    DWORD action;
    DWORD name_len;
    char name[SEAF_PATH_MAX];
} EventInfo;

typedef struct RepoWatchInfo {
    WTStatus *status;
    RenameInfo *rename_info;
    EventInfo last_event;
    char *worktree;
} RepoWatchInfo;

struct SeafWTMonitorPriv {
    pthread_mutex_t hash_lock;
    GHashTable *handle_hash;    /* repo_id -> dir handle */
    GHashTable *info_hash;      /* handle -> RepoWatchInfo  */
    GHashTable *buf_hash;       /* handle -> aux buf */

    HANDLE iocp_handle;

    int cmd_bytes_read;
    WatchCommand cmd;
};

static void *wt_monitor_job_win32 (void *vmonitor);

static void handle_watch_command (SeafWTMonitor *monitor, WatchCommand *cmd);

/* RenameInfo */

static RenameInfo *create_rename_info ()
{
    RenameInfo *info = g_new0 (RenameInfo, 1);

    return info;
}

static void free_rename_info (RenameInfo *info)
{
    g_free (info->old_path);
    g_free (info);
}

inline static void
set_rename_processing_state (RenameInfo *info, const char *path)
{
    info->old_path = g_strdup(path);
    info->processing = TRUE;
}

inline static void
unset_rename_processing_state (RenameInfo *info)
{
    g_free (info->old_path);
    info->old_path = NULL;
    info->processing = FALSE;
}

/* RepoWatchInfo */

static RepoWatchInfo *
create_repo_watch_info (const char *repo_id, const char *worktree)
{
    WTStatus *status = create_wt_status (repo_id);
    RenameInfo *rename_info = create_rename_info ();

    RepoWatchInfo *info = g_new0 (RepoWatchInfo, 1);
    info->status = status;
    info->rename_info = rename_info;
    info->worktree = g_strdup(worktree);

    return info;
}

static void
free_repo_watch_info (RepoWatchInfo *info)
{
    wt_status_unref (info->status);
    free_rename_info (info->rename_info);
    g_free (info->worktree);
    g_free (info);
}

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

static void
add_event_to_queue (WTStatus *status,
                    int type, const char *path, const char *new_path)
{
    WTEvent *event = wt_event_new (type, path, new_path);

    char *name;
    switch (type) {
    case WT_EVENT_CREATE_OR_UPDATE:
        name = "create/update";
        break;
    case WT_EVENT_SCAN_DIR:
        name = "scan dir";
        break;
    case WT_EVENT_DELETE:
        name = "delete";
        break;
    case WT_EVENT_RENAME:
        name = "rename";
        break;
    case WT_EVENT_OVERFLOW:
        name = "overflow";
        break;
    default:
        name = "unknown";
    }

    seaf_debug ("Adding event: %s, %s %s\n", name, path, new_path?new_path:"");

    pthread_mutex_lock (&status->q_lock);
    g_queue_push_tail (status->event_q, event);
    pthread_mutex_unlock (&status->q_lock);

    if (type == WT_EVENT_CREATE_OR_UPDATE) {
        pthread_mutex_lock (&status->ap_q_lock);

        char *last = g_queue_peek_tail (status->active_paths);
        if (!last || strcmp(last, path) != 0)
            g_queue_push_tail (status->active_paths, g_strdup(path));

        pthread_mutex_unlock (&status->ap_q_lock);
    }
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
       is changed would be encoded in wide char).
    */
    BOOL ret;
    DWORD code;
    RepoWatchInfo *info;
retry:
    ret = ReadDirectoryChangesW
        (dir_handle,            /* dir handle */
         aux->buf,              /* buf to hold change info */
         DIR_WATCH_BUFSIZE,     /* buf size */
         TRUE,                  /* watch subtree */
         DIR_WATCH_MASK,        /* notify filter */
         NULL,                  /* bytes returned */
         &aux->ol,              /* pointer to overlapped */
         NULL);                 /* completion routine */

    if (!ret) {
        code = GetLastError();
        seaf_warning("Failed to ReadDirectoryChangesW, "
                     "error code %lu", code);

        if (first_alloc)
            /* if failed at the first watch, free the aux buffer */
            g_free(aux);
        else if (code == ERROR_NOTIFY_ENUM_DIR) {
            /* If buffer overflowed after the last call,
             * add an overflow event and retry watch.
             */
            info = g_hash_table_lookup (priv->info_hash, dir_handle);
            add_event_to_queue (info->status, WT_EVENT_OVERFLOW, NULL, NULL);
            goto retry;
        }
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
start_watch_cmd_pipe (SeafWTMonitor *monitor, OVERLAPPED *ol_in)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    OVERLAPPED *ol = ol_in; 

    if (!ol) {
        ol = g_new0(OVERLAPPED, 1);
        init_overlapped(ol);
    }

    HANDLE hPipe = (HANDLE)monitor->cmd_pipe[0];

    void *p = &priv->cmd + priv->cmd_bytes_read;
    int to_read = sizeof(WatchCommand) - priv->cmd_bytes_read;

    BOOL sts = ReadFile
        (hPipe,                 /* file handle */
         p,            /* buffer */
         to_read,  /* bytes to read */
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
add_handle_to_iocp (SeafWTMonitor *monitor, HANDLE hAdd)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    
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

    if (hAdd == (HANDLE)monitor->cmd_pipe[0]) {
        /* HANDLE is cmd_pipe */
        return start_watch_cmd_pipe (monitor, NULL);
    } else {
        /* HANDLE is a dir handle */
        return start_watch_dir_change (priv, hAdd);
    }

}

/* Add the pipe handle and all repo wt handles to IO Completion Port. */
static BOOL
add_all_to_iocp (SeafWTMonitor *monitor)
{
    SeafWTMonitorPriv *priv = monitor->priv;

    if (!add_handle_to_iocp(monitor, (HANDLE)monitor->cmd_pipe[0])) {

        seaf_warning("Failed to add cmd_pipe to iocp, "
                     "error code %lu", GetLastError());
        return FALSE;
    }

    GHashTableIter iter;
    gpointer value = NULL;
    gpointer key = NULL;

    g_hash_table_iter_init (&iter, priv->handle_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        if (!add_handle_to_iocp(monitor, (HANDLE)value)) {
            seaf_warning("Failed to add dir handle to iocp, "
                         "repo %s, error code %lu", (char *)key,
                         GetLastError());
            continue;
        }
    }

    seaf_debug("Done: add_all_to_iocp\n");
    return TRUE;
}

/*
 * On Windows, RENAMED_OLD_NAME and RENAMED_NEW_NAME always comes in pairs.
 * If a file or dir is moved in/out of the worktree, ADDED or REMOVED event
 * will be emitted by the kernel.
 * 
 * This is a two-state state machine. The states are 'not processing rename' and
 * 'processing rename'.
 */
static void
handle_rename (RepoWatchInfo *info,
               PFILE_NOTIFY_INFORMATION event,
               const char *worktree,
               const char *filename,
               gboolean last_event)
{
    WTStatus *status = info->status;
    RenameInfo *rename_info = info->rename_info;

    if (event->Action == FILE_ACTION_RENAMED_OLD_NAME)
        seaf_debug ("Move %s ->\n", filename);
    else if (event->Action == FILE_ACTION_RENAMED_NEW_NAME)
        seaf_debug ("Move -> %s.\n", filename);

    if (!rename_info->processing) {
        if (event->Action == FILE_ACTION_RENAMED_OLD_NAME) {
            if (!last_event) {
                set_rename_processing_state (rename_info, filename);
            } else {
                /* RENAMED_OLD_NAME should not be the last event,
                   just ignore it.
                */
            }
        }
    } else {
        if (event->Action == FILE_ACTION_RENAMED_NEW_NAME) {
            /* Rename pair detected. */
            add_event_to_queue (status, WT_EVENT_RENAME,
                                rename_info->old_path, filename);
            unset_rename_processing_state (rename_info);
        }
    }
}

#if 0
static gboolean
handle_consecutive_duplicate_event (RepoWatchInfo *info,
                                    PFILE_NOTIFY_INFORMATION event)
{
    gboolean duplicate;

    /* Initially last_event is zero so it's not duplicate with any real events. */
    duplicate = (info->last_event.action == event->Action &&
                 info->last_event.name_len == event->FileNameLength &&
                 memcmp (info->last_event.name, event->FileName, event->FileNameLength) == 0);

    info->last_event.action = event->Action;
    info->last_event.name_len = event->FileNameLength;
    memcpy (info->last_event.name, event->FileName, event->FileNameLength);

    return duplicate;
}
#endif

static char *
convert_to_unix_path (const char *worktree, const wchar_t *path, int path_len,
                      gboolean convert_long_path)
{
    char *utf8_path = NULL;

    if (convert_long_path) {
        wchar_t *long_path = win32_83_path_to_long_path (worktree,
                                                         path,
                                                         path_len/sizeof(wchar_t));
        if (long_path) {
            utf8_path = g_utf16_to_utf8 (long_path, -1, NULL, NULL, NULL);
            g_free (long_path);
        } else
            utf8_path = g_utf16_to_utf8 (path, path_len/sizeof(wchar_t),
                                         NULL, NULL, NULL);
    } else
        utf8_path = g_utf16_to_utf8 (path, path_len/sizeof(wchar_t), NULL, NULL, NULL);

    if (!utf8_path)
        return NULL;

    char *p;
    for (p = utf8_path; *p != 0; ++p)
        if (*p == '\\')
            *p = '/';

    return utf8_path;
}

static void
process_one_event (RepoWatchInfo *info,
                   const char *worktree,
                   PFILE_NOTIFY_INFORMATION event,
                   gboolean last_event)
{
    WTStatus *status = info->status;
    char *filename;
    gboolean add_to_queue = TRUE;

#if 0
    if (handle_consecutive_duplicate_event (info, event))
        add_to_queue = FALSE;
#endif

    gboolean convert_long_path = !(event->Action == FILE_ACTION_RENAMED_OLD_NAME ||
                                   event->Action == FILE_ACTION_REMOVED);
    filename = convert_to_unix_path (worktree, event->FileName, event->FileNameLength,
                                     convert_long_path);
    if (!filename)
        goto out;

    handle_rename (info, event, worktree, filename, last_event);

    if (event->Action == FILE_ACTION_MODIFIED) {
        seaf_debug ("Modified %s.\n", filename);

        /* Ignore modified event for directories. */
        char *full_path = g_build_filename (worktree, filename, NULL);
        SeafStat st;
        int rc = seaf_stat (full_path, &st);
        if (rc < 0 || S_ISDIR(st.st_mode)) {
            g_free (full_path);
            goto out;
        }
        g_free (full_path);

        if (add_to_queue)
            add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, filename, NULL);
    } else if (event->Action == FILE_ACTION_ADDED) {
        seaf_debug ("Created %s.\n", filename);
        add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, filename, NULL);
    } else if (event->Action == FILE_ACTION_REMOVED) {
        seaf_debug ("Deleted %s.\n", filename);
        add_event_to_queue (status, WT_EVENT_DELETE, filename, NULL);
    }

out:
    g_free (filename);
    g_atomic_int_set (&info->status->last_changed, (gint)time(NULL));

}

static gboolean
process_events (const char *repo_id, RepoWatchInfo *info,
                char *event_buf, unsigned int buf_size)
{
    PFILE_NOTIFY_INFORMATION event;

    int offset = 0;
    while (1) {
        event = (PFILE_NOTIFY_INFORMATION)&event_buf[offset];
        offset += event->NextEntryOffset;

        process_one_event (info, info->worktree,
                           event, (event->NextEntryOffset == 0));

        if (!event->NextEntryOffset)
            break;
    }

    return TRUE;
}

static void *
wt_monitor_job_win32 (void *vmonitor)
{
    SeafWTMonitor *monitor = vmonitor;
    SeafWTMonitorPriv *priv = monitor->priv;
    /* 2 * sizeof(inotify_event) + 256, should be large enough for one event.*/
    RepoWatchInfo *info;


    DWORD bytesRead = 0;
    ULONG_PTR key = 0;
    OVERLAPPED *ol = NULL;

    /* Use I/O Completion Port to watch asynchronous events on:

     * 1) dir watch handles(events created by ReadDirectoryChangesW)
     * 2) the cmd pipe (which is a socket indeed)
     
     */

    if (!add_all_to_iocp(monitor)) {
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

        if (key == (ULONG_PTR)monitor->cmd_pipe[0]) {     
            /* Triggered by a cmd pipe event */

            priv->cmd_bytes_read += (int)bytesRead;
            if (priv->cmd_bytes_read != sizeof(WatchCommand)) {
                reset_overlapped(ol);
                start_watch_cmd_pipe (monitor, ol);
                continue;
            } else
                priv->cmd_bytes_read = 0;

            seaf_debug ("recevied a pipe cmd, type %d for repo %s\n",
                        priv->cmd.type, priv->cmd.repo_id);

            handle_watch_command (monitor, &priv->cmd);

            reset_overlapped(ol);
            start_watch_cmd_pipe (monitor, ol);

        } else {
            /* Trigger by one of the dir watch handles */

            HANDLE hTriggered = (HANDLE)key;
            info = (RepoWatchInfo *)g_hash_table_lookup
                (priv->info_hash, (gconstpointer)hTriggered); 

            if (info) {
                DirWatchAux *aux = g_hash_table_lookup (priv->buf_hash,
                                                        (gconstpointer)hTriggered);

                process_events (info->status->repo_id, info, aux->buf, bytesRead);

                reset_overlapped(ol);
                if (!start_watch_dir_change(priv, hTriggered)) {

                    seaf_warning ("start_watch_dir_change failed"
                                  "for repo %s, error code %lu\n",
                                  info->status->repo_id, GetLastError());
                }
            } else {
                /* A previously unwatched dir_handle's DirWatchAux buf was
                   scheduled to be freed. */
                g_hash_table_remove (priv->buf_hash, (gconstpointer)hTriggered);
            }
        }
    }
    return NULL;
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

static HANDLE add_watch (SeafWTMonitorPriv *priv,
                         const char *repo_id,
                         const char *worktree)
{
    HANDLE dir_handle = NULL;
    wchar_t *path = NULL;
    RepoWatchInfo *info;

    /* worktree is in utf8, need to convert to wchar in win32 */
    path = wchar_from_utf8 (worktree);

    dir_handle = get_handle_of_path (path);
    if (!dir_handle) {
        seaf_warning ("failed to open handle for worktree "
                      "of repo  %s\n", repo_id);
        g_free (path);
        return NULL;
    }
    g_free (path);

    pthread_mutex_lock (&priv->hash_lock);
    g_hash_table_insert (priv->handle_hash,
                         g_strdup(repo_id), (gpointer)dir_handle);

    info = create_repo_watch_info (repo_id, worktree);
    g_hash_table_insert (priv->info_hash, (gpointer)dir_handle, info);
    pthread_mutex_unlock (&priv->hash_lock);

    add_event_to_queue (info->status, WT_EVENT_SCAN_DIR, "", NULL);

    return dir_handle;
}

static int handle_add_repo (SeafWTMonitor *monitor,
                            const char *repo_id,
                            const char *worktree)
{
    HANDLE handle;

    handle = add_watch (monitor->priv, repo_id, worktree);
    if (handle == NULL ||
        !add_handle_to_iocp(monitor, handle)) {
        return -1;
    }

    return 0;
}

static int handle_rm_repo (SeafWTMonitorPriv *priv, const char *repo_id, gpointer handle)
{
    pthread_mutex_lock (&priv->hash_lock);
    g_hash_table_remove (priv->handle_hash, repo_id);
    g_hash_table_remove (priv->info_hash, handle);
    pthread_mutex_unlock (&priv->hash_lock);

    /* `aux' can't be freed here. Once we we close the dir_handle, its
     *  outstanding io would cause GetQueuedCompletionStatus() to return some
     *  information in aux->buf. If we free it here, it would cause seg fault.
     *  It will be freed in the completion code of GetQueuedCompletionStatus().
     */
    CloseHandle (handle);

    return 0;
}

static int handle_refresh_repo (SeafWTMonitorPriv *priv, const char *repo_id)
{
    return 0;
}

static void
reply_watch_command (SeafWTMonitor *monitor, int result)
{
    int n;

    n = seaf_pipe_writen (monitor->res_pipe[1], &result, sizeof(int));
    if (n != sizeof(int))
        seaf_warning ("[wt mon] fail to write command result.\n");
}

static void
handle_watch_command (SeafWTMonitor *monitor, WatchCommand *cmd)
{
    SeafWTMonitorPriv *priv = monitor->priv;

    if (cmd->type == CMD_ADD_WATCH) {
        if (g_hash_table_lookup_extended (priv->handle_hash, cmd->repo_id,
                                          NULL, NULL)) {
            reply_watch_command (monitor, 0);
            return;
        }

        if (handle_add_repo(monitor, cmd->repo_id, cmd->worktree) < 0) {
            seaf_warning ("[wt mon] failed to watch worktree of repo %s.\n",
                          cmd->repo_id);
            reply_watch_command (monitor, -1);
            return;
        }

        seaf_debug ("[wt mon] add watch for repo %s\n", cmd->repo_id);
        reply_watch_command (monitor, 0);
    } else if (cmd->type == CMD_DELETE_WATCH) {
        gpointer key, value;
        if (!g_hash_table_lookup_extended (priv->handle_hash, cmd->repo_id,
                                           &key, &value)) {
            reply_watch_command (monitor, 0);
            return;
        }

        handle_rm_repo (priv, cmd->repo_id, value);
        reply_watch_command (monitor, 0);
    } else if (cmd->type ==  CMD_REFRESH_WATCH) {
        if (handle_refresh_repo (priv, cmd->repo_id) < 0) {
            seaf_warning ("[wt mon] failed to refresh watch of repo %s.\n",
                          cmd->repo_id);
            reply_watch_command (monitor, -1);
            return;
        }
        reply_watch_command (monitor, 0);
    }
}

/* Public interface functions. */

SeafWTMonitor *
seaf_wt_monitor_new (SeafileSession *seaf)
{
    SeafWTMonitor *monitor = g_new0 (SeafWTMonitor, 1);
    SeafWTMonitorPriv *priv = g_new0 (SeafWTMonitorPriv, 1);

    pthread_mutex_init (&priv->hash_lock, NULL);

    priv->handle_hash = g_hash_table_new_full
        (g_str_hash, g_str_equal, g_free, NULL);

    priv->info_hash = g_hash_table_new_full
        (g_direct_hash, g_direct_equal, NULL, (GDestroyNotify)free_repo_watch_info);

    priv->buf_hash = g_hash_table_new_full
        (g_direct_hash, g_direct_equal, NULL, g_free);

    monitor->priv = priv;
    monitor->seaf = seaf;

    monitor->job_func = wt_monitor_job_win32;

    return monitor;
}

WTStatus *
seaf_wt_monitor_get_worktree_status (SeafWTMonitor *monitor,
                                     const char *repo_id)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    gpointer key, value;
    RepoWatchInfo *info;

    pthread_mutex_lock (&priv->hash_lock);

    if (!g_hash_table_lookup_extended (priv->handle_hash, repo_id,
                                       &key, &value)) {
        pthread_mutex_unlock (&priv->hash_lock);
        return NULL;
    }

    info = g_hash_table_lookup(priv->info_hash, value);
    wt_status_ref (info->status);

    pthread_mutex_unlock (&priv->hash_lock);

    return info->status;
}
