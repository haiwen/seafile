/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "common.h"

#include <CoreServices/CoreServices.h>
#include <sys/event.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "job-mgr.h"
#include "seafile-session.h"
#include "utils.h"
#include "wt-monitor.h"
#define DEBUG_FLAG SEAFILE_DEBUG_WATCH
#include "log.h"

typedef struct RepoWatchInfo {
    WTStatus *status;
    char *worktree;
} RepoWatchInfo;

struct SeafWTMonitorPriv {
    pthread_mutex_t hash_lock;
    GHashTable *handle_hash;        /* repo_id -> inotify_fd (or handle) */
    GHashTable *info_hash;          /* inotify_fd(or handle in deeed) -> RepoWatchInfo */
};

static void
add_event_to_queue (WTStatus *status,
                    int type, const char *path, const char *new_path);

static void handle_watch_command (SeafWTMonitor *monitor, WatchCommand *cmd);

/* RepoWatchInfo */

static RepoWatchInfo *
create_repo_watch_info (const char *repo_id, const char *worktree)
{
    WTStatus *status = create_wt_status (repo_id);

    RepoWatchInfo *info = g_new0 (RepoWatchInfo, 1);
    info->status = status;
    info->worktree = g_strdup(worktree);

    return info;
}

static void
free_repo_watch_info (RepoWatchInfo *info)
{
    wt_status_unref (info->status);
    g_free (info->worktree);
    g_free (info);
}

static void
add_event_to_queue (WTStatus *status,
                    int type, const char *path, const char *new_path)
{
    char *nfc_path = NULL, *nfc_new_path = NULL;

    if (path)
        nfc_path = g_utf8_normalize (path, -1, G_NORMALIZE_NFC);
    if (new_path)
        nfc_new_path = g_utf8_normalize (new_path, -1, G_NORMALIZE_NFC);

    WTEvent *event = wt_event_new (type, nfc_path, nfc_new_path);

    g_free (nfc_path);
    g_free (nfc_new_path);

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
    case WT_EVENT_ATTRIB:
        name = "attribute change";
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

static void
process_one_event (const char* eventPath,
                   RepoWatchInfo *info,
                   const char *worktree,
                   const FSEventStreamEventId eventId,
                   const FSEventStreamEventFlags eventFlags)
{
    WTStatus *status = info->status;
    char *filename;
    char *event_path_nfc;
    const char *tmp;
    struct stat buf;

    event_path_nfc = g_utf8_normalize (eventPath, -1, G_NORMALIZE_NFC);

    tmp = event_path_nfc + strlen(worktree);
    if (*tmp == '/')
        tmp++;
    filename = g_strdup(tmp);
    g_free (event_path_nfc);

    /* Path for folder returned from system may contain a '/' at the end. */
    int len = strlen(filename);
    if (len > 0 && filename[len - 1] == '/')
        filename[len - 1] = 0;

    /* Reinterpreted RENAMED as combine of CREATED or DELETED event */
    if (eventFlags & kFSEventStreamEventFlagItemRenamed) {
        seaf_debug ("Rename flag set for %s \n", filename);
        if (stat (eventPath, &buf) < 0) {
            /* ret = -1, file is gone */
            add_event_to_queue (status, WT_EVENT_DELETE, filename, NULL);
        } else {
            /* ret = 0, file is here, but rename behaviour is unknown to us */
            add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, filename, NULL);
        }
    }

    if (eventFlags & kFSEventStreamEventFlagItemRemoved) {
        seaf_debug ("Deleted flag set for %s.\n", filename);
        if (stat (eventPath, &buf) < 0) {
            add_event_to_queue (status, WT_EVENT_DELETE, filename, NULL);
        }
    }

    if (eventFlags & kFSEventStreamEventFlagItemModified) {
        seaf_debug ("Modified flag set for %s.\n", filename);
        if (stat (eventPath, &buf) == 0) {
            add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, filename, NULL);
        }
    }

    if (eventFlags & kFSEventStreamEventFlagItemCreated) {
        seaf_debug ("Created flag set for %s.\n", filename);
         /**
          * no need to rechecking recursively in FSEventStream
          *
          * these flags are useful if necessary:
          * kFSEventStreamEventFlagItemIsFile
          * kFSEventStreamEventFlagItemIsDir
          * kFSEventStreamEventFlagItemIsSymlink
          */
        if (stat (eventPath, &buf) == 0) {
            add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, filename, NULL);
        }
    }

    g_free (filename);
    g_atomic_int_set (&info->status->last_changed, (gint)time(NULL));
}

#if 0
static void
process_one_event (const char* eventPath,
                   RepoWatchInfo *info,
                   const char *worktree,
                   const FSEventStreamEventId eventId,
                   const FSEventStreamEventFlags eventFlags)
{
    WTStatus *status = info->status;
    char *dirname;
    char *event_path_nfc;
    const char *tmp;

    event_path_nfc = g_utf8_normalize (eventPath, -1, G_NORMALIZE_NFC);

    tmp = event_path_nfc + strlen(worktree);
    if (*tmp == '/')
        tmp++;
    dirname = g_strdup(tmp);
    g_free (event_path_nfc);

    /* Path for folder returned from system may contain a '/' at the end. */
    int len = strlen(dirname);
    if (len > 0 && dirname[len - 1] == '/')
        dirname[len - 1] = 0;

    if (eventFlags & kFSEventStreamEventFlagItemRenamed) {
        seaf_debug ("Rename event in dir: %s \n", dirname);
    } else if (eventFlags & kFSEventStreamEventFlagItemModified) {
        seaf_debug ("Modified event in dir %s.\n", dirname);
    } else if (eventFlags & kFSEventStreamEventFlagItemCreated) {
        seaf_debug ("Created event in dir %s.\n", dirname);
    } else if (eventFlags & kFSEventStreamEventFlagItemRemoved) {
        seaf_debug ("Deleted event in dir %s.\n", dirname);
    } else if (eventFlags & kFSEventStreamEventFlagItemXattrMod) {
        seaf_debug ("XattrMod event in dir %s.\n", dirname);
    } else {
        seaf_debug ("Unhandled event with flags %x.\n", eventFlags);
    }

    add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, dirname, NULL);

    g_free (dirname);
    g_atomic_int_set (&info->status->last_changed, (gint)time(NULL));
}
#endif

static void
stream_callback (ConstFSEventStreamRef streamRef,
                      void *clientCallBackInfo,
                      size_t numEvents,
                      void *eventPaths,
                      const FSEventStreamEventFlags eventFlags[],
                      const FSEventStreamEventId eventIds[])
{
    RepoWatchInfo *info;
    SeafWTMonitor *monitor = (SeafWTMonitor *)clientCallBackInfo;
    SeafWTMonitorPriv *priv = monitor->priv;
    char **paths = (char **)eventPaths;

    info = g_hash_table_lookup (priv->info_hash, (gpointer)(long)streamRef);
    if (!info) {
        seaf_warning ("Repo watch info not found.\n");
        return;
    }

    int i;
    for (i = 0; i < numEvents; i++) {
        seaf_debug("%ld Change %llu in %s, flags %x\n", (long)CFRunLoopGetCurrent(),
                   eventIds[i], paths[i], eventFlags[i]);
        process_one_event (paths[i], info, info->worktree,
                           eventIds[i], eventFlags[i]);
    }
}

static FSEventStreamRef
add_watch (SeafWTMonitor *monitor, const char* repo_id, const char* worktree)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    RepoWatchInfo *info;
    double latency = 0.25; /* unit: second */

    char *worktree_nfd = g_utf8_normalize (worktree, -1, G_NORMALIZE_NFD);

    CFStringRef mypaths[1];
    mypaths[0] = CFStringCreateWithCString (kCFAllocatorDefault,
                                            worktree_nfd, kCFStringEncodingUTF8);
    g_free (worktree_nfd);
    CFArrayRef pathsToWatch = CFArrayCreate(NULL, (const void **)mypaths, 1, NULL);
    FSEventStreamRef stream;

    /* Create the stream, passing in a callback */
    // kFSEventStreamCreateFlagFileEvents does not work for libraries with name
    // containing accent characters.
    struct FSEventStreamContext ctx = {0, monitor, NULL, NULL, NULL};
    stream = FSEventStreamCreate(kCFAllocatorDefault,
                                 stream_callback,
                                 &ctx,
                                 pathsToWatch,
                                 kFSEventStreamEventIdSinceNow,
                                 latency,
                                 kFSEventStreamCreateFlagFileEvents
                                 );

    CFRelease (mypaths[0]);
    CFRelease (pathsToWatch);

    if (!stream) {
        seaf_warning ("[wt] Failed to create event stream.\n");
        return stream;
    }

    FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    FSEventStreamStart (stream);
    /* FSEventStreamShow (stream); */
    seaf_debug ("[wt mon] Add repo %s watch success: %s.\n", repo_id, worktree);

    pthread_mutex_lock (&priv->hash_lock);
    g_hash_table_insert (priv->handle_hash,
                         g_strdup(repo_id), (gpointer)(long)stream);

    info = create_repo_watch_info (repo_id, worktree);
    g_hash_table_insert (priv->info_hash, (gpointer)(long)stream, info);
    pthread_mutex_unlock (&priv->hash_lock);

    /* A special event indicates repo-mgr to scan the whole worktree. */
    add_event_to_queue (info->status, WT_EVENT_SCAN_DIR, "", NULL);
    return stream;
}

static void
command_read_cb (CFFileDescriptorRef fdref,
                             CFOptionFlags callBackTypes,
                             void *info)
{
    SeafWTMonitor *monitor = (SeafWTMonitor *)info;
    WatchCommand cmd;
    int n;

    n = seaf_pipe_readn (monitor->cmd_pipe[0], &cmd, sizeof(cmd));
    if (n != sizeof(cmd)) {
        seaf_warning ("[wt mon] failed to read command.\n");
        CFFileDescriptorEnableCallBacks (fdref, kCFFileDescriptorReadCallBack);
        return;
    }

    seaf_debug ("[wt mon] %ld receive command type=%d, repo=%s\n",
                (long)CFRunLoopGetCurrent(), cmd.type, cmd.repo_id);
    handle_watch_command (monitor, &cmd);
    CFFileDescriptorEnableCallBacks (fdref, kCFFileDescriptorReadCallBack);
}

static int
add_command_pipe (SeafWTMonitor *monitor)
{
    CFFileDescriptorContext ctx = {0, monitor, NULL, NULL, NULL};
    CFFileDescriptorRef fdref = CFFileDescriptorCreate(NULL,
                                                       monitor->cmd_pipe[0], true,
                                                       command_read_cb, &ctx);
    if (fdref == NULL) {
        return -1;
    }

    CFFileDescriptorEnableCallBacks(fdref, kCFFileDescriptorReadCallBack);
    CFRunLoopSourceRef source = CFFileDescriptorCreateRunLoopSource(kCFAllocatorDefault, fdref, 0);
    CFRunLoopAddSource (CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
    CFRelease(source);
    return 0;
}

static void *
wt_monitor_job_darwin (void *vmonitor)
{
    SeafWTMonitor *monitor = (SeafWTMonitor *)vmonitor;

    add_command_pipe (monitor);
    while (1) {
        CFRunLoopRun();
    }
    return NULL;
}

static int
handle_add_repo (SeafWTMonitor *monitor, const char *repo_id, const char *worktree)
{
    FSEventStreamRef stream = add_watch (monitor, repo_id, worktree);
    if (!stream)
        return -1;
    return 0;
}

static int
handle_rm_repo (SeafWTMonitor *monitor, const char *repo_id, gpointer handle)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    FSEventStreamRef stream = (FSEventStreamRef)handle;
    FSEventStreamStop (stream);
    FSEventStreamInvalidate (stream);
    FSEventStreamRelease (stream);

    pthread_mutex_lock (&priv->hash_lock);
    g_hash_table_remove (priv->handle_hash, repo_id);
    g_hash_table_remove (priv->info_hash, (gpointer)(long)stream);
    pthread_mutex_unlock (&priv->hash_lock);
    return 0;
}

static int
handle_refresh_repo (SeafWTMonitor *monitor, const char *repo_id)
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

        handle_rm_repo (monitor, cmd->repo_id, value);
        reply_watch_command (monitor, 0);
    } else if (cmd->type ==  CMD_REFRESH_WATCH) {
        if (handle_refresh_repo (monitor, cmd->repo_id) < 0) {
            seaf_warning ("[wt mon] failed to refresh watch of repo %s.\n",
                          cmd->repo_id);
            reply_watch_command (monitor, -1);
            return;
        }
        reply_watch_command (monitor, 0);
    }
}

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

    monitor->priv = priv;
    monitor->seaf = seaf;

    monitor->job_func = wt_monitor_job_darwin;

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
