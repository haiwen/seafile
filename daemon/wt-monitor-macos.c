/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "common.h"

#include <CoreServices/CoreServices.h>
#include <sys/event.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ccnet/job-mgr.h>
#include "seafile-session.h"
#include "utils.h"
#include "wt-monitor.h"
#define DEBUG_FLAG SEAFILE_DEBUG_WATCH
#include "log.h"

typedef struct EventInfo {
    FSEventStreamEventId id;
    FSEventStreamEventFlags flags;
    char name[NAME_MAX];
} EventInfo;

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
    WTEvent *event = wt_event_new (type, path, new_path);

    char *name;
    switch (type) {
    case WT_EVENT_CREATE_OR_UPDATE:
        name = "create/update";
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
}

/*
 * Reinterpreted RENAMED as CREATED or DELETED event
 */
static void
handle_rename (const char *eventPath, RepoWatchInfo *info)
{
    struct stat buf;
    WTStatus *status = info->status;
    if (stat(eventPath, &buf)) {
        /* ret = -1, file is gone */
        add_event_to_queue (status, WT_EVENT_DELETE, eventPath, NULL);
    } else {
        /* ret = 0, file is here, but rename behaviour is unknown to us */
        add_event_to_queue (status, WT_EVENT_DELETE, eventPath, NULL);
        add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, eventPath, NULL);
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

    if (eventFlags & kFSEventStreamEventFlagItemRenamed) {
        seaf_debug ("Renamed %s \n", eventPath);
        handle_rename (eventPath, info);
    } else if (eventFlags & kFSEventStreamEventFlagItemModified) {
        seaf_debug ("Modified %s.\n", eventPath);
        add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, eventPath, NULL);
    } else if (eventFlags & kFSEventStreamEventFlagItemCreated) {
        seaf_debug ("Created %s.\n", eventPath);
         /**
          * no need to rechecking recursively in FSEventStream
          *
          * these flags are useful if necessary:
          * kFSEventStreamEventFlagItemIsFile
          * kFSEventStreamEventFlagItemIsDir
          * kFSEventStreamEventFlagItemIsSymlink
          */
        add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, eventPath, NULL);
    } else if (eventFlags & kFSEventStreamEventFlagItemRemoved) {
        seaf_debug ("Deleted %s.\n", eventPath);
        add_event_to_queue (status, WT_EVENT_DELETE, eventPath, NULL);
    }
    //TODO: kFSEventStreamEventFlagRootChanged and
    //kFSEventStreamCreateFlagWatchRoot
    g_atomic_int_set (&info->status->last_changed, (gint)time(NULL));
}

static void
stream_callback (ConstFSEventStreamRef streamRef,
                      void *clientCallBackInfo,
                      size_t numEvents,
                      void *eventPaths,
                      const FSEventStreamEventFlags eventFlags[],
                      const FSEventStreamEventId eventIds[])
{
    RepoWatchInfo *info;
    char *repo_id;
    SeafWTMonitor *monitor = (SeafWTMonitor *)clientCallBackInfo;
    SeafWTMonitorPriv *priv = monitor->priv;
    char **paths = (char **)eventPaths;
    char *dir;

    info = g_hash_table_lookup (priv->info_hash, (gpointer)(long)streamRef);
    if (!info) {
        seaf_warning ("Repo watch info not found.\n");
        return;
    }

    for (int i = 0; i < numEvents; i++) {
#ifdef FSEVENT_DEBUG
        seaf_debug("%ld Change %llu in %s, flags %x\n", (long)CFRunLoopGetCurrent(),
                   eventIds[i], paths[i], eventFlags[i]);
#endif
        process_one_event (paths[i], info, info->worktree,
                           eventIds[i], eventFlags[i]);
    }
}

static FSEventStreamRef
add_watch (SeafWTMonitor *monitor, const char* repo_id, const char* worktree)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    const char *path = worktree;
    RepoWatchInfo *info;
    double latency = 0.25; /* unit: second */

    CFStringRef mypath = CFStringCreateWithCString (kCFAllocatorDefault,
                                                    path, kCFStringEncodingUTF8);
    CFArrayRef pathsToWatch = CFArrayCreate(NULL, (const void **)&mypath, 1, NULL);
    FSEventStreamRef stream;

    /* Create the stream, passing in a callback */
    struct FSEventStreamContext ctx = {0, monitor, NULL, NULL, NULL};
    stream = FSEventStreamCreate(kCFAllocatorDefault,
                                 stream_callback,
                                 &ctx,
                                 pathsToWatch,
                                 kFSEventStreamEventIdSinceNow,
                                 latency,
                                 kFSEventStreamCreateFlagFileEvents /* deprecated OSX 10.6 support*/
        );

    CFRelease (mypath);
    CFRelease (pathsToWatch);

    if (!stream) {
        seaf_warning ("[wt] Failed to create event stream \n");
        return stream;
    }

    FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    FSEventStreamStart (stream);
#ifdef FSEVENT_DEBUG
    FSEventStreamShow (stream);
    seaf_debug ("[wt mon] Add repo %s watch success :%s.\n", repo_id, repo->worktree);
#endif

    pthread_mutex_lock (&priv->hash_lock);
    g_hash_table_insert (priv->handle_hash,
                         g_strdup(repo_id), (gpointer)(long)stream);

    info = create_repo_watch_info (repo_id, worktree);
    g_hash_table_insert (priv->info_hash, (gpointer)(long)stream, info);
    pthread_mutex_unlock (&priv->hash_lock);

    /* An empty path indicates repo-mgr to scan the whole worktree. */
    add_event_to_queue (info->status, WT_EVENT_CREATE_OR_UPDATE, "", NULL);
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

    n = pipereadn (monitor->cmd_pipe[0], &cmd, sizeof(cmd));
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

    n = pipewriten (monitor->res_pipe[1], &result, sizeof(int));
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
