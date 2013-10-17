/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "common.h"

#include <CoreServices/CoreServices.h>
#include <sys/event.h>

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

struct SeafWTMonitorPriv {
    GHashTable *handle_hash;        /* repo_id -> inotify_fd (or handle) */
    GHashTable *status_hash;    /* inotify_df (or handle) -> wt status */
    ccnet_pipe_t cmd_pipe[2];
    ccnet_pipe_t res_pipe[2];
};

static void handle_watch_command (SeafWTMonitorPriv *priv, WatchCommand *cmd);

static void stream_callback (ConstFSEventStreamRef streamRef,
                      void *clientCallBackInfo,
                      size_t numEvents,
                      void *eventPaths,
                      const FSEventStreamEventFlags eventFlags[],
                      const FSEventStreamEventId eventIds[])
{
    WTStatus *status;
    SeafWTMonitorPriv *priv = (SeafWTMonitorPriv *)clientCallBackInfo;

    status = g_hash_table_lookup (priv->status_hash, streamRef);
    if (status) {
        g_atomic_int_set (&status->last_changed, (gint)time(NULL));
    }

#ifdef FSEVENT_DEBUG
    int i;
    char **paths = eventPaths;
    for (i = 0; i < numEvents; i++) {
        /* flags are unsigned long, IDs are uint64_t */
        seaf_debug("%ld Change %llu in %s, flags %lu\n", (long)CFRunLoopGetCurrent(),
                   eventIds[i], paths[i], (unsigned long)eventFlags[i]);
    }
#endif
}

static FSEventStreamRef add_watch (SeafWTMonitorPriv *priv, const char* repo_id)
{
    SeafRepo *repo = NULL;
    const char *path = NULL;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("[wt mon] cannot find repo %s.\n", repo_id);
        return 0;
    }

    path = repo->worktree;
    CFStringRef mypath = CFStringCreateWithCString (kCFAllocatorDefault,
                                                    path, kCFStringEncodingUTF8);
    CFArrayRef pathsToWatch = CFArrayCreate(NULL, (const void **)&mypath, 1, NULL);
    FSEventStreamRef stream;

    /* Create the stream, passing in a callback */
    struct FSEventStreamContext ctx = {0, priv, NULL, NULL, NULL};
    stream = FSEventStreamCreate(kCFAllocatorDefault,
                                 stream_callback,
                                 &ctx,
                                 pathsToWatch,
                                 kFSEventStreamEventIdSinceNow,
                                 1.0,
                                 kFSEventStreamCreateFlagWatchRoot
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
    return stream;
}

static void command_read_cb (CFFileDescriptorRef fdref,
                             CFOptionFlags callBackTypes,
                             void *info)
{
    SeafWTMonitorPriv *priv = (SeafWTMonitorPriv *)info;
    WatchCommand cmd;
    int n;

    n = pipereadn (priv->cmd_pipe[0], &cmd, sizeof(cmd));
    if (n != sizeof(cmd)) {
        seaf_warning ("[wt mon] failed to read command.\n");
        CFFileDescriptorEnableCallBacks (fdref, kCFFileDescriptorReadCallBack);
        return;
    }

    seaf_debug ("[wt mon] %ld receive command type=%d, repo=%s\n",
                (long)CFRunLoopGetCurrent(), cmd.type, cmd.repo_id);
    handle_watch_command (priv, &cmd);
    CFFileDescriptorEnableCallBacks (fdref, kCFFileDescriptorReadCallBack);
}

static int add_command_pipe (SeafWTMonitorPriv *priv)
{
    CFFileDescriptorContext ctx = {0, priv, NULL, NULL, NULL};
    CFFileDescriptorRef fdref = CFFileDescriptorCreate(NULL,
                                                       priv->cmd_pipe[0], true,
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
wt_monitor_job (void *vmonitor)
{
    SeafWTMonitor *monitor = vmonitor;
    SeafWTMonitorPriv *priv = monitor->priv;

    add_command_pipe (priv);
    while (1) {
        CFRunLoopRun();
    }
    return NULL;
}

static int handle_add_repo (SeafWTMonitorPriv *priv, const char *repo_id, long *handle)
{
    g_return_val_if_fail (handle, -1);
    FSEventStreamRef stream = add_watch (priv, repo_id);
    if (!stream)
        return -1;
    *handle = (long)stream;
    return 0;
}

static int handle_rm_repo (SeafWTMonitorPriv *priv, gpointer handle)
{
    FSEventStreamRef stream = (FSEventStreamRef)handle;
    FSEventStreamStop (stream);
    FSEventStreamInvalidate (stream);
    FSEventStreamRelease (stream);
    return 0;
}

static int handle_refresh_repo (SeafWTMonitorPriv *priv, const char *repo_id)
{
    return 0;
}

#include "wt-monitor-common.h"
