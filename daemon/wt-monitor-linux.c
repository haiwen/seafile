/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "common.h"

#include <sys/select.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <dirent.h>

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "job-mgr.h"
#include "seafile-session.h"
#include "utils.h"
#include "wt-monitor.h"
#define DEBUG_FLAG SEAFILE_DEBUG_WATCH
#include "log.h"

typedef struct WatchPathMapping {
    GHashTable *wd_to_path;     /* watch descriptor -> path */
} WatchPathMapping;

typedef struct RenameInfo {
    uint32_t last_cookie;
    char *old_path;
    gboolean processing;        /* Are we processing a rename event? */
} RenameInfo;

typedef struct EventInfo {
    int wd;
    uint32_t mask;
    uint32_t cookie;
    char name[NAME_MAX];
} EventInfo;

typedef struct RepoWatchInfo {
    WTStatus *status;
    WatchPathMapping *mapping;
    RenameInfo *rename_info;
    EventInfo last_event;
    char *worktree;
} RepoWatchInfo;

#define WATCH_MASK IN_MODIFY | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_CLOSE_WRITE | IN_ATTRIB

struct SeafWTMonitorPriv {
    pthread_mutex_t hash_lock;
    GHashTable *handle_hash;        /* repo_id -> inotify_fd */
    GHashTable *info_hash;          /* inotify_fd -> RepoWatchInfo */
    fd_set read_fds;
    int maxfd;
};

static void *wt_monitor_job_linux (void *vmonitor);

static void handle_watch_command (SeafWTMonitor *monitor, WatchCommand *cmd);

static int
add_watch_recursive (RepoWatchInfo *info, int in_fd,
                     const char *worktree, const char *path,
                     gboolean add_events);

/* WatchPathMapping */

static WatchPathMapping *create_mapping ()
{
    WatchPathMapping *mapping;

    mapping = g_new0 (WatchPathMapping, 1);
    mapping->wd_to_path = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                                 NULL, g_free);

    return mapping;
}

static void free_mapping (WatchPathMapping *mapping)
{
    g_hash_table_destroy (mapping->wd_to_path);
    g_free (mapping);
}

static void add_mapping (WatchPathMapping *mapping,
                         const char *path,
                         int wd)
{
    g_hash_table_insert (mapping->wd_to_path, (gpointer)(long)wd, g_strdup(path));
}

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
set_rename_processing_state (RenameInfo *info, uint32_t cookie, const char *path)
{
    info->last_cookie = cookie;
    info->old_path = g_strdup(path);
    info->processing = TRUE;
}

inline static void
unset_rename_processing_state (RenameInfo *info)
{
    info->last_cookie = 0;
    g_free (info->old_path);
    info->old_path = NULL;
    info->processing = FALSE;
}

/* RepoWatchInfo */

static RepoWatchInfo *
create_repo_watch_info (const char *repo_id, const char *worktree)
{
    WTStatus *status = create_wt_status (repo_id);
    WatchPathMapping *mapping = create_mapping ();
    RenameInfo *rename_info = create_rename_info ();

    RepoWatchInfo *info = g_new0 (RepoWatchInfo, 1);
    info->status = status;
    info->mapping = mapping;
    info->rename_info = rename_info;
    info->worktree = g_strdup(worktree);

    return info;
}

static void
free_repo_watch_info (RepoWatchInfo *info)
{
    wt_status_unref (info->status);
    free_mapping (info->mapping);
    free_rename_info (info->rename_info);
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

/*
 * We only recognize two consecutive "moved" events with the same cookie as
 * a rename pair. The processing logic is:
 * 1. Receive a MOVED_FROM event, set last_cookie and old_path, set processing to TRUE
 * 2. If the next event is MOVED_TO, and with the same cookie, then add an
 *    WT_EVENT_RENAME event to the queue.
 * 3. Otherwise, recognize them as one delete event followed by one
 *    create event
 *
 * This is a two-state state machine. The states are 'not processing rename' and
 * 'processing rename'.
 */
static void
handle_rename (int in_fd,
               RepoWatchInfo *info,
               struct inotify_event *event,
               const char *worktree,
               const char *filename,
               gboolean last_event)
{
    WTStatus *status = info->status;
    RenameInfo *rename_info = info->rename_info;

    if (event->mask & IN_MOVED_FROM)
        seaf_debug ("(%d) Move %s ->\n", event->cookie, event->name);
    else if (event->mask & IN_MOVED_TO)
        seaf_debug ("(%d) Move -> %s.\n", event->cookie, event->name);

    if (!rename_info->processing) {
        if (event->mask & IN_MOVED_FROM) {
            if (!last_event) {
                set_rename_processing_state (rename_info, event->cookie, filename);
            } else {
                /* Rename event pair should be in one batch of events.
                 * If a MOVED_FROM event is the last event in a batch,
                 * the path should be moved out of the repo.
                 */
                add_event_to_queue (status, WT_EVENT_DELETE, filename, NULL);
            }
        } else if (event->mask & IN_MOVED_TO) {
            /* A file/dir was moved into this repo. */
            /* Add watch and produce events. */
            add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, filename, NULL);
            add_watch_recursive (info, in_fd, worktree, filename, FALSE);
        }
    } else {
        if (event->mask & IN_MOVED_FROM) {
            /* A file/dir was moved out of this repo.
             * Output the last MOVED_FROM event as DELETE event
             */
            add_event_to_queue (status, WT_EVENT_DELETE, rename_info->old_path, NULL);

            if (!last_event) {
                /* Stay in processing state. */
                rename_info->last_cookie = event->cookie;
                g_free (rename_info->old_path);
                rename_info->old_path = g_strdup(filename);
            } else {
                /* Another file/dir was moved out of this repo. */
                add_event_to_queue (status, WT_EVENT_DELETE, filename, NULL);
                unset_rename_processing_state (rename_info);
            }
        } else if (event->mask & IN_MOVED_TO) {
            if (event->cookie == rename_info->last_cookie) {
                /* Rename pair detected. */
                add_event_to_queue (status, WT_EVENT_RENAME,
                                    rename_info->old_path, filename);
            } else {
                /* A file/dir was moved out of the repo, followed by
                 * aother file/dir was moved into this repo.
                 */
                add_event_to_queue (status, WT_EVENT_DELETE,
                                    rename_info->old_path, NULL);
                add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE,
                                    filename, NULL);
            }
            /* Need to update wd -> path mapping. */
            add_watch_recursive (info, in_fd, worktree, filename, FALSE);
            unset_rename_processing_state (rename_info);
        } else {
            /* A file/dir was moved out of this repo, followed by another
             * file operations.
             */
            add_event_to_queue (status, WT_EVENT_DELETE, rename_info->old_path, NULL);
            unset_rename_processing_state (rename_info);
        }
    }
}

inline static gboolean
is_modify_close_write (EventInfo *e1, struct inotify_event *e2)
{
    return ((e1->mask & IN_MODIFY) && (e2->mask & IN_CLOSE_WRITE));
}

#if 0
static gboolean
handle_consecutive_duplicate_event (RepoWatchInfo *info, struct inotify_event *event)
{
    gboolean duplicate;

    /* Initially last_event is zero so it's not duplicate with any real events. */
    duplicate = (info->last_event.wd == event->wd &&
                 (info->last_event.mask == event->mask ||
                  is_modify_close_write(&info->last_event, event)) &&
                 info->last_event.cookie == event->cookie &&
                 strcmp (info->last_event.name, event->name) == 0);

    info->last_event.wd = event->wd;
    info->last_event.mask = event->mask;
    info->last_event.cookie = event->cookie;
    memcpy (info->last_event.name, event->name, event->len);
    info->last_event.name[event->len] = 0;

    return duplicate;
}
#endif

static void
process_one_event (int in_fd,
                   RepoWatchInfo *info,
                   const char *worktree,
                   const char *parent,
                   struct inotify_event *event,
                   gboolean last_event)
{
    WTStatus *status = info->status;
    char *filename;
    gboolean update_last_changed = TRUE;
    gboolean add_to_queue = TRUE;

    /* An inotfy watch has been removed, we don't care about this for now. */
    if ((event->mask & IN_IGNORED) || (event->mask & IN_UNMOUNT))
        return;

    /* Kernel event queue was overflowed, some events may lost. */
    if (event->mask & IN_Q_OVERFLOW) {
        add_event_to_queue (status, WT_EVENT_OVERFLOW, NULL, NULL);
        return;
    }

    /* if (handle_consecutive_duplicate_event (info, event)) */
    /*     add_to_queue = FALSE; */

    filename = g_build_filename (parent, event->name, NULL);

    handle_rename (in_fd, info, event, worktree, filename, last_event);

    if (event->mask & IN_MODIFY) {
        seaf_debug ("Modified %s.\n", filename);
        if (add_to_queue)
            add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, filename, NULL);
    } else if (event->mask & IN_CREATE) {
        seaf_debug ("Created %s.\n", filename);

        /* Nautilus's file copy operation doesn't trigger write events.
         * If the user copy a large file into the repo, only a create
         * event and a close_write event will be received. If we process
         * the create event, we'll certainly try to index a file when it's
         * still being copied. So we'll ignore create event for files.
         * Since write and close_write events will always be triggered,
         * we don't need to worry about missing this file.
         */
        char *fullpath = g_build_filename (worktree, filename, NULL);
        struct stat st;
        if (lstat (fullpath, &st) < 0 ||
            (!S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode))) {
            g_free (fullpath);
            update_last_changed = FALSE;
            goto out;
        }
        g_free (fullpath);

        /* We now know it's a directory or a symlink. */

        /* Files or dirs could have been added under this dir before we
         * watch it. So it's safer to scan this dir. At most time we don't
         * have to scan recursively and very few new files will be found.
         */
        add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, filename, NULL);
        add_watch_recursive (info, in_fd, worktree, filename, FALSE);
    } else if (event->mask & IN_DELETE) {
        seaf_debug ("Deleted %s.\n", filename);
        add_event_to_queue (status, WT_EVENT_DELETE, filename, NULL);
    } else if (event->mask & IN_CLOSE_WRITE) {
        seaf_debug ("Close write %s.\n", filename);
        if (add_to_queue)
            add_event_to_queue (status, WT_EVENT_CREATE_OR_UPDATE, filename, NULL);
    } else if (event->mask & IN_ATTRIB) {
        seaf_debug ("Attribute changed %s.\n", filename);
        add_event_to_queue (status, WT_EVENT_ATTRIB, filename, NULL);
    }

out:
    g_free (filename);
    if (update_last_changed)
        g_atomic_int_set (&info->status->last_changed, (gint)time(NULL));
}

static gboolean
process_events (SeafWTMonitorPriv *priv, const char *repo_id, int in_fd)
{
    char *event_buf = NULL;
    unsigned int buf_size;
    struct inotify_event *event;
    RepoWatchInfo *info;
    int rc, n;
    char *dir;
    gboolean ret = FALSE;

    rc = ioctl (in_fd, FIONREAD, &buf_size);
    if (rc < 0) {
        seaf_warning ("Cannot get inotify event buf size: %s.\n", strerror(errno));
        return FALSE;
    }
    event_buf = g_new (char, buf_size);

    n = readn (in_fd, event_buf, buf_size);
    if (n < 0) {
        seaf_warning ("Failed to read inotify fd: %s.\n", strerror(errno));
        goto out;
    } else if (n != buf_size) {
        seaf_warning ("Read incomplete inotify event struct.\n");
        goto out;
    }

    info = g_hash_table_lookup (priv->info_hash, (gpointer)(long)in_fd);
    if (!info) {
        seaf_warning ("Repo watch info not found.\n");
        goto out;
    }

    int offset = 0;
    while (offset < buf_size) {
        event = (struct inotify_event *)&event_buf[offset];
        offset += sizeof(struct inotify_event) + event->len;

        dir = g_hash_table_lookup (info->mapping->wd_to_path,
                                   (gpointer)(long)event->wd);
        if (!dir) {
            seaf_warning ("Cannot find path from wd.\n");
            goto out;
        }

        process_one_event (in_fd, info, info->worktree, dir,
                           event, (offset >= buf_size));
    }

    ret = TRUE;

out:
    g_free (event_buf);
    return ret;
}

static void *
wt_monitor_job_linux (void *vmonitor)
{
    SeafWTMonitor *monitor = vmonitor;
    SeafWTMonitorPriv *priv = monitor->priv;

    WatchCommand cmd;
    int n;
    int rc;
    fd_set fds;
    int inotify_fd;
    char *repo_id;
    gpointer key, value;
    GHashTableIter iter;

    FD_SET (monitor->cmd_pipe[0], &priv->read_fds);
    priv->maxfd = monitor->cmd_pipe[0];

    while (1) {
        fds = priv->read_fds;

        rc = select (priv->maxfd + 1, &fds, NULL, NULL, NULL);
        if (rc < 0 && errno == EINTR) {
            continue;
        } else if (rc < 0) {
            seaf_warning ("[wt mon] select error: %s.\n", strerror(errno));
            break;
        }

        if (FD_ISSET (monitor->cmd_pipe[0], &fds)) {
            n = seaf_pipe_readn (monitor->cmd_pipe[0], &cmd, sizeof(cmd));
            if (n != sizeof(cmd)) {
                seaf_warning ("[wt mon] failed to read command.\n");
                continue;
            }
            handle_watch_command (monitor, &cmd);
        }

        g_hash_table_iter_init (&iter, priv->handle_hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
            repo_id = key;
            inotify_fd = (int)(long)value;
            if (FD_ISSET (inotify_fd, &fds))
                process_events (priv, repo_id, inotify_fd);
        }
    }

    return NULL;
}

/* Ignore errors so that we can still monitor other dirs
 * when one dir is bad.
 *
 * If @add_events is TRUE, add events for each dir and entries under that dir.
 * Note that only adding events for files is not enough, because repo-mgr will
 * need to add empty dirs to index.
 */
static int
add_watch_recursive (RepoWatchInfo *info,
                     int in_fd,
                     const char *worktree,
                     const char *path,
                     gboolean add_events)
{
    char *full_path;
    SeafStat st;
    DIR *dir;
    struct dirent *dent;
    int wd;

    full_path = g_build_filename (worktree, path, NULL);

    if (stat (full_path, &st) < 0) {
        seaf_warning ("[wt mon] fail to stat %s: %s\n", full_path, strerror(errno));
        goto out;
    }

    if (add_events && path[0] != 0)
        add_event_to_queue (info->status, WT_EVENT_CREATE_OR_UPDATE,
                            path, NULL);

    if (S_ISDIR (st.st_mode)) {
        seaf_debug ("Watching %s.\n", full_path);

        wd = inotify_add_watch (in_fd, full_path, (uint32_t)WATCH_MASK);
        if (wd < 0) {
            seaf_warning ("[wt mon] fail to add watch to %s: %s.\n",
                          full_path, strerror(errno));
            goto out;
        }

        add_mapping (info->mapping, path, wd);

        dir = opendir (full_path);
        if (!dir) {
            seaf_warning ("[wt mon] fail to open dir %s: %s.\n",
                          full_path, strerror(errno));
            goto out;
        }

        while (1) {
            dent = readdir (dir);
            if (!dent)
                break;
            if (strcmp (dent->d_name, ".") == 0 ||
                strcmp (dent->d_name, "..") == 0)
                continue;

            char *sub_path = g_build_filename (path, dent->d_name, NULL);

            /* Check d_type to avoid stating every files under this dir.
             * Note that d_type may not be supported in some file systems,
             * in this case DT_UNKNOWN is returned.
             */
            if (dent->d_type == DT_DIR || dent->d_type == DT_LNK ||
                dent->d_type == DT_UNKNOWN)
                add_watch_recursive (info, in_fd, worktree, sub_path, add_events);

            if (dent->d_type == DT_REG && add_events)
                add_event_to_queue (info->status, WT_EVENT_CREATE_OR_UPDATE,
                                    sub_path, NULL);
            g_free (sub_path);
        }

        closedir (dir);
    }

out:
    g_free (full_path);
    return 0;
}

static int
add_watch (SeafWTMonitorPriv *priv, const char *repo_id, const char *worktree)
{
    int inotify_fd;
    RepoWatchInfo *info;

    inotify_fd = inotify_init ();
    if (inotify_fd < 0) {
        seaf_warning ("[wt mon] inotify_init failed: %s.\n", strerror(errno));
        return -1;
    }

    pthread_mutex_lock (&priv->hash_lock);
    g_hash_table_insert (priv->handle_hash,
                         g_strdup(repo_id), (gpointer)(long)inotify_fd);

    info = create_repo_watch_info (repo_id, worktree);
    g_hash_table_insert (priv->info_hash, (gpointer)(long)inotify_fd, info);
    pthread_mutex_unlock (&priv->hash_lock);

    if (add_watch_recursive (info, inotify_fd, worktree, "", FALSE) < 0) {
        close (inotify_fd);
        pthread_mutex_lock (&priv->hash_lock);
        g_hash_table_remove (priv->handle_hash, repo_id);
        g_hash_table_remove (priv->info_hash, (gpointer)(long)inotify_fd);
        pthread_mutex_unlock (&priv->hash_lock);
        return -1;
    }

    /* A special event indicates repo-mgr to scan the whole worktree. */
    add_event_to_queue (info->status, WT_EVENT_SCAN_DIR, "", NULL);

    return inotify_fd;
}

static int handle_add_repo (SeafWTMonitorPriv *priv,
                            const char *repo_id,
                            const char *worktree)
{
    int inotify_fd;

    inotify_fd = add_watch (priv, repo_id, worktree);
    if (inotify_fd < 0) {
        return -1;
    }

    FD_SET (inotify_fd, &priv->read_fds);
    priv->maxfd = MAX (inotify_fd, priv->maxfd);
    return 0;
}

static void
update_maxfd (SeafWTMonitor *monitor)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    GHashTableIter iter;
    gpointer key, value;
    int fd, maxfd = monitor->cmd_pipe[0];

    g_hash_table_iter_init (&iter, priv->info_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        fd = (int) (long)key;
        if (fd > maxfd)
            maxfd = fd;
    }

    priv->maxfd = maxfd;
}

static int handle_rm_repo (SeafWTMonitor *monitor,
                           const char *repo_id,
                           gpointer handle)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    int inotify_fd = (int)(long)handle;

    close (inotify_fd);
    FD_CLR (inotify_fd, &priv->read_fds);
    update_maxfd (monitor);

    pthread_mutex_lock (&priv->hash_lock);
    g_hash_table_remove (priv->handle_hash, repo_id);
    g_hash_table_remove (priv->info_hash, (gpointer)(long)inotify_fd);
    pthread_mutex_unlock (&priv->hash_lock);

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

        if (handle_add_repo(priv, cmd->repo_id, cmd->worktree) < 0) {
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

    monitor->priv = priv;
    monitor->seaf = seaf;

    monitor->job_func = wt_monitor_job_linux;

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
