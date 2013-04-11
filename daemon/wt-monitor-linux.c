/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "common.h"

#include <sys/select.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <dirent.h>

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

typedef struct WatchPathMapping {
    GHashTable *wd_to_path;     /* watch descriptor -> full path */
} WatchPathMapping;

#define WATCH_MASK IN_MODIFY | IN_ATTRIB | IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_CLOSE_WRITE

struct SeafWTMonitorPriv {
    GHashTable *handle_hash;        /* repo_id -> inotify_fd (or handle) */
    GHashTable *status_hash;        /* inotify_fd -> wt status */
    GHashTable *mapping_hash;       /* inotify_fd -> watch mapping */
    ccnet_pipe_t cmd_pipe[2];
    ccnet_pipe_t res_pipe[2];
    fd_set read_fds;
    int maxfd;
};

static void handle_watch_command (SeafWTMonitorPriv *priv, WatchCommand *cmd);

static int
add_watch_recursive (WatchPathMapping *mapping, int in_fd, const char *path);

static gboolean
process_event (SeafWTMonitorPriv *priv, int in_fd)
{
    char *event_buf = NULL;
    unsigned int buf_size;
    struct inotify_event *event;
    WatchPathMapping *mapping;
    int rc, n;
    char *dir, *full_path;
    struct stat sb, sb2;
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
        return FALSE;
    } else if (n != buf_size) {
        seaf_warning ("Read incomplete inotify event struct.\n");
        return FALSE;
    }

    int offset = 0;
    while (offset < buf_size) {
        event = (struct inotify_event *)&event_buf[offset];
        offset += sizeof(struct inotify_event) + event->len;

        if (event->mask & (IN_CREATE | IN_MOVED_TO)) {
            seaf_debug ("%s is added.\n", event->name);

            mapping = g_hash_table_lookup (priv->mapping_hash,
                                           (gpointer)(long)in_fd);
            dir = g_hash_table_lookup (mapping->wd_to_path,
                                       (gpointer)(long)event->wd);
            if (!dir) {
                seaf_warning ("Cannot find path from wd.\n");
                goto out;
            }

            full_path = g_build_filename (dir, event->name, NULL);

            if (stat (full_path, &sb) < 0) {
                seaf_warning ("Failed to stat %s: %s.\n",
                              full_path, strerror(errno));
                g_free (full_path);
                goto out;
            }

            if (lstat (full_path, &sb2) < 0) {
                seaf_warning ("Failed to lstat %s: %s.\n",
                              full_path, strerror(errno));
                g_free (full_path);
                goto out;
            }

            /* Don't update status->last_changed for "create file" event.
             * The timestamp will be updated when we receive write
             * and close_write events later. So we won't miss this
             * file anyway.
             * 
             * Nautilus' copy file operation doesn't trigger any
             * write events. Not updating last_changed on "create
             * file" event avoids to start auto commit before nautilus
             * finish writing the file.
             *
             * Note that if a symlink to file is created, we have to update
             * status->last_changed, because the file will not be written
             * later.
             */
            if ((event->mask & IN_MOVED_TO) ||
                S_ISDIR(sb.st_mode) || S_ISLNK(sb2.st_mode))
                ret = TRUE;

            if (S_ISDIR (sb.st_mode)) {
                seaf_debug ("Watching dir %s when it's added.\n", full_path);
                add_watch_recursive (mapping, in_fd, full_path);
            }

            g_free (full_path);
        } else {
            /* Update status->last_changed. */
            ret = TRUE;
        }
    }

out:
    g_free (event_buf);
    return ret;
}

static void *
wt_monitor_job (void *vmonitor)
{
    SeafWTMonitor *monitor = vmonitor;
    SeafWTMonitorPriv *priv = monitor->priv;
    WTStatus *status;

    WatchCommand cmd;
    int n;
    int rc;
    fd_set fds;
    int inotify_fd;
    gpointer key, value;
    GHashTableIter iter;

    FD_SET (priv->cmd_pipe[0], &priv->read_fds);
    priv->maxfd = priv->cmd_pipe[0];

    while (1) {
        fds = priv->read_fds;

        rc = select (priv->maxfd + 1, &fds, NULL, NULL, NULL);
        if (rc < 0 && errno == EINTR) {
            continue;
        } else if (rc < 0) {
            seaf_warning ("[wt mon] select error: %s.\n", strerror(errno));
            break;
        }

        if (FD_ISSET (priv->cmd_pipe[0], &fds)) {
            n = pipereadn (priv->cmd_pipe[0], &cmd, sizeof(cmd));
            if (n != sizeof(cmd)) {
                seaf_warning ("[wt mon] failed to read command.\n");
                continue;
            }
            handle_watch_command (priv, &cmd);
        }

        g_hash_table_iter_init (&iter, priv->status_hash);
        while (g_hash_table_iter_next (&iter, &key, &value)) {
            inotify_fd = (int)(long)key;
            if (FD_ISSET (inotify_fd, &fds)) {
                if (!process_event (priv, inotify_fd))
                    continue;

                status = value;
                if (status) {
                    g_atomic_int_set (&status->last_changed, (gint)time(NULL));
                }
            }
        }
    }

    return NULL;
}

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

/* Ignore errors so that we can still monitor other dirs
 * when one dir is bad.
 */
static int
add_watch_recursive (WatchPathMapping *mapping, int in_fd, const char *path)
{
    SeafStat st;
    DIR *dir;
    struct dirent *dent;
    int wd;

    if (stat (path, &st) < 0) {
        seaf_warning ("[wt mon] fail to stat %s: %s\n", path, strerror(errno));
        return 0;
    }

    if (S_ISDIR (st.st_mode)) {
        seaf_debug ("Watching %s.\n", path);

        wd = inotify_add_watch (in_fd, path, (uint32_t)WATCH_MASK);
        if (wd < 0) {
            seaf_warning ("[wt mon] fail to add watch to %s: %s.\n",
                          path, strerror(errno));
            return 0;
        }

        add_mapping (mapping, path, wd);

        dir = opendir (path);
        if (!dir) {
            seaf_warning ("[wt mon] fail to open dir %s: %s.\n",
                          path, strerror(errno));
            return 0;
        }

        while (1) {
            dent = readdir (dir);
            if (!dent)
                break;
            if (strcmp (dent->d_name, ".") == 0 ||
                strcmp (dent->d_name, "..") == 0)
                continue;

            char *sub_path = g_build_filename (path, dent->d_name, NULL);
            add_watch_recursive (mapping, in_fd, sub_path);
            g_free (sub_path);
        }

        closedir (dir);
    }

    return 0;
}

static int
add_watch (SeafWTMonitorPriv *priv, const char *repo_id)
{
    SeafRepo *repo;
    int inotify_fd;
    char path[SEAF_PATH_MAX];
    WatchPathMapping *mapping;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("[wt mon] cannot find repo %s.\n", repo_id);
        return -1;
    }

    inotify_fd = inotify_init ();
    if (inotify_fd < 0) {
        seaf_warning ("[wt mon] inotify_init failed: %s.\n", strerror(errno));
        return -1;
    }

    mapping = create_mapping ();
    g_hash_table_insert (priv->mapping_hash, (gpointer)(long)inotify_fd, mapping);

    g_strlcpy (path, repo->worktree, SEAF_PATH_MAX);
    if (add_watch_recursive (mapping, inotify_fd, path) < 0) {
        close (inotify_fd);
        g_hash_table_remove (priv->mapping_hash, (gpointer)(long)inotify_fd);
        return -1;
    }

    return inotify_fd;
}

static int handle_add_repo (SeafWTMonitorPriv *priv, const char *repo_id, long *handle) 
{
    int inotify_fd;

    inotify_fd = add_watch (priv, repo_id);
    if (inotify_fd < 0) {
        return -1;
    }

    FD_SET (inotify_fd, &priv->read_fds);
    priv->maxfd = MAX (inotify_fd, priv->maxfd);
    *handle = (long)inotify_fd;
    return 0;
}

static void
update_maxfd (SeafWTMonitorPriv *priv)
{
    GHashTableIter iter;
    gpointer key, value;
    int fd, maxfd = priv->cmd_pipe[0];

    g_hash_table_iter_init (&iter, priv->status_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        fd = (int) (long)key;
        if (fd > maxfd)
            maxfd = fd;
    }

    priv->maxfd = maxfd;
}

static int handle_rm_repo (SeafWTMonitorPriv *priv, gpointer handle)
{
    int inotify_fd = (int)(long)handle;

    close (inotify_fd);
    FD_CLR (inotify_fd, &priv->read_fds);
    update_maxfd (priv);

    g_hash_table_remove (priv->mapping_hash, (gpointer)(long)inotify_fd);

    return 0;
}

static int
refresh_watch (SeafWTMonitorPriv *priv, int inotify_fd, const char *repo_id)
{
    SeafRepo *repo;
    char path[SEAF_PATH_MAX];
    WatchPathMapping *mapping;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("[wt mon] cannot find repo %s.\n", repo_id);
        return -1;
    }

    mapping = g_hash_table_lookup (priv->mapping_hash, (gpointer)(long)inotify_fd);

    g_strlcpy (path, repo->worktree, SEAF_PATH_MAX);
    if (add_watch_recursive (mapping, inotify_fd, path) < 0) {
        return -1;
    }

    return 0;
}

static int handle_refresh_repo (SeafWTMonitorPriv *priv, const char *repo_id)
{
    gpointer key, value;
    if (!g_hash_table_lookup_extended (priv->handle_hash, repo_id, &key, &value))
        return -1;

    int inotify_fd = (int)(long)value;
    if (refresh_watch (priv, inotify_fd, repo_id) < 0)
        return -1;

    return 0;
}

#include "wt-monitor-common.h"
