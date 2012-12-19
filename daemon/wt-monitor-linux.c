/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "common.h"

#include <sys/select.h>
#include <sys/inotify.h>
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

#define DIR_WATCH_MASK IN_CREATE | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO
#define FILE_WATCH_MASK IN_MODIFY | IN_ATTRIB

struct SeafWTMonitorPriv {
    GHashTable *handle_hash;        /* repo_id -> inotify_fd (or handle) */
    GHashTable *status_hash;    /* inotify_df (or handle) -> wt status */
    ccnet_pipe_t cmd_pipe[2];
    ccnet_pipe_t res_pipe[2];
    fd_set read_fds;
    int maxfd;
};

static void handle_watch_command (SeafWTMonitorPriv *priv, WatchCommand *cmd);

static int
add_watch_recursive (int in_fd, char *path, int pathlen)
{
    struct stat st;
    DIR *dir;
    struct dirent *dent;

    if (stat (path, &st) < 0) {
        seaf_warning ("[wt mon] fail to stat %s: %s\n", path, strerror(errno));
        return -1;
    }

    if (S_ISREG (st.st_mode)) {
        if (inotify_add_watch (in_fd, path, (uint32_t)FILE_WATCH_MASK) < 0) {
            seaf_warning ("[wt mon] fail to add watch to %s: %s.\n", path, strerror(errno));
            return -1;
        }
    } else if (S_ISDIR (st.st_mode)) {
        if (inotify_add_watch (in_fd, path, (uint32_t)DIR_WATCH_MASK) < 0) {
            seaf_warning ("[wt mon] fail to add watch to %s: %s.\n", path, strerror(errno));
            return -1;
        }

        dir = opendir (path);
        if (!dir) {
            seaf_warning ("[wt mon] fail to open dir %s: %s.\n", path, strerror(errno));
            return -1;
        }

        errno = 0;
        while (1) {
            dent = readdir (dir);
            if (!dent)
                break;
            if (strcmp (dent->d_name, ".") == 0 ||
                strcmp (dent->d_name, "..") == 0)
                continue;

            int len = snprintf (path + pathlen, SEAF_PATH_MAX, "/%s", dent->d_name);
            if (add_watch_recursive (in_fd, path, pathlen + len) < 0)
                return -1;
        }
        if (errno != 0) {
            seaf_warning ("[wt mon] fail to read dir: %s.\n", strerror(errno));
            return -1;
        }

        closedir (dir);
    }

    return 0;
}

static int
add_watch (const char *repo_id)
{
    SeafRepo *repo;
    int inotify_fd;
    char path[SEAF_PATH_MAX];

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

    g_strlcpy (path, repo->worktree, SEAF_PATH_MAX);
    if (add_watch_recursive (inotify_fd, path, strlen(path)) < 0) {
        close (inotify_fd);
        return -1;
    }

    return inotify_fd;
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

static int
refresh_watch (int inotify_fd, const char *repo_id)
{
    SeafRepo *repo;
    char path[SEAF_PATH_MAX];

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("[wt mon] cannot find repo %s.\n", repo_id);
        return -1;
    }

    g_strlcpy (path, repo->worktree, SEAF_PATH_MAX);
    if (add_watch_recursive (inotify_fd, path, strlen(path)) < 0) {
        return -1;
    }

    return 0;
}

static void *
wt_monitor_job (void *vmonitor)
{
    SeafWTMonitor *monitor = vmonitor;
    SeafWTMonitorPriv *priv = monitor->priv;
    /* 2 * sizeof(inotify_event) + 256, should be large enough for one event.*/
    WTStatus *status;

    WatchCommand cmd;
    int n;
    int rc;
    fd_set fds;
    int inotify_fd;
    char event_buf[(sizeof(struct inotify_event) << 1) + 256];
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
                /* We don't care about the details of the event now.
                 * So we just read out the data but don't parse it.
                 * We may read partial event structure.
                 */
                n = read (inotify_fd, event_buf, sizeof(event_buf));
                if (n <= 0) {
                    seaf_warning ("[wt mon] failed to read inotify event.\n");
                    continue;
                }
                status = value;
                if (status) {
                    g_atomic_int_set (&status->last_changed, (gint)time(NULL));
                }
            }
        }
    }

    return NULL;
}

static int handle_add_repo (SeafWTMonitorPriv *priv, const char *repo_id, long *handle) 
{
    int inotify_fd;
    g_assert (handle != NULL);
    inotify_fd = add_watch (repo_id);

    if (inotify_fd < 0)
        return -1;

    FD_SET (inotify_fd, &priv->read_fds);
    priv->maxfd = MAX (inotify_fd, priv->maxfd);
    *handle = (long)inotify_fd;
    return 0;
}

static int handle_rm_repo (SeafWTMonitorPriv *priv, gpointer handle)
{
    int inotify_fd = (int)(long)handle;
    close (inotify_fd);
    FD_CLR (inotify_fd, &priv->read_fds);
    update_maxfd (priv);
    return 0;
}

static int handle_refresh_repo (SeafWTMonitorPriv *priv, const char *repo_id)
{
    gpointer key, value;
    if (!g_hash_table_lookup_extended (priv->handle_hash, repo_id, &key, &value))
        return -1;

    int inotify_fd = (int)(long)value;
    if (refresh_watch (inotify_fd, repo_id) < 0)
        return -1;

    return 0;
}

#include "wt-monitor-common.h"
