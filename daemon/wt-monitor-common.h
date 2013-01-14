/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef WT_MONITOR_COMMON_H
#define WT_MONITOR_COMMON_H

SeafWTMonitor *
seaf_wt_monitor_new (SeafileSession *seaf)
{
    SeafWTMonitor *monitor = g_new0 (SeafWTMonitor, 1);
    SeafWTMonitorPriv *priv = g_new0 (SeafWTMonitorPriv, 1);

    priv->handle_hash = g_hash_table_new_full
        (g_str_hash, g_str_equal, g_free, NULL);

    priv->status_hash = g_hash_table_new_full
        (g_direct_hash, g_direct_equal, NULL, g_free);

#ifdef WIN32
    priv->buf_hash = g_hash_table_new_full
        (g_direct_hash, g_direct_equal, NULL, NULL);
#endif

#ifdef __linux__
    priv->mapping_hash = g_hash_table_new_full (g_direct_hash, g_direct_equal,
                                                NULL, (GDestroyNotify)free_mapping);
#endif

    monitor->priv = priv;
    monitor->seaf = seaf;

    return monitor;
}


int
seaf_wt_monitor_start (SeafWTMonitor *monitor)
{
    SeafWTMonitorPriv *priv = monitor->priv;

    if (ccnet_pipe (priv->cmd_pipe) < 0) {
        seaf_warning ("[wt mon] failed to create command pipe: %s.\n", strerror(errno));
        return -1;
    }

    if (ccnet_pipe (priv->res_pipe) < 0) {
        seaf_warning ("[wt mon] failed to create result pipe: %s.\n", strerror(errno));
        return -1;
    }

    if (ccnet_job_manager_schedule_job (monitor->seaf->job_mgr,
                                        wt_monitor_job,
                                        NULL, monitor) < 0) {
        seaf_warning ("[wt mon] failed to start monitor thread.\n");
        return -1;
    }

    return 0;
}

int
seaf_wt_monitor_watch_repo (SeafWTMonitor *monitor, const char *repo_id)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    WatchCommand cmd;
    int res;

    memcpy (cmd.repo_id, repo_id, 37);
    cmd.type = CMD_ADD_WATCH;

    int n = pipewriten (priv->cmd_pipe[1], &cmd, sizeof(cmd));
    
    if (n != sizeof(cmd)) {
        seaf_warning ("[wt mon] fail to write command pipe.\n");
        return -1;
    }

    seaf_debug ("send a watch command, repo %s\n", repo_id);

    n = pipereadn (priv->res_pipe[0], &res, sizeof(int));
    if (n != sizeof(int)) {
        seaf_warning ("[wt mon] fail to read result pipe.\n");
        return -1;
    }

    return res;
}

int
seaf_wt_monitor_unwatch_repo (SeafWTMonitor *monitor, const char *repo_id)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    WatchCommand cmd;
    int res;

    memcpy (cmd.repo_id, repo_id, 37);
    cmd.type = CMD_DELETE_WATCH;

    int n = pipewriten (priv->cmd_pipe[1], &cmd, sizeof(cmd));

    if (n != sizeof(cmd)) {
        seaf_warning ("[wt mon] fail to write command pipe.\n");
        return -1;
    }

    seaf_debug ("send an unwatch command, repo %s\n", repo_id);

    n = pipereadn (priv->res_pipe[0], &res, sizeof(int));
    if (n != sizeof(int)) {
        seaf_warning ("[wt mon] fail to read result pipe.\n");
        return -1;
    }

    return res;
}

int
seaf_wt_monitor_refresh_repo (SeafWTMonitor *monitor, const char *repo_id)
{
    SeafWTMonitorPriv *priv = monitor->priv;
    WatchCommand cmd;
    int res;

    memcpy (cmd.repo_id, repo_id, 37);
    cmd.type = CMD_REFRESH_WATCH;

    int n = pipewriten (priv->cmd_pipe[1], &cmd, sizeof(cmd));

    if (n != sizeof(cmd)) {
        seaf_warning ("[wt mon] fail to write command pipe.\n");
        return -1;
    }

    seaf_debug ("send a refresh command, repo %s\n", repo_id);

    n = pipereadn (priv->res_pipe[0], &res, sizeof(int));
    if (n != sizeof(int)) {
        seaf_warning ("[wt mon] fail to read result pipe.\n");
        return -1;
    }

    return res;
}

WTStatus *
seaf_wt_monitor_get_worktree_status (SeafWTMonitor *monitor,
                                     const char *repo_id)
{
    gpointer key, value;

    if (!g_hash_table_lookup_extended (monitor->priv->handle_hash, repo_id,
                                       &key, &value))
        return NULL;

    return (WTStatus *)g_hash_table_lookup(monitor->priv->status_hash, value);
}

static void
reply_watch_command (SeafWTMonitorPriv *priv, int result)
{
    int n;

    n = pipewriten (priv->res_pipe[1], &result, sizeof(int));
    if (n != sizeof(int))
        seaf_warning ("[wt mon] fail to write command result.\n");
}

static void
handle_watch_command (SeafWTMonitorPriv *priv, WatchCommand *cmd)
{
    long inotify_fd;
    WTStatus *status;

    if (cmd->type == CMD_ADD_WATCH) {
        if (g_hash_table_lookup_extended (priv->handle_hash, cmd->repo_id, NULL, NULL)) {
            reply_watch_command (priv, 0);
            return;
        }

        if (handle_add_repo(priv, cmd->repo_id, &inotify_fd) < 0) {
            seaf_warning ("[wt mon] failed to watch worktree of repo %s.\n", cmd->repo_id);
            reply_watch_command (priv, -1);
            return;
        }

        g_hash_table_insert (priv->handle_hash, g_strdup(cmd->repo_id), (gpointer)(long)inotify_fd);
        status = g_new0 (WTStatus, 1);
        memcpy (status->repo_id, cmd->repo_id, 37);
        g_hash_table_insert (priv->status_hash, (gpointer)(long)inotify_fd, status);

        seaf_debug ("[wt mon] add watch for repo %s\n", cmd->repo_id);
        reply_watch_command (priv, 0);
    } else if (cmd->type == CMD_DELETE_WATCH) {
        gpointer key, value;
        if (!g_hash_table_lookup_extended (priv->handle_hash, cmd->repo_id, &key, &value)) {
            reply_watch_command (priv, 0);
            return;
        }

        g_hash_table_remove (priv->handle_hash, cmd->repo_id);
        g_hash_table_remove (priv->status_hash, value);
        handle_rm_repo (priv, value);
        reply_watch_command (priv, 0);
    } else if (cmd->type ==  CMD_REFRESH_WATCH) {
        if (handle_refresh_repo (priv, cmd->repo_id) < 0) {
            seaf_warning ("[wt mon] failed to refresh watch of repo %s.\n", cmd->repo_id);
            reply_watch_command (priv, -1);
            return;
        }
        reply_watch_command (priv, 0);
    }
}

#endif
