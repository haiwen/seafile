/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"

#include "utils.h"
#include "wt-monitor.h"
#define DEBUG_FLAG SEAFILE_DEBUG_WATCH
#include "log.h"

#include "job-mgr.h"

int
seaf_wt_monitor_start (SeafWTMonitor *monitor)
{
    if (seaf_pipe (monitor->cmd_pipe) < 0) {
        seaf_warning ("[wt mon] failed to create command pipe: %s.\n",
                      strerror(errno));
        return -1;
    }

    if (seaf_pipe (monitor->res_pipe) < 0) {
        seaf_warning ("[wt mon] failed to create result pipe: %s.\n",
                      strerror(errno));
        return -1;
    }

    if (seaf_job_manager_schedule_job (monitor->seaf->job_mgr,
                                       monitor->job_func,
                                       NULL, monitor) < 0) {
        seaf_warning ("[wt mon] failed to start monitor thread.\n");
        return -1;
    }

    return 0;
}

int
seaf_wt_monitor_watch_repo (SeafWTMonitor *monitor,
                            const char *repo_id,
                            const char *worktree)
{
    WatchCommand cmd;
    int res;

    memset (&cmd, 0, sizeof(cmd));
    memcpy (cmd.repo_id, repo_id, 37);
    cmd.type = CMD_ADD_WATCH;
    g_strlcpy (cmd.worktree, worktree, SEAF_PATH_MAX);

    int n = seaf_pipe_writen (monitor->cmd_pipe[1], &cmd, sizeof(cmd));
    
    if (n != sizeof(cmd)) {
        seaf_warning ("[wt mon] fail to write command pipe.\n");
        return -1;
    }

    seaf_debug ("send a watch command, repo %s\n", repo_id);

    n = seaf_pipe_readn (monitor->res_pipe[0], &res, sizeof(int));
    if (n != sizeof(int)) {
        seaf_warning ("[wt mon] fail to read result pipe.\n");
        return -1;
    }

    return res;
}

int
seaf_wt_monitor_unwatch_repo (SeafWTMonitor *monitor, const char *repo_id)
{
    WatchCommand cmd;
    int res;

    memset (&cmd, 0, sizeof(cmd));
    memcpy (cmd.repo_id, repo_id, 37);
    cmd.type = CMD_DELETE_WATCH;

    int n = seaf_pipe_writen (monitor->cmd_pipe[1], &cmd, sizeof(cmd));

    if (n != sizeof(cmd)) {
        seaf_warning ("[wt mon] fail to write command pipe.\n");
        return -1;
    }

    seaf_debug ("send an unwatch command, repo %s\n", repo_id);

    n = seaf_pipe_readn (monitor->res_pipe[0], &res, sizeof(int));
    if (n != sizeof(int)) {
        seaf_warning ("[wt mon] fail to read result pipe.\n");
        return -1;
    }

    return res;
}

int
seaf_wt_monitor_refresh_repo (SeafWTMonitor *monitor, const char *repo_id)
{
    WatchCommand cmd;
    int res;

    memset (&cmd, 0, sizeof(cmd));
    memcpy (cmd.repo_id, repo_id, 37);
    cmd.type = CMD_REFRESH_WATCH;

    int n = seaf_pipe_writen (monitor->cmd_pipe[1], &cmd, sizeof(cmd));

    if (n != sizeof(cmd)) {
        seaf_warning ("[wt mon] fail to write command pipe.\n");
        return -1;
    }

    seaf_debug ("send a refresh command, repo %s\n", repo_id);

    n = seaf_pipe_readn (monitor->res_pipe[0], &res, sizeof(int));
    if (n != sizeof(int)) {
        seaf_warning ("[wt mon] fail to read result pipe.\n");
        return -1;
    }

    return res;
}
