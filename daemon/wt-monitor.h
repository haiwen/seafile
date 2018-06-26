#ifndef SEAF_WT_MONITOR_H
#define SEAF_WT_MONITOR_H

#include "wt-monitor-structs.h"
#include "utils.h"

typedef struct SeafWTMonitorPriv SeafWTMonitorPriv;

struct _SeafileSession;

typedef enum CommandType {
    CMD_ADD_WATCH,
    CMD_DELETE_WATCH,
    CMD_REFRESH_WATCH,
    N_CMD_TYPES,
} CommandType;

typedef struct WatchCommand {
    CommandType type;
    char repo_id[37];
    char worktree[SEAF_PATH_MAX];
} WatchCommand;

typedef struct SeafWTMonitor {
    struct _SeafileSession      *seaf;
    SeafWTMonitorPriv   *priv;

    seaf_pipe_t cmd_pipe[2];
    seaf_pipe_t res_pipe[2];

    /* platform dependent virtual functions */
    void* (*job_func) (void *);
} SeafWTMonitor;

SeafWTMonitor *
seaf_wt_monitor_new (struct _SeafileSession *seaf);

int
seaf_wt_monitor_start (SeafWTMonitor *monitor);

int
seaf_wt_monitor_watch_repo (SeafWTMonitor *monitor,
                            const char *repo_id,
                            const char *worktree);

int
seaf_wt_monitor_unwatch_repo (SeafWTMonitor *monitor, const char *repo_id);

int
seaf_wt_monitor_refresh_repo (SeafWTMonitor *monitor, const char *repo_id);

WTStatus *
seaf_wt_monitor_get_worktree_status (SeafWTMonitor *monitor,
                                     const char *repo_id);

#endif
