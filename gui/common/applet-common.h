#ifndef APPLET_COMMON_H
#define APPLET_COMMON_H

/* Common subroutines for win/linux/mac */

#include <glib.h>

#define SEAHUB_OFFICIAL_REGISTER_ADDR "http://cloud.seafile.com.cn/accounts/register"

#define SEAF_HTTP_ADDR "http://127.0.0.1:13420"
#define SEAFILE_WEBSITE "http://www.seafile.com/"

void applet_exit (int code);
int seafile_applet_start (int argc, char **argv);

void stop_ccnet (void);
void restart_all (void);

int connect_to_daemon (void);
void on_ccnet_daemon_down (void);

void start_heartbeat_monitor (void);
void stop_heartbeat_monitor (void);
gboolean heartbeat_monitor_running (void);

gboolean test_web_server (void);
gboolean on_open_browser_timeout(void);
gboolean connect_to_server (gpointer data);
gboolean heartbeat_monitor (void *data);

void send_command (const char *command);

int is_repo_path_allowed(const char *path);

typedef struct {
    gboolean disable;
} SetAutoSyncData;

void seafile_disable_auto_sync (void);
void seafile_enable_auto_sync (void);

enum {
    CCNET_STATE_UP = 0,
    CCNET_STATE_DOWN,
    CCNET_STATE_AUTOSYNC_DISABLED
};

#define SEAF_HTTP_ADDR "http://127.0.0.1:13420"

#endif
