#ifndef SEAFILE_APPLET_H
#define SEAFILE_APPLET_H

#include <glib.h>
#include <time.h>
#include <searpc-client.h>


#define APP_NAME "Seafile"

enum {
    WEB_NOT_STARTED = 0,
    WEB_STARTED,
    WEB_READY
};

typedef struct _SeafileApplet SeafileApplet;

struct _SeafileApplet {
    struct _CcnetClient             *client;
    struct _CcnetClient             *sync_client;
    struct _CcnetMqclientProc       *mqclient_proc;

    SearpcClient                    *seafile_rpc_client;
    SearpcClient                    *ccnet_rpc_client;

    time_t                          last_heartbeat;
    char                            last_synced_repo[128];

    char                            *config_dir;
    char                            *seafile_dir;
    char                            *seafile_worktree;

    int                             login_status;
    guint                           web_status;
    gboolean                        heartbeat_monitor_on;

    gboolean                        auto_sync_disabled;

#ifndef __APPLE__
    struct _SeafileTrayIcon         *icon;
    int                             client_io_id;
#endif

#ifdef WIN32
    HINSTANCE                       hInstance;
    HWND                            hWnd;
    UINT                            WM_TASKBARCREATED;
#endif
};

extern SeafileApplet *applet;

/**
 *  The following functions are platform-dependent stuff needed to implment in
 *  win/linux/mac. "applet-common.c" need them to implement common
 *  subroutines.
 */

int spawn_ccnet_daemon (void);
int start_seafile_daemon(void);
int is_seafile_daemon_running(void);
int start_web_server(void);
int stop_web_server(void);

void add_client_fd_to_mainloop (void);
void rm_client_fd_from_mainloop (void);

void start_conn_daemon_timer (int timeout_ms, void *data);
void start_heartbeat_monitor_timer (int timeout_ms, void *data);
void start_open_browser_timer (int timeout_ms, void *data);
void stop_open_browser_timer (void);

/* All string parameters to trayicon related functions are UTF-8 encoded */
void trayicon_set_ccnet_state (int state);
void trayicon_notify (char *title, char *buf);
void trayicon_rotate (gboolean start);
void trayicon_set_tip (char *tip);

int open_web_browser(const char *url);
void on_quit(void);

int show_init_seafile_window (void);
int ccnet_open_dir(const char *path);
int set_seafile_auto_start(int on);

#ifdef WIN32

int get_seafile_auto_start (void);

#define CONNECT_TO_DAEMON_TIMER_ID  1
#define OPEN_BROWSER_TIMER_ID       2
#define QUERY_LOGIN_TIMER_ID        3
#define ROTATE_TRAYICON_TIMER_ID    4
#define QUERY_REPO_CREATE_TIMER_ID  5
#define WAIT_CALC_DIR_TIMER_ID      6
#define HEARTBEAT_MONITOR_TIMER_ID  7
#define TRAYICON_INIT_RETRY_TIMER_ID  8

#endif


#endif
