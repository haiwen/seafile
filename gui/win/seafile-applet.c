/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <glib/gi18n.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <evutil.h>
#include <string.h>

#include <ccnet.h>

#include "stdafx.h"
#ifdef SEAF_LANG_CHINESE
    #include "resource.h"
#else
    #include "resource.en.h"
#endif

#include "utils.h"
#include "applet-common.h"
#include "trayicon.h"
#include "applet-log.h"
#include "rpc-wrapper.h"
#include "seafile-applet.h"

#define GETTEXT_PACKAGE "seafile"
#define STARTWEBSERVER "seafile-web.exe 127.0.0.1:13420"
#define WEB_PROCESS_NAME "seafile-web.exe"

SeafileApplet *applet;
/* In UTF-8 */
char *seafile_bin_dir = NULL;

void
on_quit ()
{
    stop_web_server();
    stop_ccnet ();
    if (applet->icon)
        trayicon_delete_icon(applet->icon);
}

extern BOOL first_use;

static void CALLBACK
TestWebServer (HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime)
{
    if (test_web_server()) {
        KillTimer(hwnd, iTimerID);

        applet_message ("Web server is up.\n");

        applet->web_status = WEB_READY;
        if (first_use) {
            trayicon_notify (_("Seafile is started"), _("Click the icon to open admin console"));
        }
    }
}

static void
reset_trayicon_and_tip()
{
    UINT id;
    char *tip = "Seafile";

    if (!applet->client->connected) {
        id = IDI_STATUS_DOWN;
    } else {
        if (applet->auto_sync_disabled) {
            id = IDI_STATUS_AUTO_SYNC_DISABLED;
            tip = _("Auto sync is disabled");
        } else {
            id = IDI_STATUS_UP;
        }
    }

    trayicon_set_icon_by_id (applet->icon, id);
    trayicon_set_tip (tip);
}


int
start_web_server ()
{
    applet_message ("Starting web ...\n");

    if (win32_spawn_process (STARTWEBSERVER, NULL) < 0) {
        applet_warning ("Failed to start seafile web\n");
        applet_exit(-1);
    }

    applet->web_status = WEB_STARTED;
    return 0;
}

int
start_seafile_daemon ()
{
    applet_message ("Starting seaf-daemon ...\n");
    applet_message ("data dir:      %s\n", applet->seafile_dir);
    applet_message ("worktree dir:  %s\n", applet->seafile_worktree);

    char buf[4096];

    snprintf (buf, sizeof(buf), "seaf-daemon.exe -c \"%s\" -d \"%s\" -w \"%s\"",
              applet->config_dir, applet->seafile_dir, applet->seafile_worktree);

    if (win32_spawn_process (buf, NULL) < 0) {
        applet_warning ("Failed to start seaf-daemon\n");
        applet_exit(-1);
    }

    return 0;
}

int
ccnet_open_dir (const char *path)
{
    wchar_t *path_w = wchar_from_utf8 (path);
    ShellExecuteW (0, L"open", path_w, NULL, NULL, SW_SHOWNORMAL);

    g_free (path_w);
    return 0;
}

static LONG
get_win_run_key (HKEY *pKey)
{
    const char *key_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    LONG result = RegOpenKeyEx(
        /* We don't use HKEY_LOCAL_MACHINE here because that requires
         * seaf-daemon to run with admin privilege. */
                               HKEY_CURRENT_USER,
                               key_run,
                               0L,KEY_WRITE | KEY_READ,
                               pKey);
    if (result != ERROR_SUCCESS) {
        applet_warning("Failed to open Registry key %s\n", key_run);
    }

    return result;
}

static int
add_to_auto_start (const wchar_t *appname_w, const wchar_t *path_w)
{
    HKEY hKey;
    LONG result = get_win_run_key(&hKey);
    if (result != ERROR_SUCCESS) {
        return -1;
    }

    DWORD n = sizeof(wchar_t) * (wcslen(path_w) + 1);

    result = RegSetValueExW (hKey, appname_w,
                             0, REG_SZ, (const BYTE *)path_w, n);

    RegCloseKey(hKey);
    if (result != ERROR_SUCCESS) {
        applet_warning("Failed to create auto start value\n");
        return -1;
    }

    return 0;
}

static int
delete_from_auto_start(const char *appname)
{
    HKEY hKey;
    LONG result = get_win_run_key(&hKey);
    if (result != ERROR_SUCCESS) {
        return -1;
    }

    result = RegDeleteValue (hKey, appname);
    RegCloseKey(hKey);
    if (result != ERROR_SUCCESS) {
        applet_warning("Failed to remove auto start value for %s\n", appname);
        return -1;
    }

    return 0;
}

int
get_seafile_auto_start()
{
    HKEY hKey;
    LONG result = get_win_run_key(&hKey);
    if (result != ERROR_SUCCESS) {
        return -1;
    }

    char buf[SEAF_PATH_MAX] = {0};
    DWORD len = sizeof(buf);
    result = RegQueryValueEx (hKey,             /* Key */
                              "Seafile",        /* value */
                              NULL,             /* reserved */
                              NULL,             /* output type */
                              (LPBYTE)buf,      /* output data */
                              &len);            /* output length */

    RegCloseKey(hKey);
    if (result != ERROR_SUCCESS) {
        /* seafile applet auto start no set  */
        return 0;
    }

    return 1;
}

int
set_seafile_auto_start(int on)
{
    int result = 0;
    if (on) {
        /* turn on auto start  */
        wchar_t applet_path[SEAF_PATH_MAX];
        if (GetModuleFileNameW (NULL, applet_path, SEAF_PATH_MAX) == 0) {
            return -1;
        }

        result = add_to_auto_start (L"Seafile", applet_path);

    } else {
        /* turn off auto start */
        result = delete_from_auto_start("Seafile");
    }
    return result;
}

static UINT_PTR open_browser_timer_id = 0;

/*
 *  After spawning the ccnet.exe process;
 *
 *  1. Connect to daemon
 *  2. spawn seaf-daemon, sefile-web
 *  3. start rpc server & rpc client
 *  4. open browser when 13420 port can be connected
 */
static void CALLBACK
ConnDaemonProc (HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime)
{
    if (connect_to_daemon() < 0) {
        return;
    }
    applet_message ("Connected to ccnet.\n");

    KillTimer (hwnd, iTimerID);

    start_seafile_daemon ();
    start_heartbeat_monitor ();
    start_web_server ();

    open_browser_timer_id = SetTimer (NULL, OPEN_BROWSER_TIMER_ID,
                                      1000, TestWebServer);
}

int
open_web_browser(const char *url)
{
    ShellExecute(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
    return 0;
}

/*
   Tray icon callback functions.
*/

int
tray_notify_cb(UINT message, WPARAM uID, LPARAM lEvent)
{
    switch(LOWORD(lEvent)) {
    case WM_RBUTTONUP: {
        HINSTANCE hInstance = applet->hInstance;
        HMENU hMenu = LoadMenu(hInstance, MAKEINTRESOURCE(IDC_STARTINTRAY));

        if (applet->web_status == WEB_READY)
            EnableMenuItem (hMenu, IDM_OPEN, MF_ENABLED);
        else
            EnableMenuItem (hMenu, IDM_OPEN, MF_GRAYED);

        if (applet->auto_sync_disabled) {
            EnableMenuItem (hMenu, IDM_ENABLE_AUTO_SYNC, MF_ENABLED);
            EnableMenuItem (hMenu, IDM_DISABLE_AUTO_SYNC, MF_GRAYED);
        } else {
            EnableMenuItem (hMenu, IDM_DISABLE_AUTO_SYNC, MF_ENABLED);
            EnableMenuItem (hMenu, IDM_ENABLE_AUTO_SYNC, MF_GRAYED);
        }

        /* Always allow restarting. */
        EnableMenuItem (hMenu, IDM_RESTART, MF_ENABLED);

        hMenu = GetSubMenu(hMenu, 0);

        HWND hWnd = applet->hWnd;
        SetForegroundWindow(hWnd);

        POINT pos;
        GetCursorPos(&pos);
        TrackPopupMenu(hMenu, 0, pos.x, pos.y, 0, hWnd, NULL);
        DestroyMenu(hMenu);

        break;
    }

    case WM_MOUSEMOVE:
        break;

    case WM_LBUTTONUP:
        if (applet->web_status == WEB_READY) {
            open_web_browser (SEAF_HTTP_ADDR);
        }
        break;

    case NIN_BALLOONUSERCLICK: {
        if (applet->last_synced_repo[0] != '\0') {
            char *repo = applet->last_synced_repo;
            if (repo[0]) {
                char buf[128];
                snprintf (buf, sizeof(buf), SEAF_HTTP_ADDR "/repo/?repo=%s", repo);
                open_web_browser (buf);
                memset(repo, 0, sizeof(applet->last_synced_repo));
            }
        }
        break;
    }
    case NIN_BALLOONHIDE:
    case NIN_BALLOONTIMEOUT:
        memset(applet->last_synced_repo, 0, sizeof(applet->last_synced_repo));
        break;
    default:
        break;
    }
    return TRUE;
}

void
set_auto_sync_cb (void *result, void *data, GError *error)
{
    SetAutoSyncData *sdata = data;
    gboolean disable = sdata->disable;

    if (error) {
        applet_warning ("failed to %s sync: %s\n",
                        disable ? "disable" : "enable",
                        error->message);

        wchar_t *msg = wchar_from_utf8 (disable ?
                                        _("Failed to disable auto sync") :
                                        _("Failed to enable auto sync"));
        MessageBoxW (NULL, msg, L"Seafile", MB_OK);

        g_free (msg);

    } else {
        HINSTANCE hInstance = applet->hInstance;
        HMENU hMenu = LoadMenu(hInstance, MAKEINTRESOURCE(IDC_STARTINTRAY));
        if (disable) {
            /* auto sync is disabled */
            EnableMenuItem (hMenu, IDM_ENABLE_AUTO_SYNC, MF_ENABLED);
            EnableMenuItem (hMenu, IDM_DISABLE_AUTO_SYNC, MF_GRAYED);
        } else {
            /* auto sync is enabled */
            EnableMenuItem (hMenu, IDM_DISABLE_AUTO_SYNC, MF_ENABLED);
            EnableMenuItem (hMenu, IDM_ENABLE_AUTO_SYNC, MF_GRAYED);
        }

        applet->auto_sync_disabled = disable;

        reset_trayicon_and_tip();
    }

    g_free (sdata);
}

int
tray_command_cb (UINT message, WPARAM wParam, LPARAM lParam)
{
    switch(wParam) {
    case IDM_OPEN:
        if (applet->web_status == WEB_READY) {
            open_web_browser (SEAF_HTTP_ADDR);
        }
        break;

    case IDM_DISABLE_AUTO_SYNC: {
        seafile_disable_auto_sync();
        break;
    }

    case IDM_ENABLE_AUTO_SYNC: {
        seafile_enable_auto_sync();
        break;
    }

    case IDM_RESTART:
        trayicon_rotate (FALSE);
        restart_all();
        break;

    case IDM_EXIT:
        PostQuitMessage(0);
        applet_exit(0);
        break;

    default:
        break;
    }

    return TRUE;
}

int
tray_socket_cb (UINT message, WPARAM wParam, LPARAM lParam)
{
    if (WSAGETSELECTERROR(lParam)) {
        closesocket(wParam);
        on_ccnet_daemon_down ();
        return FALSE;
    }

    switch (WSAGETSELECTEVENT(lParam)) {
    case FD_READ:
        if (ccnet_client_read_input (applet->client) <= 0) {
            on_ccnet_daemon_down ();
            return FALSE;
        }
        return TRUE;

    case FD_CLOSE:
        closesocket(wParam);
        on_ccnet_daemon_down ();
        break;
    }
    return TRUE;
}


/**
   Since we'll spawn various child processes, including
   ccnet/seaf-daemon/ccnetweb, we need first setup the current working
   directory. Without this setup, auto start when system boots up would not
   work.
**/
static int
set_applet_wd()
{
    wchar_t module_path[SEAF_PATH_MAX];
    wchar_t *bindir_w = NULL;
    char *module_path_utf8 = NULL;

    if (GetModuleFileNameW (NULL, module_path, SEAF_PATH_MAX) == 0) {
        applet_warning ("Failed to get module name\n");
        return -1;
    }

    module_path_utf8 = wchar_to_utf8 (module_path);
    seafile_bin_dir = g_path_get_dirname (module_path_utf8);
    if (!seafile_bin_dir) {
        return -1;
    }

    bindir_w = wchar_from_utf8 (seafile_bin_dir);
    if (!bindir_w) {
        return -1;
    }

    if (!SetCurrentDirectoryW (bindir_w)) {
        applet_warning ("Failed to set working directory for ccnet-applet: %lu\n",
                        GetLastError());
        return -1;
    }

    g_free (module_path_utf8);
    g_free (bindir_w);
    return 0;
}

static void
seafile_applet_init (HINSTANCE hInstance)
{
    applet->hInstance = hInstance;
    applet->WM_TASKBARCREATED = RegisterWindowMessage ("TaskbarCreated");

    applet->client = ccnet_client_new ();
    applet->sync_client = ccnet_client_new ();
    applet->icon = trayicon_new ();

    trayicon_init (applet->icon);
}

int
WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    if (set_applet_wd() < 0)
        return -1;

    char *seafile_locale_dir = g_build_filename (seafile_bin_dir,
                                                 "i18n", NULL);
    char *locale = g_win32_getlocale();

    /* init i18n */
    setlocale (LC_ALL, locale);
    bindtextdomain(GETTEXT_PACKAGE, seafile_locale_dir);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
    textdomain(GETTEXT_PACKAGE);

    g_free (seafile_locale_dir);
    g_free (locale);

    if (count_process("seafile-applet") > 1) {
        char *msg = _("Seafile is already running");
        wchar_t *msg_w = wchar_from_utf8 (msg);
        MessageBoxW (NULL, msg_w, L"Seafile", MB_OK);
        exit(1);
    }

    int argc;
    char **argv;
    char cmdbuf[1024];
    GError *err = NULL;

    WSADATA     wsadata;
    WSAStartup(0x0101, &wsadata);

    UNREFERENCED_PARAMETER(hPrevInstance);

    snprintf(cmdbuf, sizeof(cmdbuf), "seafile-applet.exe %s", lpCmdLine);

    if (!g_shell_parse_argv (cmdbuf, &argc, &argv, &err)) {
        if (err)
            applet_warning ("parse arguments failed %s\n", err->message);
        applet_exit(1);
    }

    g_type_init();

    applet = g_new0 (SeafileApplet, 1);

    seafile_applet_init (hInstance);
    seafile_applet_start (argc, argv);

    MSG msg;
    HACCEL hAccelTable;

    memset(&msg, 0, sizeof(msg));
    hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_STARTINTRAY));

    while (GetMessage(&msg, NULL, 0, 0)) {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    return (int) msg.wParam;
}

/*  The following functions are called by applet-common.c to implement common
 *  subroutines in win/linux/mac
 */

int
spawn_ccnet_daemon ()
{
    if (!applet->config_dir)
        return -1;

    char buf[4096];
    snprintf (buf, sizeof(buf),
              "ccnet.exe -c \"%s\" -D Peer,Message,Connection,Other",
              applet->config_dir);

    if (win32_spawn_process (buf, NULL) < 0) {
        applet_warning ("Failed to fork ccnet.exe\n");
        return -1;
    }

    return 0;
}

int stop_web_server()
{
    win32_kill_process (WEB_PROCESS_NAME);
    applet->web_status = WEB_NOT_STARTED;

    return 0;
}

void
add_client_fd_to_mainloop ()
{
    WSAAsyncSelect(applet->client->connfd, applet->hWnd,
                   WM_SOCKET, FD_READ | FD_CLOSE);
}

void
rm_client_fd_from_mainloop ()
{
}

void
start_conn_daemon_timer (int timeout_ms, void *data)
{
    SetTimer (NULL, CONNECT_TO_DAEMON_TIMER_ID, timeout_ms, ConnDaemonProc);
}

void
trayicon_set_ccnet_state (int state)
{
    UINT id;
    if (state == CCNET_STATE_DOWN) {
        id = IDI_STATUS_DOWN;
    } else {
        if (applet->auto_sync_disabled) {
            id = IDI_STATUS_AUTO_SYNC_DISABLED;
        } else {
            id = IDI_STATUS_UP;
        }
    }

    trayicon_set_icon_by_id (applet->icon, id);
}

void
trayicon_notify (char *title, char *buf)
{
    trayicon_set_tooltip (applet->icon, buf, TRUE, title, 3);
}

static int nth_trayicon = 0;
static int rotate_counter = 0;
static gboolean trayicon_is_rotating = FALSE;

static void CALLBACK
do_rotate (HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime)
{
    if (rotate_counter >= 8 || !trayicon_is_rotating || applet->auto_sync_disabled) {
        trayicon_is_rotating = FALSE;
        KillTimer(hwnd, iTimerID);
        reset_trayicon_and_tip();
        return;
    }
    trayicon_set_icon_by_id (applet->icon,
                             IDI_STATUS_TRANSFER_1 + (nth_trayicon % 4));
    nth_trayicon++;
    rotate_counter++;
}

/* Once trayicon_rotate(TRUE) is called, the icon begins to rotate, and stops
   when either one of the below happens:

   1. trayicon_rotate(TRUE) is not called in two seconds.
   2. trayicon_rotate(FALSE) is called to force stop rotation immediately.
      This happens when restarting ccnet.
 */

void trayicon_rotate (gboolean start)
{
    if (start) {
        rotate_counter = 0;
        if (!trayicon_is_rotating) {
            nth_trayicon = 0;
            trayicon_is_rotating = TRUE;
            SetTimer (NULL, ROTATE_TRAYICON_TIMER_ID, 250, do_rotate);
        }

    } else {
        trayicon_is_rotating = FALSE;
    }
}

void trayicon_set_tip (char *tip)
{
    if (!tip)
        return;

    trayicon_set_tooltip (applet->icon, tip, FALSE, NULL, 0);
}

static void CALLBACK
heartbeat_monitor_wrapper (HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime)
{
    if (!heartbeat_monitor (NULL))
        KillTimer(hwnd, iTimerID);
}

void
start_heartbeat_monitor_timer (int timeout_ms, void *data)
{
    applet_message ("[heartbeat mon] started.\n");
    applet->heartbeat_monitor_on = TRUE;
    SetTimer (NULL, HEARTBEAT_MONITOR_TIMER_ID, timeout_ms,
              heartbeat_monitor_wrapper);
}

gboolean is_seafile_daemon_running ()
{
    return process_is_running ("seaf-daemon");
}

void
start_open_browser_timer (int timeout_ms, void *data)
{
    open_browser_timer_id = SetTimer (NULL, OPEN_BROWSER_TIMER_ID,
                                      timeout_ms, TestWebServer);
}

void
stop_open_browser_timer()
{
    if (open_browser_timer_id != 0) {
        KillTimer(NULL, open_browser_timer_id);
        open_browser_timer_id = 0;
    }
}
