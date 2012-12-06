/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <wchar.h>
#include <glib/gi18n.h>
#include <ccnet.h>

#ifdef SEAF_LANG_CHINESE
    #include "resource.h"
#else
    #include "resource.en.h"
#endif
#include "trayicon.h"
#include "seafile-applet.h"
#include "applet-common.h"
#include "applet-log.h"
#include "utils.h"

SeafileTrayIcon *
trayicon_new ()
{
    SeafileTrayIcon *icon = g_new0 (SeafileTrayIcon, 1);

    return icon;
}

static void
trayicon_set_icon (SeafileTrayIcon *icon, HICON hIcon)
{
    int ret;
    unsigned int msg;
    HICON prev_icon;

    if (!hIcon || hIcon == icon->nid.hIcon)
        return;

    msg = icon->nid.hIcon? NIM_MODIFY : NIM_ADD;

    prev_icon = icon->nid.hIcon;
    icon->nid.hIcon = hIcon;
    icon->nid.uFlags = NIF_ICON;

    ret = Shell_NotifyIconW (msg, &icon->nid);

    if (!ret) {
        applet_warning ("trayicon_set_icon failed, GLE=%lu\n", GetLastError());
        icon->nid.hIcon = prev_icon;
    }
}

extern int tray_notify_cb(UINT message, WPARAM wParam, LPARAM lParam);
extern int tray_command_cb(UINT message, WPARAM wParam, LPARAM lParam);
extern int tray_socket_cb(UINT message, WPARAM wParam, LPARAM lParam);

static LRESULT CALLBACK
WndProc (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    SeafileTrayIcon *icon = applet->icon;
    if (!icon)
        return DefWindowProc (hWnd, message, wParam, lParam);

    switch(message) {
    case WM_CLOSE:
        applet_message ("WM_CLOSE received, now exit\n");
        applet_exit(0);
        break;

    case WM_TRAYNOTIFY:
        if(wParam != icon->nid.uID)
            return S_FALSE;
        return tray_notify_cb(message, wParam, lParam);
        break;

    case WM_COMMAND:
        return tray_command_cb(message, wParam, lParam);
        break;

    case WM_SOCKET:
        return tray_socket_cb(message, wParam, lParam);
        break;

    default:
        if (message == applet->WM_TASKBARCREATED) {
            /* Restore applet trayicon when taskbar is re-created. This normally
             * happens when explorer is restarted.
             */
            applet_message ("WM_TASKBARCREATED received\n");
            trayicon_init (applet->icon);
        }
        break;
    }


    return DefWindowProc (hWnd, message, wParam, lParam);
}

static void
create_applet_window ()
{
    WNDCLASSEX wcex;

    memset(&wcex, 0, sizeof(WNDCLASSEX));
    wcex.cbSize         = sizeof(WNDCLASSEX);
    wcex.lpfnWndProc    = (WNDPROC)WndProc;
    wcex.hInstance      = applet->hInstance;
    wcex.lpszClassName  = "seafile-applet";
    wcex.hIcon          = LoadIcon(applet->hInstance, MAKEINTRESOURCE(IDI_SEAFILE_ICON));

    RegisterClassEx(&wcex);
    applet->hWnd = CreateWindow("seafile-applet", "seafile-applet",
                                WS_OVERLAPPED, 0, 0, 0, 0,
                                NULL, NULL, applet->hInstance, NULL);

    if (!applet->hWnd) {
        DWORD e = GetLastError();
        g_warning("create window error: %lu", e);
        applet_exit(1);
    }
}

static BOOL
_trayicon_init (SeafileTrayIcon *icon)
{
    if (!applet->hWnd)
        create_applet_window ();

    UINT icon_id;
    if (applet->client && applet->client->connected)
        icon_id = IDI_STATUS_UP;
    else
        icon_id = IDI_STATUS_DOWN;

    icon->nid.cbSize = sizeof(NOTIFYICONDATAW);
    icon->nid.hWnd = applet->hWnd;
    icon->nid.uID = 0;
    icon->nid.hIcon = LoadIcon(applet->hInstance, MAKEINTRESOURCE(icon_id));
    icon->nid.uCallbackMessage = WM_TRAYNOTIFY;

    wchar_t *tip_w = L"Seafile";

    wmemcpy (icon->nid.szTip, tip_w, wcslen(tip_w));

    icon->nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;

    return Shell_NotifyIconW(NIM_ADD, &(icon->nid));
}

static int trayicon_init_retried = 0;

static void CALLBACK
trayicon_init_retry (HWND hwnd, UINT message, UINT iTimerID, DWORD dwTime)
{
    if (trayicon_init_retried++ >= 3) {
        applet_exit(1);
    }

    if (_trayicon_init(applet->icon)) {
        applet_message ("trayicon inited succesfully in retry\n");
        KillTimer (hwnd, iTimerID);
    } else {
        applet_warning ("trayicon init failed, retry = %d, GLE=%lu\n",
                        trayicon_init_retried,
                        GetLastError());
    }
}


void
trayicon_init (SeafileTrayIcon *icon)
{
    if (!_trayicon_init(icon)) {
        applet_warning ("trayicon init failed, GLE=%lu\n", GetLastError());
        SetTimer (NULL, TRAYICON_INIT_RETRY_TIMER_ID, 1000, trayicon_init_retry);
    }
}


/* Copy at most n wchar from src to dst, also make sure dst is null terminated */
static void
safe_wcsncpy (wchar_t *dst, const wchar_t *src, int n)
{
    int srclen= wcslen (src);

    if (srclen < n) {
        /* dst has enough space  */
        wcscpy (dst, src);
    } else if (srclen >= n) {
        /* dst is not big enough */
        wmemcpy (dst, src, n - 1);
        dst[n - 1] = L'\0';
    }
}

void
trayicon_set_tooltip (SeafileTrayIcon *icon, char *tooltip,
                      int balloon, char *title,
                      unsigned int timeout)
{
    wchar_t *tip_w = NULL;
    wchar_t *title_w = NULL;

    if (tooltip) {
        tip_w = wchar_from_utf8 (tooltip ? tooltip : "");
        if (!tip_w) {
            goto out;
        }
    }

    if (title) {
        title_w = wchar_from_utf8 (title ? title : "");
        if (!title_w) {
            goto out;
        }
    }

    icon->nid.cbSize = sizeof(NOTIFYICONDATAW);
    if (balloon) {
        icon->nid.uFlags      = NIF_INFO;
        icon->nid.uTimeout    = timeout;
        icon->nid.dwInfoFlags = NIIF_INFO;

        safe_wcsncpy (icon->nid.szInfo, tip_w,
                        sizeof(icon->nid.szInfo) / sizeof(wchar_t));
        safe_wcsncpy (icon->nid.szInfoTitle, title_w,
                        sizeof(icon->nid.szInfoTitle) / sizeof(wchar_t));

    } else {
        icon->nid.uFlags = NIF_TIP;
        safe_wcsncpy (icon->nid.szTip, tip_w,
                        sizeof(icon->nid.szInfo) / sizeof(wchar_t));
    }

    Shell_NotifyIconW(NIM_MODIFY, &(icon->nid));
out:
    g_free (tip_w);
    g_free (title_w);
}

void
trayicon_set_icon_by_id(SeafileTrayIcon *icon, UINT icon_id)
{
    HICON hIcon = LoadIcon(applet->hInstance, MAKEINTRESOURCE(icon_id));
    if (hIcon) {
        trayicon_set_icon (icon, hIcon);
    } else {
        applet_warning ("can't find icon %u\n", icon_id);
    }
}


void
trayicon_delete_icon (SeafileTrayIcon *icon)
{
    Shell_NotifyIconW(NIM_DELETE, &(icon->nid));
}

