/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

    ret = Shell_NotifyIcon (msg, &icon->nid);
    
    if (!ret) {
        applet_warning ("Shell_NotifyIcon() failed, GLE=%lu\n", GetLastError());
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

void
trayicon_init (SeafileTrayIcon *icon)
{
    if (!applet->hWnd)
        create_applet_window ();

    UINT icon_id;
    if (applet->client && applet->client->connected)
        icon_id = IDI_STATUS_UP;
    else 
        icon_id = IDI_STATUS_DOWN;
    
    icon->nid.cbSize = sizeof(NOTIFYICONDATA);
    icon->nid.hWnd = applet->hWnd;
    icon->nid.uID = 0;
    icon->nid.hIcon = LoadIcon(applet->hInstance, MAKEINTRESOURCE(icon_id));
    icon->nid.uCallbackMessage = WM_TRAYNOTIFY;

    memcpy(icon->nid.szTip, "Seafile", 8);

    icon->nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    Shell_NotifyIcon(NIM_ADD, &(icon->nid));
}

/* Copy at most n bytes from src to dest. Ensure the content in dest is
 * null-terminated. */
static void
safe_strncpy (char *dest, const char *src, int n)
{
    int srclen= strlen(src);

    if (srclen < n) {
        memcpy (dest, src, srclen + 1);
    } else if (srclen >= n) {
        memcpy (dest, src, n - 1);
        dest[n - 1] = '\0';
    }
}

void
trayicon_set_tooltip(SeafileTrayIcon *icon, LPCTSTR tooltip,
                     int balloon, LPCTSTR title,
                     unsigned int timeout)
{
    const char *tp = tooltip ? tooltip : "";
    const char *tt = title ? title : "";

    icon->nid.cbSize = sizeof(NOTIFYICONDATA);
    if (balloon) {
        icon->nid.uFlags      = NIF_INFO;
        icon->nid.uTimeout    = timeout;
        icon->nid.dwInfoFlags = NIIF_INFO;

        safe_strncpy (icon->nid.szInfo, tp, sizeof(icon->nid.szInfo));

        safe_strncpy (icon->nid.szInfoTitle, tt, sizeof(icon->nid.szInfoTitle));
        
    } else {
        icon->nid.uFlags = NIF_TIP;
        safe_strncpy (icon->nid.szTip, tp, sizeof(icon->nid.szTip));
    }
    
    Shell_NotifyIcon(NIM_MODIFY, &(icon->nid));
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
    Shell_NotifyIcon(NIM_DELETE, &(icon->nid));
}

