/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef TRAYICON_H_
#define TRAYICON_H_

#include "stdafx.h"
#include <shellapi.h>

#define WM_TRAYNOTIFY   WM_APP + 1
#define WM_SOCKET       WM_APP + 2

#ifndef NIN_BALLOONSHOW
    #define NIN_BALLOONSHOW     (WM_USER + 2)
#endif

#ifndef NIN_BALLOONHIDE
    #define NIN_BALLOONHIDE     (WM_USER + 3)
#endif

#ifndef NIN_BALLOONTIMEOUT
    #define NIN_BALLOONTIMEOUT  (WM_USER + 4)
#endif

#ifndef NIN_BALLOONUSERCLICK
    #define NIN_BALLOONUSERCLICK (WM_USER + 5)
#endif

typedef int (*MSGFunc) (UINT,WPARAM, LPARAM);

typedef struct _SeafileTrayIcon {
    NOTIFYICONDATAW nid;
} SeafileTrayIcon;

SeafileTrayIcon *trayicon_new();

void trayicon_init (SeafileTrayIcon *icon);

void trayicon_set_icon_by_id (SeafileTrayIcon *icon, UINT icon_id);

void trayicon_set_tooltip (SeafileTrayIcon *icon, char *tooltip,
                           int balloon, char *title,
                           unsigned int timeout);

void trayicon_delete_icon (SeafileTrayIcon *icon);
    
#endif
