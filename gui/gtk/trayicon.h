/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef TRAYICON_H
#define TRAYICON_H

#include <glib.h>

#define SEAFILE_TYPE_TRAY_ICON         (seafile_tray_icon_get_type ())
#define SEAFILE_TRAY_ICON(o)           (G_TYPE_CHECK_INSTANCE_CAST ((o), SEAFILE_TYPE_TRAY_ICON, SeafileTrayIcon))
#define SEAFILE_TRAY_ICON_CLASS(k)     (G_TYPE_CHECK_CLASS_CAST((k), SEAFILE_TYPE_TRAY_ICON, SeafileTrayIconClass))
#define SEAFILE_IS_TRAY_ICON(o)        (G_TYPE_CHECK_INSTANCE_TYPE ((o), SEAFILE_TYPE_TRAY_ICON))
#define SEAFILE_IS_TRAY_ICON_CLASS(k)  (G_TYPE_CHECK_CLASS_TYPE ((k), SEAFILE_TYPE_TRAY_ICON))
#define SEAFILE_TRAY_ICON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), SEAFILE_TYPE_TRAY_ICON, SeafileTrayIconClass))

typedef struct _SeafileTrayIcon      SeafileTrayIcon;
typedef struct _SeafileTrayIconClass SeafileTrayIconClass;

typedef struct SeafileTrayIconPriv SeafileTrayIconPriv;

struct _SeafileTrayIcon {
        GObject parent;
        SeafileTrayIconPriv *priv;
};

struct _SeafileTrayIconClass {
        GObjectClass parent_class;
};

GType seafile_trayicon_get_type (void);

SeafileTrayIcon *seafile_trayicon_new ();

#define ICON_STATUS_UP	    "ccnet_daemon_up"
#define ICON_STATUS_DOWN    "ccnet_daemon_down"
#define ICON_AUTO_SYNC_DISABLED    "seafile_auto_sync_disabled"

#define SEAFILE_TRANFER_1   "seafile_transfer_1"
#define SEAFILE_TRANFER_2   "seafile_transfer_2"
#define SEAFILE_TRANFER_3   "seafile_transfer_3"
#define SEAFILE_TRANFER_4   "seafile_transfer_4"

void seafile_trayicon_set_icon (SeafileTrayIcon *icon, const char *name);

void seafile_trayicon_notify (SeafileTrayIcon *icon, char *title, char *buf);

void seafile_trayicon_set_tooltip (SeafileTrayIcon *icon, const char *tooltip);

void reset_trayicon_and_tip (SeafileTrayIcon *icon);

#endif /* __SEAFILE_TRAY_ICON_H__ */
