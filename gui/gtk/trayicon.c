/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <config.h>
#include <unistd.h>

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <libnotify/notify.h>

#include "misc.h"
#include "trayicon.h"
#include "seafile-applet.h"
#include "applet-common.h"
#include "rpc-wrapper.h"
#include "applet-log.h"

#ifdef HAVE_APP_INDICATOR
    #include <libappindicator/app-indicator.h>
#endif


struct SeafileTrayIconPriv {
#ifdef HAVE_APP_INDICATOR
    AppIndicator        *icon;
#else
    GtkStatusIcon       *icon;
#endif
    GtkWidget           *popup_menu;
    GtkAction           *start_action;
    GtkAction           *quit_action;
    GtkAction           *restart_action;
    GtkAction           *disable_auto_sync_action;
    GtkAction           *enable_auto_sync_action;
};

#define GET_PRIV(o)  \
    (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_TRAY_ICON, SeafileTrayIconPriv))

G_DEFINE_TYPE (SeafileTrayIcon, seafile_tray_icon, G_TYPE_OBJECT);

static void
tray_icon_popup_menu_cb (GtkStatusIcon     *tray_icon,
                         guint              button,
                         guint              activate_time,
                         SeafileTrayIcon   *icon);


void
seafile_trayicon_set_icon (SeafileTrayIcon *icon, const char *name)
{
    SeafileTrayIconPriv *priv = GET_PRIV (icon);

#ifdef HAVE_APP_INDICATOR
    const char *desktop;
    desktop = g_getenv ("XDG_CURRENT_DESKTOP");
    if (g_strcmp0(desktop, "Unity") == 0) {
        app_indicator_set_icon_full (priv->icon, name, NULL);
    } else {
        gtk_status_icon_set_from_icon_name (priv->icon, name);
    }
#else
    gtk_status_icon_set_from_icon_name (priv->icon, name);
#endif
}

static void
tray_icon_quit_cb (GtkAction *action, SeafileTrayIcon *icon)
{
    on_quit ();
}

static void
restart_menu_cb (GtkAction       *action,
                 SeafileTrayIcon *icon)
{
    reset_trayicon_and_tip(icon);
    restart_all();
}

static void
open_browser_cb (GtkAction *action, SeafileTrayIcon *icon)
{
    open_web_browser(SEAF_HTTP_ADDR);
}

static void
tray_icon_popup_menu_cb (GtkStatusIcon     *tray_icon,
                         guint              button,
                         guint              activate_time,
                         SeafileTrayIcon   *icon)
{
    SeafileTrayIconPriv *priv = GET_PRIV (icon);

    gtk_menu_popup (GTK_MENU (priv->popup_menu),
                    NULL, NULL,
                    gtk_status_icon_position_menu,
                    priv->icon,
                    button,
                    activate_time);
}

void reset_trayicon_and_tip(SeafileTrayIcon *icon)
{
    char *name;
    char *tip = "Seafile";
    
    if (!applet->client->connected) {
        name = ICON_STATUS_DOWN;
    } else {
        if (applet->auto_sync_disabled) {
            name = ICON_AUTO_SYNC_DISABLED;
            tip = _("Auto sync is disabled");
        } else {
            name = ICON_STATUS_UP;
        }
    }

    seafile_trayicon_set_icon (icon, name);
    seafile_trayicon_set_tooltip (icon, tip);
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
        
    } else {
        if (disable) {
            /* auto sync is disabled */
            gtk_action_set_visible(applet->icon->priv->disable_auto_sync_action, FALSE);
            gtk_action_set_visible(applet->icon->priv->enable_auto_sync_action, TRUE);
        } else {
            /* auto sync is enabled */
            gtk_action_set_visible(applet->icon->priv->disable_auto_sync_action, TRUE);
            gtk_action_set_visible(applet->icon->priv->enable_auto_sync_action, FALSE);
        }

        applet->auto_sync_disabled = disable;

        reset_trayicon_and_tip(applet->icon);
    }

    g_free (sdata);
}

static void
disable_auto_sync (GtkAction *action, SeafileTrayIcon *icon)
{
    seafile_disable_auto_sync();
}

static void
enable_auto_sync (GtkAction *action, SeafileTrayIcon *icon)
{
    seafile_enable_auto_sync();
}

static void
tray_icon_create_menu (SeafileTrayIcon *icon)
{
    SeafileTrayIconPriv *priv = GET_PRIV (icon);
    GtkBuilder *builder;
    gchar *filename;

    filename = ccnet_file_lookup ("seafile-trayicon.ui", "gtk");
    builder = gtk_builder_get_all_widgets (filename,
    /* builder = gtk_builder_get_all_widgets ("seafile-trayicon.ui", */
                       "popup_menu", &priv->popup_menu,
                       "quit_action", &priv->quit_action,
                       "start_action", &priv->start_action,
                       "restart_network_action", &priv->restart_action,
                       "disable_auto_sync_action", &priv->disable_auto_sync_action,
                       "enable_auto_sync_action", &priv->enable_auto_sync_action,
                       NULL);
    g_free (filename);
    g_object_ref (priv->popup_menu);
    g_object_unref (builder);

    gtk_action_set_visible (priv->disable_auto_sync_action, TRUE);
    gtk_action_set_visible (priv->enable_auto_sync_action, FALSE);
    
    g_signal_connect (priv->quit_action, "activate",
                      G_CALLBACK (tray_icon_quit_cb), icon);
    g_signal_connect (priv->restart_action, "activate",
                      G_CALLBACK (restart_menu_cb), icon);
    g_signal_connect (priv->start_action, "activate",
                      G_CALLBACK (open_browser_cb), icon);

    g_signal_connect (priv->disable_auto_sync_action, "activate",
                      G_CALLBACK (disable_auto_sync), icon);
    g_signal_connect (priv->enable_auto_sync_action, "activate",
                      G_CALLBACK (enable_auto_sync), icon);
}

static void
seafile_trayicon_finalize (GObject *object)
{
    SeafileTrayIconPriv *priv = GET_PRIV (object);

    g_object_unref (priv->icon);
}

static void
seafile_tray_icon_class_init (SeafileTrayIconClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS (klass);

    object_class->finalize = seafile_trayicon_finalize;

    g_type_class_add_private (object_class, sizeof (SeafileTrayIconPriv));
}


static void
seafile_tray_icon_init (SeafileTrayIcon *icon)
{
    SeafileTrayIconPriv *priv = G_TYPE_INSTANCE_GET_PRIVATE (icon,
        SEAFILE_TYPE_TRAY_ICON, SeafileTrayIconPriv);

    icon->priv = priv;

#ifdef HAVE_APP_INDICATOR
    const char *desktop;
    desktop = g_getenv ("XDG_CURRENT_DESKTOP");
    if (g_strcmp0(desktop, "Unity") == 0) {
        AppIndicator *app_icon = app_indicator_new("seafile",
                                               ICON_STATUS_UP,
                                               APP_INDICATOR_CATEGORY_APPLICATION_STATUS);
        app_indicator_set_status (app_icon, APP_INDICATOR_STATUS_ACTIVE);
        app_indicator_set_icon_theme_path (app_icon, PKGDATADIR);

        priv->icon = app_icon;
        tray_icon_create_menu (icon);
        app_indicator_set_menu(APP_INDICATOR(icon->priv->icon),
                               GTK_MENU(priv->popup_menu));
    } else {
        priv->icon = gtk_status_icon_new ();
        tray_icon_create_menu (icon);
        g_signal_connect (icon->priv->icon, "popup-menu",
                          G_CALLBACK (tray_icon_popup_menu_cb),
                          icon);
        g_signal_connect (priv->icon, "activate",
                          G_CALLBACK (open_browser_cb),
                          icon);
    }
#else
    priv->icon = gtk_status_icon_new ();
    tray_icon_create_menu (icon);
    g_signal_connect (icon->priv->icon, "popup-menu",
                      G_CALLBACK (tray_icon_popup_menu_cb),
                      icon);
    g_signal_connect (priv->icon, "activate",
                      G_CALLBACK (open_browser_cb),
                      icon);
#endif

    notify_init("Seafile");
}

SeafileTrayIcon *
seafile_trayicon_new (GtkWindow *window)
{
    SeafileTrayIcon *icon;

    icon = g_object_new (SEAFILE_TYPE_TRAY_ICON, NULL);

    seafile_trayicon_set_icon (icon, ICON_STATUS_UP);

    return icon;
}

static GtkStatusIcon *
seafile_trayicon_get_gtk_icon (SeafileTrayIcon *icon)
{
#ifdef HAVE_APP_INDICATOR
    const char *desktop;
    desktop = g_getenv ("XDG_CURRENT_DESKTOP");
    if (g_strcmp0(desktop, "Unity") == 0) {
        return NULL;
    } else
        return (GtkStatusIcon *)(icon->priv->icon);
#else
    return (GtkStatusIcon *)(icon->priv->icon);
#endif
}

void seafile_trayicon_notify (SeafileTrayIcon *icon, char *title, char *buf)
{
    NotifyNotification *n;
    GtkStatusIcon *gtk_icon = seafile_trayicon_get_gtk_icon(icon);

    /* notify_notification_new_with_status_icon doesn't exists in
       libnotify version > 0.7 */
#ifdef LIBNOTIFY_GREAT_THAN_7
    if (gtk_icon) {
        const char *name = gtk_status_icon_get_icon_name (gtk_icon);
        n = notify_notification_new (title, buf, name);
    } else {
        n = notify_notification_new (title, buf, NULL);
    }
#else
    n = notify_notification_new_with_status_icon (title, buf,
                                                  "Seafile", gtk_icon);
#endif

    notify_notification_set_timeout (n, 2000);
    notify_notification_show (n, NULL);
    g_object_unref (n);
}

void
seafile_trayicon_set_tooltip (SeafileTrayIcon *icon,
                              const char *tooltip)
{
#ifdef HAVE_APP_INDICATOR
    const char *desktop;
    desktop = g_getenv ("XDG_CURRENT_DESKTOP");
    if (g_strcmp0(desktop, "Unity") == 0) {
        /* do nothing */
    } else {
        gtk_status_icon_set_tooltip_text (icon->priv->icon, tooltip);
    }
#else
    gtk_status_icon_set_tooltip_text (icon->priv->icon, tooltip);
#endif
}
