/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <locale.h>

#include <glib/gi18n.h>
#include <gtk/gtk.h>

#include <ccnet.h>
#include "utils.h"

#include "seafile-applet.h"
#include "applet-common.h"
#include "trayicon.h"
#include "applet-log.h"

#include "misc.h"

#define SEAFILE_INI "seafile.ini"

SeafileApplet *applet;

static int
spawn_process (char *cmdline_in)
{
    GError *error = NULL;
    gboolean result;

    result = g_spawn_command_line_async((const char*)cmdline_in, &error);

    if (!result) {
        applet_warning ("Failed to spawn [%s] : %s", cmdline_in, error->message);
        return -1;
    }
    return 0;
}

int start_web_server ()
{
    applet_message ("Starting web ...\n");

    if (spawn_process("seafile-web start") < 0) {
        applet_warning ("Failed to start seafile web\n");
        applet_exit(-1);
    }

    applet->web_status = WEB_STARTED;

    return 0;
}

int
start_seafile_daemon ()
{
    GString *buf = g_string_new (NULL);

    applet_message ("Starting seafile ...\n");
    
    g_string_append_printf (buf, 
        "seaf-daemon -c \"%s\" -d \"%s\" -w \"%s\"",
        applet->config_dir, applet->seafile_dir, applet->seafile_worktree);
    
    if (spawn_process (buf->str) < 0) {
        applet_warning ("Failed to start seaf-daemon\n");
        applet_exit(-1);
    }

    g_string_free (buf, TRUE);
    return 0;
}

int ccnet_open_dir(const char *path)
{
    char buf[4096];
    snprintf (buf, 4096, "xdg-open '%s' &", path);
    if (system (buf) < 0) {
        applet_warning ("failed to exec: %s\n", buf);
        return -1;
    }
    return 0;
}

int
set_seafile_auto_start(int on)
{
    return 0;
}

static gboolean
client_io_cb (GIOChannel *source, GIOCondition condition, gpointer data)
{
    if (condition & G_IO_IN) {
        if (ccnet_client_read_input (applet->client) <= 0) {
            on_ccnet_daemon_down ();
            return FALSE;
        }
        return TRUE;
    } else {
        on_ccnet_daemon_down ();
        return FALSE;
    }
}

int
open_web_browser(const char *url)
{
    GString *buf = g_string_new("xdg-open ");
    g_string_append (buf, url);
    spawn_process (buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

void start_conn_daemon_timer (int timeout_ms, void *data)
{
    g_timeout_add (timeout_ms, connect_to_server, data);
}

static void
sigint_handler (int signo)
{
    on_quit ();

    signal (signo, SIG_DFL);
    raise (signo);
}

void on_quit ()
{
    stop_ccnet ();
    stop_web_server ();
    gtk_main_quit ();
}

void
seafile_applet_init (SeafileApplet *applet)
{
    applet->client = ccnet_client_new ();
    applet->sync_client = ccnet_client_new ();
    applet->icon = seafile_trayicon_new ();
}

int
main (int argc, char **argv)
{
    /* init i18n */
    setlocale (LC_ALL, "");
    bindtextdomain(GETTEXT_PACKAGE, SEAFILE_LOCALE_DIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
    textdomain(GETTEXT_PACKAGE);

    if (count_process("seafile-applet") > 1) {
        fprintf(stderr, _("Seafile is already running\n"));
        exit(1);
    }

    gtk_init (&argc, &argv);
    gtk_icon_theme_append_search_path (gtk_icon_theme_get_default(),
                                       PKGDATADIR);
    gtk_window_set_default_icon_name ("seafile");

    signal (SIGINT, sigint_handler);

    applet = g_new0 (SeafileApplet, 1);
    seafile_applet_init (applet);
    seafile_applet_start (argc, argv);

    applet_message ("seafile started\n");

    trayicon_set_tip ("Seafile");

    gtk_main ();

    return 0;
}

/*  The following functions are called by applet-common.c to implement common
 *  subroutines in win/linux/mac
 */

int 
spawn_ccnet_daemon ()
{
    if (!applet->config_dir)
        return -1;

    int ret;
    char buf[1024];

    ret = snprintf (buf, sizeof(buf), "ccnet -c \"%s\" -D Peer,"
                    "Message,Connection,Other",
                    applet->config_dir);
    if (ret > 0) {
        if (spawn_process (buf) < 0) {
            applet_warning ("Failed to fork ccnet\n");
            return -1;
        }
        return 0;
    }
    return -1;
}

int
stop_web_server ()
{
    if (applet->web_status != WEB_NOT_STARTED) {
        if (system("seafile-web stop") < 0) {
            applet_warning ("failed to stop web\n");
            return -1;
        }
        applet->web_status = WEB_NOT_STARTED;
    }

    return 0;
}

void add_client_fd_to_mainloop ()
{
    GIOChannel *channel;

    channel = g_io_channel_unix_new (applet->client->connfd);
    applet->client_io_id = g_io_add_watch (channel,
                                           G_IO_IN | G_IO_HUP | G_IO_ERR, 
                                           client_io_cb, NULL);
}

void rm_client_fd_from_mainloop ()
{
    g_source_remove (applet->client_io_id);
    applet->client_io_id = 0;
}


void
trayicon_set_ccnet_state (int state)
{
    char *name;

    if (state == CCNET_STATE_DOWN) {
        name = ICON_STATUS_DOWN;
    } else {
        if (applet->auto_sync_disabled) {
            name = ICON_AUTO_SYNC_DISABLED;
        } else {
            name = ICON_STATUS_UP;
        }
    }
    
    seafile_trayicon_set_icon (applet->icon, name);
}

void
trayicon_notify (char *title, char *buf)
{
    seafile_trayicon_notify (applet->icon, title, buf);
}

static int nth_trayicon = 0;
static int rotate_counter = 0;
static gboolean trayicon_is_rotating = FALSE;

static gboolean
do_rotate ()
{
    SeafileTrayIcon *icon = applet->icon;
    
    if (rotate_counter >= 8 || !trayicon_is_rotating || applet->auto_sync_disabled ) {
        trayicon_is_rotating = FALSE;
        reset_trayicon_and_tip (icon);
        return FALSE;
    }
        
    static char *names[] = { SEAFILE_TRANFER_1, SEAFILE_TRANFER_2,
                             SEAFILE_TRANFER_3, SEAFILE_TRANFER_4 };

    int index = nth_trayicon % G_N_ELEMENTS(names);
    char *name = names[index];
    
    seafile_trayicon_set_icon (icon, name);
                                
    nth_trayicon++;
    rotate_counter++;

    return TRUE;
}

void
trayicon_rotate (gboolean start)
{
    if (start) {
        rotate_counter = 0;
        if (!trayicon_is_rotating) {
            nth_trayicon = 0;
            trayicon_is_rotating = TRUE;
            g_timeout_add (250, do_rotate, NULL);
        }
        
    } else {
        trayicon_is_rotating = FALSE;
    }
}

void trayicon_set_tip (char *tip)
{
    if (!tip)
        return;

    seafile_trayicon_set_tooltip (applet->icon, tip);
}

gboolean
is_seafile_daemon_running ()
{
    return process_is_running ("seaf-daemon");
}

void
start_heartbeat_monitor_timer (int timeout_ms, void *data)
{
    applet_message ("[hearbeat mon] started.\n");
    applet->heartbeat_monitor_on = TRUE;
    g_timeout_add (timeout_ms, heartbeat_monitor, NULL);
}

static int open_browser_timer_id = 0;

void
start_open_browser_timer (int timeout_ms, void *data)
{
    open_browser_timer_id = g_timeout_add (timeout_ms,
                (GSourceFunc)on_open_browser_timeout, data);
}

void
stop_open_browser_timer()
{
    if (open_browser_timer_id) {
        g_source_remove (open_browser_timer_id);
        open_browser_timer_id = 0;
    }
}
