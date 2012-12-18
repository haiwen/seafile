/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 *
 * Copyright (C) 2009 Lingtao Pan
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, 
 * Boston, MA 02111-1307, USA.
 */

#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "utils.h"
#include "misc.h"
#include "ccnet-init.h"
#include "seafile-applet.h"

#define WARNING_MSG_TITLE "Seafile"

static GtkDialog       *dialog;
static GtkBuilder      *builder;

static void
show_warning (GtkWindow *window, const char *title, const char *warning_msg)
{
    GtkWidget *dg = gtk_message_dialog_new(
        window,
        GTK_DIALOG_DESTROY_WITH_PARENT,
        GTK_MESSAGE_WARNING,
        GTK_BUTTONS_OK,
        "%s", warning_msg);
    if (title)
        gtk_window_set_title(GTK_WINDOW(dg), title);
    else
        gtk_window_set_title(GTK_WINDOW(dg), "Warning");
    gtk_dialog_run(GTK_DIALOG(dg));
    gtk_widget_destroy(dg);
}


int show_init_seafile_window ()
{
    gchar           *filename;
    gchar           *dir;
    int              response;
    GtkButton       *seafiledir_filechooser;
    GtkLabel        *seafiledir_label;

    filename = ccnet_file_lookup ("init-seafile-window.ui", "gtk");
    builder = gtk_builder_get_all_widgets (
        filename,
        "dialog", &dialog,
        "seafiledir_label", &seafiledir_label,
        "seafiledir_filechooser", &seafiledir_filechooser,
        NULL);
    g_free (filename);
    g_object_unref (builder);

again:
    response = gtk_dialog_run (dialog);
    if (response != 2) {
        gtk_widget_destroy (GTK_WIDGET(dialog));
        return -1;
    }

    dir = gtk_file_chooser_get_filename (
        (GtkFileChooser *)seafiledir_filechooser);
    if (!dir) {
        show_warning (GTK_WINDOW(dialog), NULL,
                      "A directory should be selected");
        goto again;
    } 

    applet->seafile_dir = g_build_filename(dir, "seafile-data", NULL);
    gtk_widget_destroy (GTK_WIDGET(dialog));
    return 0;
}
