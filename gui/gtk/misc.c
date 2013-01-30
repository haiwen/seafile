/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include "utils.h"
#include "misc.h"
#include "config.h"

static GtkBuilder *
_get_all_widgets (const gchar *filename,
                  const gchar *first_required_widget,
                  va_list      args)
{
    GtkBuilder *builder;
	const char *name;
	GtkWidget **widget_ptr;
    GError *err = NULL;

	/* DEBUG ("Loading glade file %s", filename); */

    builder = gtk_builder_new ();
    gtk_builder_add_from_file (builder, filename, &err);

	if (err) {
		g_error ("Load UI file '%s' error: %s", filename, err->message);
	}

	for (name = first_required_widget; name; name = va_arg (args, char *)) {
		widget_ptr = va_arg (args, void *);

		*widget_ptr = (GtkWidget *) gtk_builder_get_object (builder, name);
     
		if (!*widget_ptr) {
			g_warning ("UI file '%s' is missing widget '%s'.\n",
                       filename, name);
			continue;
		}
	}

	return builder;
}


GtkBuilder *
gtk_builder_get_all_widgets (const gchar *filename,
                             const gchar *first_required_widget, ...)
{
	va_list   args;
    GtkBuilder *builder;

	va_start (args, first_required_widget);

	builder = _get_all_widgets (filename, first_required_widget, args);

	va_end (args);

	if (!builder)
		return NULL;

	return builder;
}

gchar *
ccnet_file_lookup (const gchar *filename, const gchar *subdir)
{
	gchar *path;

	if (!subdir) {
		subdir = ".";
	}

	path = g_build_filename (g_getenv ("CCNET_SRCDIR"), subdir, filename, NULL);
	if (!g_file_test (path, G_FILE_TEST_EXISTS)) {
		g_free (path);
		path = g_build_filename (PKGDATADIR, filename, NULL);
	}
	return path;
}

int
show_warning_dialog (GtkWindow *parent, const char *str)
{
    GtkWidget *dialog;
    int result;

    dialog = gtk_message_dialog_new (parent,
                                     GTK_DIALOG_MODAL,
                                     GTK_MESSAGE_WARNING,
                                     GTK_BUTTONS_OK,
                                     str,
                                     NULL);
    gtk_window_set_position (GTK_WINDOW(dialog), GTK_WIN_POS_CENTER);
    gtk_widget_show_all (dialog);
    result = gtk_dialog_run (GTK_DIALOG (dialog));
    gtk_widget_destroy (dialog);
    switch (result) {
    case GTK_RESPONSE_YES:
        return TRUE;
    default:
        return FALSE;
    }
}

