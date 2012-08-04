/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
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

#ifndef GUI_MISC_H
#define GUI_MISC_H

void gtk_builder_get_all_widgets_simple (const char *filename,
                                         const char *first_required_widget, 
                                         ...);

GtkBuilder* gtk_builder_get_all_widgets (const char *filename,
                                         const char *first_required_widget, 
                                         ...);

gchar *ccnet_file_lookup (const gchar *filename, const gchar *subdir);

char *ccnet_ask_user_input (const char *title, GtkWindow *parent);
int show_confirm_dialog (GtkWindow *parent, const char *str);

#endif
