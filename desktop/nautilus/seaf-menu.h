#ifndef SEAF_MENU_H
#define SEAF_MENU_H

#include <glib.h>
#include <libnautilus-extension/nautilus-menu-provider.h>

typedef struct SeafMenu SeafMenu;

struct SeafMenu {
    NautilusMenuProvider *menu_provider;
    GList *submenus;
    GtkWidget *window;

    unsigned int count;
    unsigned int selection;
    char name[MAX_PATH];      /* the file/dir current clicked on */
    char repo_id[37];         /* set if in a repo dir */
    char repo_wt[MAX_PATH];   /* repo top wt, set if in a repo dir */
};


GList *
seaf_get_file_items (NautilusMenuProvider *provider,
                     GtkWidget *window,
                     GList *files);


GList *
seaf_get_background_items (NautilusMenuProvider *provider,
                           GtkWidget *window,
                           NautilusFileInfo *current_folder);


GList *
seaf_get_toolbar_items (NautilusMenuProvider *provider,
                   GtkWidget *window,
                   NautilusFileInfo *current_folder);

void send_refresh_menu_signal(NautilusMenuProvider *menu_provider);

#endif
