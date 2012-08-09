#include "platform.h"
#include "seaf-menu.h"
#include "seaf-utils.h"
#include "seaf-ext-log.h"
#include "menu-engine.h"


static NautilusMenuProvider *seaf_menu_provider;

/* This function is called when a user right-clicks on a file or several
 * selected files.
 */
GList *
seaf_get_file_items (NautilusMenuProvider *provider,
                     GtkWidget *window,
                     GList *files)
{
    return NULL;
}


/* This function is called to add menu items when a user right-clicks on the
 * background of a folder; However, it is called when the user entered the
 * folder, not at the point when the right-click takes place. And It would not
 * be refreshed unless the user clicks the "refresh" command. We can refresh
 * it by emitting `items-updated' signal on the `provider'. */
GList *
seaf_get_background_items (NautilusMenuProvider *provider,
                           GtkWidget *window,
                           NautilusFileInfo *current_folder)
{
    seaf_menu_provider = provider;

    GError *error = NULL;
    char *uri = nautilus_file_info_get_uri (current_folder);
    if (!uri)
        return NULL;

    char *name = g_filename_from_uri(uri, NULL, &error);
    g_free (uri);
    if (error || !name)
        return NULL;

    /* TODO: when to free this SeafMenu ? */
    SeafMenu *seaf_menu = g_new0(SeafMenu, 1);
    memcpy(seaf_menu->name, name, strlen(name) + 1);
    seaf_menu->menu_provider = provider;
    seaf_menu->window = window;
    seaf_menu->submenus = NULL;

    g_free (name);

    build_seafile_menu(seaf_menu);
    if (!seaf_menu->submenus) {
        return NULL;
    }

    NautilusMenuItem *item = nautilus_menu_item_new
        ("Seafile",                            /* Name */
         "Seafile",                            /* label */
         "Seafile",                            /* tooltips */
         SEAF_EXT_UI_DIR "seaf_ext" ICON_EXT); /* icon */
        
    NautilusMenu *naut_menu = nautilus_menu_new();
    nautilus_menu_item_set_submenu(item, naut_menu);

    GList *ptr = seaf_menu->submenus;
    for (; ptr; ptr = ptr->next) {
        NautilusMenuItem *item = ptr->data;
        nautilus_menu_append_item(naut_menu, item);
    }
    g_list_free(seaf_menu->submenus);

    GList *l = g_list_append(NULL, item);
    return l;
}


#if NAUTILUS_VERSION <= 2
GList *
seaf_get_toolbar_items (NautilusMenuProvider *provider,
                        GtkWidget *window,
                        NautilusFileInfo *current_folder)
{
    return NULL;
}
#endif

/* When a function is added to the main loop by g_idle_add_full(), the main
 * loop will execute this function on and on if it does not return `FALSE'.
 * Since nautilus_menu_provider_emit_items_updated_signal() itself doesn't
 * return FALSE, we need to wrap it.
 */
static bool item_updated_signal_wrapper(NautilusMenuProvider *provider)
{
    nautilus_menu_provider_emit_items_updated_signal(provider);
    return FALSE;
}

void send_refresh_menu_signal(NautilusMenuProvider *provider_in)
{
    NautilusMenuProvider *provider = NULL;

    if (provider_in)
        /* for update menu after handling a command */
        provider = provider_in;
    else
        /* for update menu periodically */
        provider = seaf_menu_provider;

    if (provider && NAUTILUS_IS_MENU_PROVIDER(provider)) {

        if (is_main_thread()) {
            nautilus_menu_provider_emit_items_updated_signal(provider);
        } else {
            /* not called from the main thread */
            g_idle_add_full
                (G_PRIORITY_DEFAULT_IDLE,
                 (GSourceFunc)item_updated_signal_wrapper,
                 provider, NULL);
        }
    }      
}

void reset_active_menu(SeafMenu *seaf_menu)
{
    seaf_menu->selection = SEAF_MI_ALWAYS;
}

bool build_menu_item(SeafMenu *seaf_menu, const struct menu_item *mi)
{
    if (!seaf_menu || !mi)
        return FALSE;

    char *name = mi->string;
    char *label = name;
    char *helptext = mi->helptext;
    char *icon = mi->icon;

    if (!name || !helptext)
        return TRUE;

    NautilusMenuItem *item = nautilus_menu_item_new
        (name,                  /* Name */
         label,                 /* label */
         helptext,              /* tooltips */
         icon);                 /* icon */

    if (!item) {
        seaf_ext_log ("Failed to create menu item");
        return FALSE;
    }
    if (mi->op != SEAF_NONE) {
        g_object_set_data_full((GObject *)item,
                               "seaf_menu",
                               seaf_menu,
                               NULL);

        g_signal_connect((GObject *)item,
                         "activate",
                         (GCallback)dispatch_menu_command,
                         (gpointer)&mi->op);

    }
    seaf_menu->submenus = g_list_append(seaf_menu->submenus, item);
    return TRUE;
}
