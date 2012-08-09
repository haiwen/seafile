/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/* 
   Seafile Nautilus extension type implentation file.
*/


#include <glib.h>
#include <glib-object.h>
#include <libnautilus-extension/nautilus-menu-provider.h>

#include "platform.h"

#include "seaf-ext.h"
#include "seaf-menu.h"
#include "seaf-ext-log.h"
#include "seaf-utils.h"


static void
seaf_ext_init (SeafExt *self)
{
    seaf_ext_log ("seafile extension instance init");
    g_object_ref(self);
}


static void
seaf_ext_class_init (SeafExtClass *klass)
{
    seaf_ext_log ("seafile extension class init");
}


static void
seaf_ext_class_finalize(SeafExtClass *klass)
{
    seaf_ext_log ("seafile ext class finalize");
    seaf_ext_log_stop();
}

static void
menu_iface_init (gpointer g_iface, gpointer iface_data)
{
    seaf_ext_log ("menu_iface_init");
    NautilusMenuProviderIface *menu_iface = g_iface;

    menu_iface->get_file_items = seaf_get_file_items;
    menu_iface->get_background_items = seaf_get_background_items;
#if NAUTILUS_VERSION <= 2
    menu_iface->get_toolbar_items = seaf_get_toolbar_items;
#endif    
}


/* Currently only the menu-provider interface is implentated */

G_DEFINE_DYNAMIC_TYPE_EXTENDED
(SeafExt, seaf_ext, G_TYPE_OBJECT, 0,
 G_IMPLEMENT_INTERFACE_DYNAMIC (NAUTILUS_TYPE_MENU_PROVIDER,
                                (GInterfaceInitFunc)menu_iface_init))


static GType seaf_ext_types[1];

void
nautilus_module_initialize (GTypeModule  *module) 
{
    seaf_ext_log("nautilus_module_initialize");

    if (!seaf_ext_mutex_init()) {
        seaf_ext_log ("failed to init cache mutex");
    }

    seaf_ext_register_type(module);
    seaf_ext_types[0] = seaf_ext_get_type();
}


void 
nautilus_module_shutdown (void)
{
    /* Any module-specific shutdown */
    seaf_ext_log ("module shut down");
    seaf_ext_log_stop();
}


void
nautilus_module_list_types (const GType **types,
                            int *num_types)
{
    seaf_ext_log("nautilus_module_list_types");
    *types = seaf_ext_types;
    *num_types = G_N_ELEMENTS(seaf_ext_types);
}
