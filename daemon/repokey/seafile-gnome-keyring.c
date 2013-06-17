/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <stdio.h>
 
#include <glib.h>
#include "gnome-keyring.h"

#include "seafile-gnome-keyring.h"

#define SEAFILE_GK_ATTR_APP_NAME  "seafile"
#define SEAFILE_GK_ATTR_APP_VALUE "seaf-daemon"
#define SEAFILE_GK_ATTR_REPO_NAME "repo_id"
#define SEAFILE_GK_ATTR_TYPE_NAME "type"

char * gnome_keyring_sf_get_password(const char * repo_id, const char * type, guint *item_id)
{
    GnomeKeyringAttributeList * attributes;
    GnomeKeyringResult result;
    GList * found_list;
    GList * i;
    GnomeKeyringFound * found;
    char * password = NULL;
     
    attributes = g_array_new(FALSE, FALSE, sizeof (GnomeKeyringAttribute));
    gnome_keyring_attribute_list_append_string(attributes,
        SEAFILE_GK_ATTR_APP_NAME,
        SEAFILE_GK_ATTR_APP_VALUE);
    gnome_keyring_attribute_list_append_string(attributes,
        SEAFILE_GK_ATTR_REPO_NAME,
        repo_id);
    gnome_keyring_attribute_list_append_string(attributes,
        SEAFILE_GK_ATTR_TYPE_NAME,
        type);
          
    result = gnome_keyring_find_items_sync(GNOME_KEYRING_ITEM_GENERIC_SECRET,
        attributes,
        &found_list);

    gnome_keyring_attribute_list_free(attributes);

        *item_id = -1;     
    if (result != GNOME_KEYRING_RESULT_OK)
        return NULL;
     
    for (i = found_list; i != NULL; i = i->next) {
        found = i->data;
        password = g_strdup(found->secret);
                *item_id = found->item_id;
             break;
    }
    gnome_keyring_found_list_free(found_list);

    return password;
}

int gnome_keyring_sf_set_password(const char * repo_id, const char * type, const char * password) 
{
    GnomeKeyringAttributeList * attributes;
    GnomeKeyringResult result; guint item_id;
     
    attributes = g_array_new(FALSE,
                             FALSE,
                             sizeof (GnomeKeyringAttribute));
                             
    gnome_keyring_attribute_list_append_string(attributes,
                                               SEAFILE_GK_ATTR_APP_NAME,
                                               SEAFILE_GK_ATTR_APP_VALUE);
    gnome_keyring_attribute_list_append_string(attributes,
                                               SEAFILE_GK_ATTR_REPO_NAME,
                                               repo_id);
    gnome_keyring_attribute_list_append_string(attributes,
                                               SEAFILE_GK_ATTR_TYPE_NAME,
                                               type);
     
    result = gnome_keyring_item_create_sync(NULL,
                                            GNOME_KEYRING_ITEM_GENERIC_SECRET,
                                            "seafile repository",
                                            attributes,
                                            password,
                                            TRUE,
                                            &item_id);

    gnome_keyring_attribute_list_free(attributes);
     
    return (result == GNOME_KEYRING_RESULT_OK);
}

int gnome_keyring_sf_delete_password(const char * repo_id, const char * type)
{
    guint item_id;
    GnomeKeyringResult result;
    char * tmp = NULL;

    tmp = gnome_keyring_sf_get_password(repo_id, type, &item_id);
    g_free(tmp);
    result = gnome_keyring_item_delete_sync(NULL, item_id);

    return (result == GNOME_KEYRING_RESULT_OK);    
}
