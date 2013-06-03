#ifndef SEAFILE_GNOME_KEYRING_H
#define SEAFILE_GNOME_KEYRING_H

#include <glib.h>
#include <gnome-keyring.h>


char * gnome_keyring_sf_get_password(const char * repo_id, const char * type, guint *item_id);
int    gnome_keyring_sf_set_password(const char * repo_id, const char * type, const char * password);
int    gnome_keyring_sf_delete_password(const char * repo_id, const char * type);
#endif /* SEAFILE_GNOME_KEYRING_H */
