/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_GNOME_KEYRING_H
#define SEAF_GNOME_KEYRING_H

#include <glib.h>
#include <gnome-keyring.h>


char * 
gnome_keyring_sf_get_password(const char * repo_id,
                              const char * type,
							  guint *item_id);

int
gnome_keyring_sf_set_password(const char * repo_id,
                              const char * type,
							  const char * password);

int
gnome_keyring_sf_delete_password(const char * repo_id,
                                 const char * type);
#endif /* SEAF_GNOME_KEYRING_H */