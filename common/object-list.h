/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef OBJECT_LIST_H
#define OBJECT_LIST_H

#include <glib.h>

typedef struct {
    GHashTable  *obj_hash;
    GPtrArray   *obj_ids;
} ObjectList;


ObjectList *
object_list_new ();

void
object_list_free (ObjectList *ol);

void
object_list_serialize (ObjectList *ol, uint8_t **buffer, uint32_t *len);

/**
 * Add object to ObjectList.
 * Return FALSE if it is already in the list, TRUE otherwise. 
 */
gboolean
object_list_insert (ObjectList *ol, const char *object_id);

inline static gboolean
object_list_exists (ObjectList *ol, const char *object_id)
{
    return (g_hash_table_lookup(ol->obj_hash, object_id) != NULL);
}

inline static int
object_list_length (ObjectList *ol)
{
    return ol->obj_ids->len;
}

#endif
