/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "object-list.h"


ObjectList *
object_list_new ()
{
    ObjectList *ol = g_new0 (ObjectList, 1);

    ol->obj_hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);
    ol->obj_ids = g_ptr_array_new_with_free_func (g_free);

    return ol;
}

void
object_list_free (ObjectList *ol)
{
    if (ol->obj_hash)
        g_hash_table_destroy (ol->obj_hash);
    g_ptr_array_free (ol->obj_ids, TRUE);
    g_free (ol);
}

void
object_list_serialize (ObjectList *ol, uint8_t **buffer, uint32_t *len)
{
    uint32_t i;
    uint32_t offset = 0;
    uint8_t *buf;
    int ollen = object_list_length(ol);

    buf = g_new (uint8_t, 41 * ollen);
    for (i = 0; i < ollen; ++i) {
        memcpy (&buf[offset], g_ptr_array_index(ol->obj_ids, i), 41);
        offset += 41;
    }

    *buffer = buf;
    *len = 41 * ollen;
}

gboolean
object_list_insert (ObjectList *ol, const char *object_id)
{
    if (g_hash_table_lookup (ol->obj_hash, object_id))
        return FALSE;
    char *id = g_strdup(object_id);
    g_hash_table_replace (ol->obj_hash, id, id);
    g_ptr_array_add (ol->obj_ids, id);
    return TRUE;
}
