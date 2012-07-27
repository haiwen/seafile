/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <json-glib/json-glib.h>

#include "utils.h"
#include "share-info.h"

SeafShareInfo*
seaf_share_info_new (const char *id,
                     const char *repo_id,
                     const char *share_id,
                     const char *user_id,
                     gint64 timestamp)
{
    SeafShareInfo *sinfo = g_new0 (SeafShareInfo, 1);

    sinfo->id = (id ? g_strdup (id) : gen_uuid());
    sinfo->repo_id = g_strdup(repo_id);
    sinfo->group_id = g_strdup(share_id);
    sinfo->user_id = g_strdup(user_id);
    if (timestamp == 0)
        sinfo->timestamp = get_current_time();
    else
        sinfo->timestamp = timestamp;

    return sinfo;
}

void
seaf_share_info_free (SeafShareInfo *sinfo)
{
    g_free (sinfo->id);
    g_free (sinfo->repo_id);
    g_free (sinfo->group_id);
    g_free (sinfo->user_id);
    g_free (sinfo);
}

void
seaf_share_info_list_free (GList *list)
{
    GList *ptr;

    if (list == NULL)
        return;

    for (ptr = list; ptr; ptr = ptr->next)
        seaf_share_info_free (ptr->data);
    g_list_free (list);
}

char *
seaf_share_info_to_json(SeafShareInfo *info)
{
    return json_printf ("ssssi", "id", info->id,
                        "repo_id", info->repo_id,
                        "group_id", info->group_id,
                        "user_id", info->user_id,
                        "timestamp", info->timestamp);
}

SeafShareInfo *
seaf_share_info_from_json(const char *str)
{
    SeafShareInfo *info;
    JsonParser *parser;
    GError *error = NULL;
    JsonNode *root;
    JsonObject *jobj;
    const char *id, *repo_id, *group_id, *user_id;
    gint64 timestamp;

    /* TODO: can we reuse the parser? */
    parser = json_parser_new ();
    
    if (!json_parser_load_from_data (parser, str, strlen(str), &error)) {
        g_warning ("failed to parse share message: %s, %s\n",
                   error->message, str);
        g_error_free (error);
        g_object_unref (parser);
        return NULL;
    }

    root = json_parser_get_root (parser);
    jobj = json_node_get_object (root);

    id = json_object_get_string_member (jobj, "id");
    repo_id = json_object_get_string_member (jobj, "repo_id");
    group_id = json_object_get_string_member (jobj, "group_id");
    user_id = json_object_get_string_member (jobj, "user_id");
    timestamp = json_object_get_int_member (jobj, "timestamp");
    if (!id || !repo_id || !group_id || !user_id || timestamp == 0) {
        ccnet_warning ("invalid share info string\n");
        return NULL;
    }

    info = seaf_share_info_new (id, repo_id, group_id, user_id, timestamp);

    g_object_unref (parser);

    return info;
}
