/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_SHARE_INFO_H
#define SEAF_SHARE_INFO_H

typedef struct _SeafShareInfo SeafShareInfo;

#define SHAREINFO_KV_CATEGORY "RepoShare"

/* share info */
struct _SeafShareInfo {
    char       *id;
    char       *group_id;
    char       *repo_id;
    char       *user_id;
    gint64      timestamp;      /* use gint64 instead of guint64 for json-glib can't
                                 * handle guint64 */
};

SeafShareInfo*
seaf_share_info_new (const char *id,
                     const char *repo_id, 
                     const char *share_id,
                     const char *user_id,
                     gint64 timestamp);


void seaf_share_info_free (SeafShareInfo* sinfo);
void seaf_share_info_list_free (GList *list);
char *seaf_share_info_to_json (SeafShareInfo *info);
SeafShareInfo *seaf_share_info_from_json (const char *str);


#endif
