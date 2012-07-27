/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_SHARE_MGR_H
#define SEAF_SHARE_MGR_H

#include <sqlite3.h>
#include <glib.h>

struct _SeafileSession;
struct _SeafRepo;
struct _CcnetGroup;

typedef struct _SeafShareManager SeafShareManager;
typedef struct _SeafShareManagerPriv SeafShareManagerPriv;

struct _SeafShareManager {
    struct _SeafileSession *seaf;

    int sync_interval;
    int sync_relay_interval;

    SeafShareManagerPriv *priv;
};

SeafShareManager *seaf_share_manager_new (struct _SeafileSession *seaf);

int seaf_share_manager_init (SeafShareManager *mgr);
int seaf_share_manager_start (SeafShareManager *mgr);

const char* seaf_share_manager_share (SeafShareManager *share_mgr,
                                      const char *repo_id,
                                      const char *group_id);

int seaf_share_manager_unshare (SeafShareManager *share_mgr,
                                const char *item_id);


GList *
seaf_share_manager_list_share_info_by_repo (SeafShareManager *mgr,
                                            const char *repo_id);

GList *
seaf_share_manager_list_share_info_by_group (SeafShareManager *mgr,
                                             const char *group_id);

GList*
seaf_share_manager_list_share_info (SeafShareManager *mgr,
                                    int offset,
                                    int limit);

char *seaf_share_manager_dump_share_info (SeafShareManager *share_mgr);

#endif
