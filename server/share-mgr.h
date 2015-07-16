/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SHARE_MGR_H
#define SHARE_MGR_H

#include <glib.h>

struct _SeafileSession;

typedef struct _SeafShareManager SeafShareManager;
typedef struct _SeafShareManagerPriv SeafShareManagerPriv;
typedef struct _ShareRepoInfo ShareRepoInfo;

struct _SeafShareManager {
    struct _SeafileSession *seaf;

};

SeafShareManager*
seaf_share_manager_new (struct _SeafileSession *seaf);

int
seaf_share_manager_start (SeafShareManager *mgr);

int
seaf_share_manager_add_share (SeafShareManager *mgr, const char *repo_id,
                              const char *from_email, const char *to_email,
                              const char *permission);

int
seaf_share_manager_set_permission (SeafShareManager *mgr, const char *repo_id,
                                   const char *from_email, const char *to_email,
                                   const char *permission);

GList*
seaf_share_manager_list_share_repos (SeafShareManager *mgr, const char *email,
                                     const char *type, int start, int limit);

GList *
seaf_share_manager_list_shared_to (SeafShareManager *mgr,
                                   const char *owner,
                                   const char *repo_id);

GList *
seaf_share_manager_list_repo_shared_to (SeafShareManager *mgr,
                                        const char *owner,
                                        const char *repo_id,
                                        GError **error);

GList *
seaf_share_manager_list_repo_shared_group (SeafShareManager *mgr,
                                           const char *from_email,
                                           const char *repo_id,
                                           GError **error);

int
seaf_share_manager_remove_share (SeafShareManager *mgr, const char *repo_id,
                                 const char *from_email, const char *to_email);

/* Remove all share info of a repo. */
int
seaf_share_manager_remove_repo (SeafShareManager *mgr, const char *repo_id);

char *
seaf_share_manager_check_permission (SeafShareManager *mgr,
                                     const char *repo_id,
                                     const char *email);

GHashTable *
seaf_share_manager_get_shared_sub_dirs (SeafShareManager *mgr,
                                        const char *repo_id,
                                        const char *path);

int
seaf_share_manager_is_repo_shared (SeafShareManager *mgr,
                                   const char *repo_id);

#endif /* SHARE_MGR_H */

