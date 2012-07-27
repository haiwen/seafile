/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_INFO_MGR_H
#define SEAF_INFO_MGR_H

#include <glib.h>

struct _SeafileSession;
struct _SeafRepo;
struct _CcnetGroup;

typedef struct _SeafInfoManager SeafInfoManager;
typedef struct _SeafInfoManagerPriv SeafInfoManagerPriv;

struct _SeafInfoManager {
    struct _SeafileSession *seaf;

    SeafInfoManagerPriv *priv;
};

SeafInfoManager *seaf_info_manager_new (struct _SeafileSession *seaf);
int seaf_info_manager_init (SeafInfoManager *mgr);
int seaf_info_manager_start (SeafInfoManager *mgr);

/* 
   Return:
       -1  calculating
       >0  the size
 */
gint64
seaf_info_manager_get_fs_size (SeafInfoManager *mgr, const char *root_id);

/* 
   Return:
       -1 calculating
       -2 error
       >=0 the number
 */
int
seaf_info_manager_get_commit_tree_block_number (SeafInfoManager *mgr,
                                                const char *commit_id);


gint64
seaf_info_manager_get_total_block_size (SeafInfoManager *mgr);

void
seaf_info_manager_schedule_total_block_size (SeafInfoManager *mgr);

gboolean
seaf_info_manager_repo_size_exists (SeafInfoManager *mgr,
                                    const char *repo_id);
typedef struct _RepoSize RepoSize;
struct _RepoSize {
    gint64 size;
    char commit_id[41];
};

RepoSize *
seaf_info_manager_get_repo_size_from_db (SeafInfoManager *mgr,
                                         const char *repo_id);

int
seaf_info_manager_save_repo_size_to_db (SeafInfoManager *mgr, 
                                        const char *repo_id,
                                        gint64 size,
                                        const char *commit_id);
#endif
