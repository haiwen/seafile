/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_FILELOCK_MGR_H
#define SEAF_FILELOCK_MGR_H

#include <glib.h>

struct _SeafileSession;
struct _FilelockMgrPriv;

struct _SeafFilelockManager {
    struct _SeafileSession *session;

    struct _FilelockMgrPriv *priv;
};
typedef struct _SeafFilelockManager SeafFilelockManager;

struct _SeafFilelockManager *
seaf_filelock_manager_new (struct _SeafileSession *session);

int
seaf_filelock_manager_init (SeafFilelockManager *mgr);

int
seaf_filelock_manager_start (SeafFilelockManager *mgr);

gboolean
seaf_filelock_manager_is_file_locked (SeafFilelockManager *mgr,
                                      const char *repo_id,
                                      const char *path);

#define FILE_NOT_LOCKED 0
#define FILE_LOCKED_BY_OTHERS 1
#define FILE_LOCKED_BY_ME_MANUAL 2
#define FILE_LOCKED_BY_ME_AUTO 3

int
seaf_filelock_manager_get_lock_status (SeafFilelockManager *mgr,
                                       const char *repo_id,
                                       const char *path);

gboolean
seaf_filelock_manager_is_file_locked_by_me (SeafFilelockManager *mgr,
                                            const char *repo_id,
                                            const char *path);

/* Remove locking from the file on worktree */
void
seaf_filelock_manager_lock_wt_file (SeafFilelockManager *mgr,
                                    const char *repo_id,
                                    const char *path);

/* Add locking to the file on worktree */
void
seaf_filelock_manager_unlock_wt_file (SeafFilelockManager *mgr,
                                      const char *repo_id,
                                      const char *path);

int
seaf_filelock_manager_update (SeafFilelockManager *mgr,
                              const char *repo_id,
                              GHashTable *new_locked_files);

int
seaf_filelock_manager_update_timestamp (SeafFilelockManager *mgr,
                                        const char *repo_id,
                                        gint64 timestamp);

gint64
seaf_filelock_manager_get_timestamp (SeafFilelockManager *mgr,
                                     const char *repo_id);

int
seaf_filelock_manager_remove (SeafFilelockManager *mgr,
                              const char *repo_id);

int
seaf_filelock_manager_mark_file_locked (SeafFilelockManager *mgr,
                                        const char *repo_id,
                                        const char *path,
                                        gboolean is_auto_lock);

int
seaf_filelock_manager_mark_file_unlocked (SeafFilelockManager *mgr,
                                          const char *repo_id,
                                          const char *path);

struct FileLockInfo {
    char repo_id[37];
    char *path;
    int status;
};
typedef struct FileLockInfo FileLockInfo;

void file_lock_info_free (FileLockInfo *info);

GList *
seaf_filelock_manager_get_auto_locked_files (SeafFilelockManager *mgr);

#endif
