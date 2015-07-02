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
                                        const char *path);

#endif
