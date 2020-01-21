#ifndef SYNC_STATUS_TREE_H
#define SYNC_STATUS_TREE_H

struct SyncStatusTree;

struct SyncStatusTree *
sync_status_tree_new (const char *worktree);

void
sync_status_tree_free (struct SyncStatusTree *tree);

/*
 * Add a @path into the @tree. If any directory along the path is missing,
 * it will be created. If the path already exists, it won't be overwritten.
 */
void
sync_status_tree_add (struct SyncStatusTree *tree,
                      const char *path,
                      int mode,
                      gboolean refresh);

/*
 * Delete a path from the tree. If directory becomes empty after the deletion,
 * it will be deleted too. All empty direcotries along the path will be deleted.
 */
void
sync_status_tree_del (struct SyncStatusTree *tree,
                      const char *path);

int
sync_status_tree_exists (struct SyncStatusTree *tree,
                         const char *path);

#endif
