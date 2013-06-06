#ifndef STATUS_H
#define STATUS_H

#include <glib.h>

#include "repo-mgr.h"
#include "index/index.h"
#include "diff-simple.h"

typedef gboolean (*IgnoreFunc) (const char *basepath, const char *filename, void *data);

void 
wt_status_collect_changes_worktree(struct index_state *index,
                                   GList **results,
                                   const char *worktree);

void 
wt_status_collect_untracked(struct index_state *index,
                            GList **results,
                            const char *worktree,
                            IgnoreFunc ignore_func);

void
wt_status_collect_changes_index (struct index_state *index,
                                 GList **results,
                                 SeafRepo *repo);

#endif /* STATUS_H */
