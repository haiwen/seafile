/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef MERGE_RECURSIVE_H
#define MERGE_RECURSIVE_H

#include <glib.h>

#include "commit-mgr.h"
#include "fs-mgr.h"
#include "seafile-crypt.h"

struct merge_options {
    char repo_id[37];
    int version;
    const char *ancestor;
    const char *branch1;
    const char *branch2;
    const char *remote_head;
    int call_depth;
    char *worktree;
    struct index_state *index;
    GString *obuf;
    GHashTable *current_file_set;
    GHashTable *current_directory_set;
    gboolean recover_merge;
    gboolean force_merge;
    SeafileCrypt *crypt;

    /* True if we only want to know the files that would be
     * updated in this merge, but don't want to update them in the
     * worktree.
     */
    gboolean collect_blocks_only;
    BlockList *bl;
};

int merge_recursive(struct merge_options *o,
                    const char *h1_root,
                    const char *h2_root,
                    const char *ca_root,
                    int *clean,
                    char **root_id);

void init_merge_options(struct merge_options *o);
void clear_merge_options(struct merge_options *o);
char *write_tree_from_memory(struct merge_options *o);

#endif
