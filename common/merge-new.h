#ifndef MERGE_NEW_H
#define MERGE_NEW_H

#include "common.h"

#include "fs-mgr.h"

struct MergeOptions;

typedef int (*MergeCallback) (const char *basedir,
                              SeafDirent *dirents[],
                              struct MergeOptions *opt);

typedef struct MergeOptions {
    int                 n_ways; /* only 2 and 3 way merges are supported. */

    MergeCallback       callback;
    void *              data;

    /* options only used in 3-way merge. */
    char                remote_repo_id[37];
    char                remote_head[41];
    gboolean            do_merge;    /* really merge the contents
                                      * and handle conflicts */
    char                merged_tree_root[41]; /* merge result */
    int                 visit_dirs;
    gboolean            conflict;
} MergeOptions;

int
seaf_merge_trees (const char *store_id, int version,
                  int n, const char *roots[], MergeOptions *opt);

#endif
