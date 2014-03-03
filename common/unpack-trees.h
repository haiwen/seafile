#ifndef UNPACK_TREES_H
#define UNPACK_TREES_H

#include "common.h"
#include "utils.h"
#include "seaf-tree-walk.h"
#include "index/index.h"
#include "seafile-crypt.h"

#define MAX_UNPACK_TREES 8

struct unpack_trees_options;

typedef int (*merge_fn_t)(struct cache_entry **src,
                          struct unpack_trees_options *options);

enum unpack_trees_error_types {
    ERROR_WOULD_OVERWRITE = 0,
    ERROR_NOT_UPTODATE_FILE,
    ERROR_NOT_UPTODATE_DIR,
    ERROR_WOULD_LOSE_UNTRACKED_OVERWRITTEN,
    ERROR_WOULD_LOSE_UNTRACKED_REMOVED,
    NB_UNPACK_TREES_ERROR_TYPES
};

struct unpack_trees_options {
    unsigned int reset,
        merge,
        update,
        index_only,
        nontrivial_merge,
        trivial_merges_only,
        verbose_update,
        aggressive,
        skip_unmerged,
        initial_checkout,
        diff_index_cached,
        debug_unpack,
        skip_sparse_checkout,
        gently,
        show_all_errors;
    char repo_id[37];
    int version;
    const char *prefix;
    const char *base;
    int cache_bottom;
    merge_fn_t fn;
    const char *msgs[NB_UNPACK_TREES_ERROR_TYPES];
    /*
     * Store error messages in an array, each case
     * corresponding to a error message type
     */
    GList *unpack_rejects[NB_UNPACK_TREES_ERROR_TYPES];

    int head_idx;
    int merge_size;

    struct cache_entry *df_conflict_entry;
    void *unpack_data;

    struct index_state *dst_index;
    struct index_state *src_index;
    struct index_state result;

    SeafileCrypt *crypt;
};

extern int unpack_trees(unsigned n, struct tree_desc *t,
		struct unpack_trees_options *options);

enum {
    OPR_CHECKOUT,
    OPR_MERGE,
    N_OPR_TYPES,
};

gboolean
get_unpack_trees_error_msgs(struct unpack_trees_options *o, GString *msgbuf, int opr_type);

int threeway_merge(struct cache_entry **stages, struct unpack_trees_options *o);
int twoway_merge(struct cache_entry **src, struct unpack_trees_options *o);
int oneway_merge(struct cache_entry **src, struct unpack_trees_options *o);

#endif
