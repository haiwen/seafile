#ifndef VC_COMMON_H
#define VC_COMMON_H

#include "commit-mgr.h"

SeafCommit *
get_merge_base (SeafCommit *head, SeafCommit *remote);

/*
 * Returns true if src_head is ahead of dst_head.
 */
gboolean
is_fast_forward (const char *repo_id, int version,
                 const char *src_head, const char *dst_head);

typedef enum {
    VC_UP_TO_DATE,
    VC_FAST_FORWARD,
    VC_INDEPENDENT,
} VCCompareResult;

/*
 * Compares commits c1 and c2 as if we were going to merge c1 into c2.
 * 
 * Returns:
 * VC_UP_TO_DATE: if c2 is ahead of c1, or c1 == c2;
 * VC_FAST_FORWARD: if c1 is ahead of c2;
 * VC_INDEPENDENT: if c1 and c2 has no inheritent relationship.
 * Returns VC_INDEPENDENT if c1 or c2 doesn't exist.
 */
VCCompareResult
vc_compare_commits (const char *repo_id, int version,
                    const char *c1, const char *c2);

char *
gen_conflict_path (const char *original_path,
                   const char *modifier,
                   gint64 mtime);

int
get_file_modifier_mtime (const char *repo_id, const char *store_id, int version,
                         const char *head, const char *path,
                         char **modifier, gint64 *mtime);

/* Wrapper around the above two functions */
char *
gen_conflict_path_wrapper (const char *repo_id, int version,
                           const char *head, const char *in_repo_path,
                           const char *original_path);

#endif
