#ifndef VC_UTILS_H
#define VC_UTILS_H

#include <glib/gstdio.h>

#include "index/index.h"
#include "index/cache-tree.h"
#include "unpack-trees.h"
#include "fs-mgr.h"

#define PATH_SEPERATOR "/"

struct SeafileCrypt;

#ifdef WIN32

static inline int readlink(const char *path, char *buf, size_t bufsiz)
{ errno = ENOSYS; return -1; }

#endif

int
commit_trees_cb (struct cache_tree *it, struct cache_entry **cache,
                 int entries, const char *base, int baselen);

int
update_index (struct index_state *istate, const char *index_path);

int
update_worktree (struct unpack_trees_options *o,
                 gboolean recover_merge,
                 const char *conflict_head,
                 const char *default_conflict_suffix,
                 int *finished_entries);

char *
gen_conflict_path (const char *origin_path, const char *suffix);

gboolean
files_locked_on_windows (struct index_state *index, const char *worktree);

char *
get_last_changer_of_file (const char *head, const char *path);

int
compare_file_content (const char *path, struct stat *st, 
                      const unsigned char *ce_sha1,
                      struct SeafileCrypt *crypt);

void
fill_seafile_blocks (const unsigned char *sha1, BlockList *bl);

void
collect_new_blocks_from_index (struct index_state *index, BlockList *bl);

#endif
