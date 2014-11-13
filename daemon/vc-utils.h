#ifndef VC_UTILS_H
#define VC_UTILS_H

#include <glib.h>

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
commit_trees_cb (const char *repo_id, int version,
                 const char *modifier,
                 struct cache_tree *it, struct cache_entry **cache,
                 int entries, const char *base, int baselen);

int
update_index (struct index_state *istate, const char *index_path);

int
update_worktree (struct unpack_trees_options *o,
                 gboolean recover_merge,
                 const char *conflict_head,
                 const char *default_conflict_suffix,
                 int *finished_entries);

int
seaf_remove_empty_dir (const char *path);

char *
build_case_conflict_free_path (const char *worktree,
                               const char *ce_name,
                               GHashTable *conflict_hash,
                               GHashTable *no_conflict_hash,
                               gboolean *is_case_conflict,
                               gboolean is_rename);

char *
build_checkout_path (const char *worktree, const char *ce_name, int len);

int
delete_path (const char *worktree, const char *name,
             unsigned int mode, gint64 old_mtime);

struct index_state;

int
delete_dir_with_check (const char *repo_id,
                       int repo_version,
                       const char *root_id,
                       const char *dir_path,
                       const char *worktree,
                       struct index_state *istate);

gboolean
do_check_file_locked (const char *path, const char *worktree);

gboolean
do_check_dir_locked (const char *path, const char *worktree);

gboolean
files_locked_on_windows (struct index_state *index, const char *worktree);

int
compare_file_content (const char *path, SeafStat *st, 
                      const unsigned char *ce_sha1,
                      struct SeafileCrypt *crypt,
                      int repo_version);

void
fill_seafile_blocks (const char *repo_id, int version,
                     const unsigned char *sha1, BlockList *bl);

void
collect_new_blocks_from_index (const char *repo_id, int version,
                               struct index_state *index, BlockList *bl);

#endif
