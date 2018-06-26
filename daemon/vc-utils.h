#ifndef VC_UTILS_H
#define VC_UTILS_H

#include <glib.h>

#include "index/index.h"
#include "index/cache-tree.h"
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
seaf_remove_empty_dir (const char *path);

char *
build_checkout_path (const char *worktree, const char *ce_name, int len);

int
delete_path (const char *worktree, const char *name,
             unsigned int mode, gint64 old_mtime);

gboolean
do_check_file_locked (const char *path, const char *worktree, gboolean locked_on_server);

gboolean
do_check_dir_locked (const char *path, const char *worktree);

gboolean
files_locked_on_windows (struct index_state *index, const char *worktree);

int
compare_file_content (const char *path, SeafStat *st, 
                      const unsigned char *ce_sha1,
                      struct SeafileCrypt *crypt,
                      int repo_version);

#endif
