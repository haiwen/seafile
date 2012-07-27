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

struct dir_entry {
    unsigned int len;
    char name[0]; /* more */
};

struct dir_struct {
    int nr, alloc;
    int ignored_nr, ignored_alloc;
   enum {
        DIR_SHOW_IGNORED = 1<<0,
        DIR_SHOW_OTHER_DIRECTORIES = 1<<1,
        DIR_HIDE_EMPTY_DIRECTORIES = 1<<2,
        DIR_NO_GITLINKS = 1<<3,
        DIR_COLLECT_IGNORED = 1<<4
    } flags;
    struct dir_entry **entries;
    struct dir_entry **ignored;
};

int 
read_directory(struct dir_struct *dir, const char *worktree, struct index_state *index);

void
fill_seafile_blocks (const unsigned char *sha1, BlockList *bl);

void
collect_new_blocks_from_index (struct index_state *index, BlockList *bl);

#endif
