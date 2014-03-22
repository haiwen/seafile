#ifndef CACHE_TREE_H
#define CACHE_TREE_H

#include <glib.h>

struct cache_tree;
struct cache_tree_sub {
    struct cache_tree *cache_tree;
    int namelen;
    int used;
    char name[0];
};

struct cache_tree {
    int entry_count; /* negative means "invalid" */
    unsigned char sha1[20];
    int subtree_nr;
    int subtree_alloc;
    guint64 mtime;
    struct cache_tree_sub **down;
};

typedef int (*CommitCB) (const char *, int,
                         const char *,
                         struct cache_tree *,
                         struct cache_entry **, int, const char *, int);
struct cache_tree_sub *cache_tree_find_subtree(struct cache_tree *,
                                               const char *, int, int);

struct cache_tree *cache_tree(void);
void cache_tree_free(struct cache_tree **);
void cache_tree_invalidate_path(struct cache_tree *, const char *);
struct cache_tree_sub *cache_tree_sub(struct cache_tree *, const char *);

/* void cache_tree_write(struct strbuf *, struct cache_tree *root); */
/* struct cache_tree *cache_tree_read(const char *buffer, unsigned long size); */

int cache_tree_fully_valid(struct cache_tree *);
int cache_tree_update(const char *repo_id, int version,
                      const char *worktree,
                      struct cache_tree *, struct cache_entry **, int, int, int, CommitCB);

/* bitmasks to write_cache_as_tree flags */
#define WRITE_TREE_MISSING_OK 1
#define WRITE_TREE_IGNORE_CACHE_TREE 2

/* error return codes */
#define WRITE_TREE_UNREADABLE_INDEX (-1)
#define WRITE_TREE_UNMERGED_INDEX (-2)
#define WRITE_TREE_PREFIX_ERROR (-3)

int write_cache_as_tree(unsigned char *sha1, int flags, const char *prefix);
/* void prime_cache_tree(struct cache_tree **, struct tree *); */

/* extern int cache_tree_matches_traversal(struct cache_tree *, struct name_entry *ent, struct traverse_info *info); */

#endif
