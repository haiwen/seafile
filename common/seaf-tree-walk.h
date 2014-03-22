#ifndef SEAF_TREE_WALK_H
#define SEAF_TREE_WALK_H

#include "fs-mgr.h"

struct name_entry {
    unsigned char sha1[20];
    const char *path;
    int pathlen;
    unsigned int mode;
    char *modifier;
    guint64 mtime;
};

struct tree_desc {
    SeafDir *tree;
};

inline static void tree_desc_free (struct tree_desc *t)
{
	if (t->tree)
		seaf_dir_free (t->tree);
}

struct traverse_info;

typedef int (*traverse_callback_t)(int n, unsigned long mask, unsigned long dirmask, struct name_entry *entry, struct traverse_info *);

struct traverse_info {
	struct traverse_info *prev;
	struct name_entry name;
	int pathlen;

	unsigned long conflicts;
	traverse_callback_t fn;
	void *data;
	int show_all_errors;
};

void fill_tree_descriptor(const char *repo_id, int version,
                          struct tree_desc *desc, const char *root_id);
int traverse_trees(int n, struct tree_desc *t, struct traverse_info *info);
char *make_traverse_path(char *path, const struct traverse_info *info, const struct name_entry *n);

static inline int traverse_path_len(const struct traverse_info *info, const struct name_entry *n)
{
	return info->pathlen + n->pathlen;
}


#endif
