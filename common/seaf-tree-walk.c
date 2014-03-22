/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "fs-mgr.h"
#include "seaf-tree-walk.h"
#include "utils.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

void
fill_tree_descriptor(const char *repo_id, int version,
                     struct tree_desc *desc, const char *root_id)
{
    SeafDir *dir;

    if (!root_id) {
        desc->tree = NULL;
        return;
    }

    dir = seaf_fs_manager_get_seafdir_sorted (seaf->fs_mgr,
                                              repo_id,
                                              version,
                                              root_id);
    if (!dir) {
        g_warning ("Failed to fill tree descriptor with %s.\n", root_id);
        desc->tree = NULL;
    }

    desc->tree = dir;
}

char *make_traverse_path(char *path, const struct traverse_info *info, const struct name_entry *n)
{
	int len = n->pathlen;
	int pathlen = info->pathlen;

	path[pathlen + len] = 0;
	for (;;) {
		memcpy(path + pathlen, n->path, len);
		if (!pathlen)
			break;
		path[--pathlen] = '/';
		n = &info->name;
		len = n->pathlen;
		info = info->prev;
		pathlen -= len;
	}
	return path;
}

int
traverse_trees(int n, struct tree_desc *t, struct traverse_info *info)
{
    struct name_entry *entries = g_new0 (struct name_entry, n);
    GList **ptrs = g_new0 (GList *, n);
    int i;
    SeafDirent *dent;
    char *first_name;
    gboolean done;
    unsigned long mask = 0, dirmask = 0;
    int error = 0, ret;

    for (i = 0; i < n; ++i) {
        if (t[i].tree)
            ptrs[i] = t[i].tree->entries;
        else
            ptrs[i] = NULL;
    }

    while (1) {
        first_name = NULL;
        mask = dirmask = 0;
        memset (entries, 0, sizeof(entries[0])*n);
        done = TRUE;

        /* Find the "largest" name, assuming dirents are sorted. */
        for (i = 0; i < n; ++i) {
            if (ptrs[i] != NULL) {
                done = FALSE;
                dent = ptrs[i]->data;
                if (!first_name)
                    first_name = dent->name;
                else if (strcmp(dent->name, first_name) > 0)
                    first_name = dent->name;
            }
        }

        if (done)
            break;

        /*
         * Setup name entries for all names that equals first_name
         */
        for (i = 0; i < n; ++i) {
            if (ptrs[i] != NULL) {
                dent = ptrs[i]->data;
                if (strcmp(first_name, dent->name) == 0) {
                    mask |= 1 << i;
                    /* We treat empty dirs as a file. */
                    if (S_ISDIR(dent->mode) && 
                        memcmp (dent->id, EMPTY_SHA1, 40) != 0)
                        dirmask |= 1 << i;

                    hex_to_rawdata (dent->id, entries[i].sha1, 20);
                    entries[i].path = dent->name;
                    entries[i].pathlen = dent->name_len;
                    entries[i].mode = dent->mode;
                    entries[i].mtime = dent->mtime;
                    if (S_ISREG(dent->mode)) {
                        entries[i].modifier = dent->modifier;
                    }

                    ptrs[i] = ptrs[i]->next;
                }
            }
        }

        ret = info->fn (n, mask, dirmask, entries, info);
        if (ret < 0) {
            error = ret;
        }
    }

    g_free (entries);
    g_free (ptrs);
    return error;
}
