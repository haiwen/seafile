#ifndef DIFF_SIMPLE_H
#define DIFF_SIMPLE_H

#include <glib.h>
#ifndef SEAFILE_SERVER
#include "index/index.h"
#endif
#include "seafile-session.h"

#define DIFF_TYPE_WORKTREE              'W' /* diff from index to worktree */
#define DIFF_TYPE_INDEX                 'I' /* diff from commit to index */
#define DIFF_TYPE_COMMITS               'C' /* diff between two commits*/

#define DIFF_STATUS_ADDED               'A'
#define DIFF_STATUS_DELETED             'D'
#define DIFF_STATUS_MODIFIED	        'M'
#define DIFF_STATUS_RENAMED             'R'
#define DIFF_STATUS_UNMERGED		'U'
#define DIFF_STATUS_DIR_ADDED           'B'
#define DIFF_STATUS_DIR_DELETED         'C'
#define DIFF_STATUS_DIR_RENAMED         'E'

enum {
    STATUS_UNMERGED_NONE,
    /* I and others modified the same file differently. */
    STATUS_UNMERGED_BOTH_CHANGED,
    /* I and others created the same file with different contents. */
    STATUS_UNMERGED_BOTH_ADDED,
    /* I removed a file while others modified it. */
    STATUS_UNMERGED_I_REMOVED,
    /* Others removed a file while I modified it. */
    STATUS_UNMERGED_OTHERS_REMOVED,
    /* I replace a directory with a file while others modified files under the directory. */
    STATUS_UNMERGED_DFC_I_ADDED_FILE,
    /* Others replace a directory with a file while I modified files under the directory. */
    STATUS_UNMERGED_DFC_OTHERS_ADDED_FILE,
};

typedef struct DiffEntry {
    char type;
    char status;
    int unmerge_state;
    unsigned char sha1[20];     /* used for resolve rename */
    char *name;
    char *new_name;             /* only used in rename. */

#ifdef SEAFILE_CLIENT
    /* Fields only used for ADDED, DIR_ADDED, MODIFIED types,
     * used in check out files/dirs.*/
    gint64 mtime;
    unsigned int mode;
    char *modifier;
    gint64 size;
#endif
} DiffEntry;

DiffEntry *
diff_entry_new (char type, char status, unsigned char *sha1, const char *name);

void
diff_entry_free (DiffEntry *de);

#ifndef SEAFILE_SERVER
int
diff_index (const char *repo_id, int version,
            struct index_state *istate, SeafDir *root, GList **results);
#endif

/*
 * @fold_dir_diff: if TRUE, only the top level directory will be included
 *                 in the diff result if a directory with files is added or removed.
 *                 Otherwise all the files in the direcotory will be recursively
 *                 included in the diff result.
 */
int
diff_commits (SeafCommit *commit1, SeafCommit *commit2, GList **results,
              gboolean fold_dir_diff);

int
diff_commit_roots (const char *store_id, int version,
                   const char *root1, const char *root2, GList **results,
                   gboolean fold_dir_diff);

int
diff_merge (SeafCommit *merge, GList **results, gboolean fold_dir_diff);

int
diff_merge_roots (const char *store_id, int version,
                  const char *merged_root, const char *p1_root, const char *p2_root,
                  GList **results, gboolean fold_dir_diff);

void
diff_resolve_renames (GList **diff_entries);

void
diff_resolve_empty_dirs (GList **diff_entries);

int 
diff_unmerged_state(int mask);

char *
format_diff_results(GList *results);

char *
diff_results_to_description (GList *results);

typedef int (*DiffFileCB) (int n,
                           const char *basedir,
                           SeafDirent *files[],
                           void *data);

typedef int (*DiffDirCB) (int n,
                          const char *basedir,
                          SeafDirent *dirs[],
                          void *data,
                          gboolean *recurse);

typedef struct DiffOptions {
    char store_id[37];
    int version;

    DiffFileCB file_cb;
    DiffDirCB dir_cb;
    void *data;
} DiffOptions;

int
diff_trees (int n, const char *roots[], DiffOptions *opt);

#endif
