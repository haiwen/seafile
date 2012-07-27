#ifndef DIFF_H
#define DIFF_H

#include "repo-mgr.h"
#include "branch-mgr.h"
#include "commit-mgr.h"

struct diff_options {
    GList *df_list;
    struct index_state *index;
    char *worktree;
};

struct diff_filespec {
    unsigned char sha1[20];
    char *path;
    void *data;
    void *cnt_data;
    const char *funcname_pattern_ident;
    unsigned long size;
    int count;               /* Reference count */
    int xfrm_flags;		     /* for use by the xfrm */
    int rename_used;         /* Count of rename users */
    unsigned short mode;	 /* file mode */
    unsigned sha1_valid : 1; /* if true, use sha1 and trust mode;
                              * if false, use the name and read from
                              * the filesystem.
                              */
#define DIFF_FILE_VALID(spec) (((spec)->mode) != 0)
    unsigned should_free : 1; /* data should be free()'ed */
    unsigned should_munmap : 1; /* data should be munmap()'ed */
    unsigned dirty_submodule : 2;  /* For submodules: its work tree is dirty */
#define DIRTY_SUBMODULE_UNTRACKED 1
#define DIRTY_SUBMODULE_MODIFIED  2
    unsigned has_more_entries : 1; /* only appear in combined diff */
    struct userdiff_driver *driver;
    /* data should be considered "binary"; -1 means "don't know yet" */
    int is_binary;
};

struct diff_filepair {
    struct diff_filespec *one;
    struct diff_filespec *two;
    unsigned short int score;
    char status; /* M C R A D U etc. (see Documentation/diff-format.txt or DIFF_STATUS_* in diff.h) */
    unsigned broken_pair : 1;
    unsigned renamed_pair : 1;
    unsigned is_unmerged : 1;

    /* for seafile */
    int unmerged; /* for unmerged status */
    char stage; /* indicate status */
};

#define DIFF_PAIR_BROKEN(p) \
    ( (!DIFF_FILE_VALID((p)->one) != !DIFF_FILE_VALID((p)->two)) && \
      ((p)->broken_pair != 0) )
#define DIFF_PAIR_MODE_CHANGED(p) ((p)->one->mode != (p)->two->mode)

#define DIFF_PAIR_UNMERGED(p) ((p)->is_unmerged)
#define DIFF_FILE_VALID(spec) (((spec)->mode) != 0)
#define DIFF_PAIR_TYPE_CHANGED(p) \
    ((S_IFMT & (p)->one->mode) != (S_IFMT & (p)->two->mode))
#define DIFF_PAIR_RENAME(p) ((p)->renamed_pair)

int diff_cache(struct index_state *istate, struct diff_options *diffopt, SeafDir *root);
int diff_tree(SeafRepo *repo, SeafCommit *c1, SeafCommit *c2, char **diff_result, char **error);
struct diff_filepair *diff_unmerge(struct diff_options *options, const char *path);
struct diff_filepair *diff_addremove(struct diff_options *options,
        int addremove, unsigned mode,
        const unsigned char *sha1,
        const char *concatpath, unsigned dirty_submodule);
struct diff_filepair *diff_change(struct diff_options *options,
        unsigned old_mode, unsigned new_mode,
        const unsigned char *old_sha1,
        const unsigned char *new_sha1,
        const char *concatpath,
        unsigned old_dirty_submodule, unsigned new_dirty_submodule);
void diff_rename(struct diff_options *options);
void diff_resolve_rename_copy(struct diff_options *options);
int diff_unmerged_stage(int mask);

/* diff-raw status letters */
#define DIFF_STATUS_ADDED		    'A'
#define DIFF_STATUS_COPIED		    'C'
#define DIFF_STATUS_DELETED		    'D'
#define DIFF_STATUS_MODIFIED	    'M'
#define DIFF_STATUS_RENAMED		    'R'
#define DIFF_STATUS_TYPE_CHANGED	'T'
#define DIFF_STATUS_UNKNOWN		    'X'
#define DIFF_STATUS_UNMERGED		'U'

#define DIFF_DETECT_RENAME      1
#define DIFF_DETECT_COPY        2

#define MAX_SCORE 60000.0
#define DEFAULT_RENAME_SCORE 30000 /* rename/copy similarity minimum (50%) */

#endif /* DIFF_H */
