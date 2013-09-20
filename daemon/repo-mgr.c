/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <glib/gstdio.h>

#ifdef WIN32
#include <windows.h>
#endif

#include <ccnet.h>
#include "utils.h"
#include "avl/avl.h"
#include "log.h"

#include "status.h"
#include "vc-utils.h"
#include "merge.h"

#include "seafile-session.h"
#include "seafile-config.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "repo-mgr.h"
#include "fs-mgr.h"
#include "seafile-error.h"
#include "gc.h"
#include "seafile-crypt.h"
#include "index/index.h"
#include "index/cache-tree.h"
#include "unpack-trees.h"
#include "diff-simple.h"

#include "db.h"

#define INDEX_DIR "index"
#define IGNORE_FILE "seafile-ignore.txt"

#ifdef HAVE_KEYSTORAGE_GK
#include "repokey/seafile-gnome-keyring.h"
#endif // HAVE_KEYSTORAGE_GK

struct _SeafRepoManagerPriv {
    avl_tree_t *repo_tree;
    sqlite3    *db;
    pthread_mutex_t db_lock;
    GHashTable *checkout_tasks_hash;
    pthread_rwlock_t lock;
};

static const char *ignore_table[] = {
    "*~",
    "*#",
    /* -------------
     * windows tmp files
     * -------------
     */
    "*.tmp",
    "*.TMP",
    /* ms office tmp files */
    "~$*",
    /* windows image cache */
    "Thumbs.db",
    /* For Mac */
    ".DS_Store",
    NULL,
};

static GPatternSpec** ignore_patterns;

static SeafRepo *
load_repo (SeafRepoManager *manager, const char *repo_id);

static void load_repos (SeafRepoManager *manager, const char *seaf_dir);
static void seaf_repo_manager_del_repo_property (SeafRepoManager *manager,
                                                 const char *repo_id);

static int save_branch_repo_map (SeafRepoManager *manager, SeafBranch *branch);

gboolean
is_repo_id_valid (const char *id)
{
    if (!id)
        return FALSE;

    return is_uuid_valid (id);
}

SeafRepo*
seaf_repo_new (const char *id, const char *name, const char *desc)
{
    SeafRepo* repo;

    /* valid check */
  
    
    repo = g_new0 (SeafRepo, 1);
    memcpy (repo->id, id, 36);
    repo->id[36] = '\0';

    repo->name = g_strdup(name);
    repo->desc = g_strdup(desc);

    repo->passwd = NULL;
    repo->worktree_invalid = TRUE;
    repo->auto_sync = 1;
    repo->net_browsable = 0;
    pthread_mutex_init (&repo->lock, NULL);

    return repo;
}

int
seaf_repo_check_worktree (SeafRepo *repo)
{
    SeafStat st;

    if (repo->worktree == NULL) {
        seaf_warning ("Worktree for repo '%s'(%.8s) is not set.\n",
                      repo->name, repo->id);
        return -1;
    }

    /* check repo worktree */
    if (g_access(repo->worktree, F_OK) < 0) {
        seaf_warning ("Failed to access worktree %s for repo '%s'(%.8s)\n",
                      repo->worktree, repo->name, repo->id);
        return -1;
    }
    if (seaf_stat(repo->worktree, &st) < 0) {
        seaf_warning ("Failed to stat worktree %s for repo '%s'(%.8s)\n",
                      repo->worktree, repo->name, repo->id);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        seaf_warning ("Worktree %s for repo '%s'(%.8s) is not a directory.\n",
                      repo->worktree, repo->name, repo->id);
        return -1;
    }

    return 0;
}

static void
send_wktree_notification (SeafRepo *repo, int addordel)
{
    if (seaf_repo_check_worktree(repo) < 0)
        return;
    if (addordel) {
        seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                              "repo.setwktree",
                                              repo->worktree);
    } else {
        seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                              "repo.unsetwktree",
                                              repo->worktree);
    }
}


static gboolean
check_worktree_common (SeafRepo *repo)
{
    if (!repo->head) {
        seaf_warning ("Head for repo '%s'(%.8s) is not set.\n",
                      repo->name, repo->id);
        return FALSE;
    }

    if (seaf_repo_check_worktree (repo) < 0) {
        /* The worktree is invalid */
        seaf_repo_manager_invalidate_repo_worktree (repo->manager, repo);
        return FALSE;
    }
    seaf_repo_manager_validate_repo_worktree (repo->manager, repo);

    return TRUE;
}

void
seaf_repo_free (SeafRepo *repo)
{
    if (repo->head) seaf_branch_unref (repo->head);

    g_free (repo->name);
    g_free (repo->desc);
    g_free (repo->category);
    g_free (repo->worktree);
    g_free (repo->relay_id);
    g_free (repo->passwd);
    g_free (repo->email);
    g_free (repo->token);
    g_free (repo);
}

static void
set_head_common (SeafRepo *repo, SeafBranch *branch)
{
    if (repo->head)
        seaf_branch_unref (repo->head);
    repo->head = branch;
    seaf_branch_ref(branch);
}

int
seaf_repo_set_head (SeafRepo *repo, SeafBranch *branch)
{
    if (save_branch_repo_map (repo->manager, branch) < 0)
        return -1;
    set_head_common (repo, branch);
    return 0;
}

void
seaf_repo_from_commit (SeafRepo *repo, SeafCommit *commit)
{
    repo->name = g_strdup (commit->repo_name);
    repo->desc = g_strdup (commit->repo_desc);
    repo->encrypted = commit->encrypted;
    if (repo->encrypted) {
        repo->enc_version = commit->enc_version;
        if (repo->enc_version >= 1)
            memcpy (repo->magic, commit->magic, 33);
    }
    repo->no_local_history = commit->no_local_history;
}

void
seaf_repo_to_commit (SeafRepo *repo, SeafCommit *commit)
{
    commit->repo_name = g_strdup (repo->name);
    commit->repo_desc = g_strdup (repo->desc);
    commit->encrypted = repo->encrypted;
    if (commit->encrypted) {
        commit->enc_version = repo->enc_version;
        if (commit->enc_version >= 1)
            commit->magic = g_strdup (repo->magic);
    }
    commit->no_local_history = repo->no_local_history;
}

static gboolean
collect_commit (SeafCommit *commit, void *vlist, gboolean *stop)
{
    GList **commits = vlist;

    /* The traverse function will unref the commit, so we need to ref it.
     */
    seaf_commit_ref (commit);
    *commits = g_list_prepend (*commits, commit);
    return TRUE;
}

GList *
seaf_repo_get_commits (SeafRepo *repo)
{
    GList *branches;
    GList *ptr;
    SeafBranch *branch;
    GList *commits = NULL;

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        g_warning ("Failed to get branch list of repo %s.\n", repo->id);
        return NULL;
    }

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 branch->commit_id,
                                                                 collect_commit,
                                                                 &commits, FALSE);
        if (!res) {
            for (ptr = commits; ptr != NULL; ptr = ptr->next)
                seaf_commit_unref ((SeafCommit *)(ptr->data));
            g_list_free (commits);
            goto out;
        }
    }

    commits = g_list_reverse (commits);

out:
    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        seaf_branch_unref ((SeafBranch *)ptr->data);
    }
    return commits;
}

int
seaf_repo_verify_passwd (const char *repo_id,
                         const char *passwd,
                         const char *magic)
{
    GString *buf = g_string_new (NULL);
    unsigned char key[16], iv[16];
    char hex[33];

    /* Recompute the magic and compare it with the one comes with the repo. */
    g_string_append_printf (buf, "%s%s", repo_id, passwd);

    seafile_generate_enc_key (buf->str, buf->len, CURRENT_ENC_VERSION, key, iv);

    g_string_free (buf, TRUE);
    rawdata_to_hex (key, hex, 16);

    if (g_strcmp0 (hex, magic) == 0)
        return 0;
    else
        return -1;
}

static inline gboolean
has_trailing_space_or_period (const char *path)
{
    int len = strlen(path);
    if (path[len - 1] == ' ' || path[len - 1] == '.') {
        return TRUE;
    }

    return FALSE;
}

static gboolean
should_ignore(const char *basepath, const char *filename, void *data)
{
    GPatternSpec **spec = ignore_patterns;
    GList *ignore_list = (GList *)data;

    /* Ignore file/dir if its name is too long. */
    if (strlen(filename) >= SEAF_DIR_NAME_LEN)
        return TRUE;

    if (has_trailing_space_or_period (filename)) {
        /* Ignore files/dir whose path has trailing spaces. It would cause
         * problem on windows. */
        /* g_debug ("ignore '%s' which contains trailing space in path\n", path); */
        return TRUE;
    }

    while (*spec) {
        if (g_pattern_match_string(*spec, filename))
            return TRUE;
        spec++;
    }
    
    /*
     *  Illegal charaters in filenames under windows: (In Linux, only '/' is
     *  disallowed)
     *  
     *  - / \ : * ? " < > | \b \t  
     *  - \1 - \31
     * 
     *  Refer to http://msdn.microsoft.com/en-us/library/aa365247%28VS.85%29.aspx
     */
    static char illegals[] = {'\\', '/', ':', '*', '?', '"', '<', '>', '|', '\b', '\t'};

    int i;
    char c;
    
    for (i = 0; i < G_N_ELEMENTS(illegals); i++) {
        if (strchr (filename, illegals[i])) {
            return TRUE;
        }
    }

    for (c = 1; c <= 31; c++) {
        if (strchr (filename, c)) {
            return TRUE;
        }
    }

    char *fullpath = g_build_path ("/", basepath, filename, NULL);
    if (seaf_repo_check_ignore_file (ignore_list, fullpath)) {
        g_free (fullpath);
        return TRUE;
    }
    g_free (fullpath);

    return FALSE;
}

static int
index_cb (const char *path,
          unsigned char sha1[],
          SeafileCrypt *crypt)
{
    /* Check in blocks and get object ID. */
    if (seaf_fs_manager_index_blocks (seaf->fs_mgr, path, sha1, crypt) < 0) {
        g_warning ("Failed to index file %s.\n", path);
        return -1;
    }
    return 0;
}

static int
add_recursive (struct index_state *istate, 
               const char *worktree,
               const char *path,
               SeafileCrypt *crypt,
               gboolean ignore_empty_dir,
               GList *ignore_list)
{
    char *full_path;
    GDir *dir;
    const char *dname;
    char *subpath;
    SeafStat st;
    int n;
    int ret = 0;

    full_path = g_build_path (PATH_SEPERATOR, worktree, path, NULL);
    if (seaf_stat (full_path, &st) < 0) {
#ifndef WIN32
        /* Ignore broken symlinks on Linux and Mac OS X */
        if (lstat (full_path, &st) == 0 && S_ISLNK(st.st_mode)) {
            g_free (full_path);
            return 0;
        }
#endif
        g_warning ("Failed to stat %s.\n", full_path);
        g_free (full_path);
        return -1;
    }

    if (S_ISREG(st.st_mode)) {
        ret = add_to_index (istate, path, full_path,
                            &st, 0, crypt, index_cb);
        g_free (full_path);
        return ret;
    }

    if (S_ISDIR(st.st_mode)) {
        dir = g_dir_open (full_path, 0, NULL);
        if (!dir) {
            g_warning ("Failed to open dir %s: %s.\n", full_path, strerror(errno));
            goto bad;
        }

        n = 0;
        while ((dname = g_dir_read_name(dir)) != NULL) {
            if (should_ignore(full_path, dname, ignore_list))
                continue;

            ++n;

#ifdef __APPLE__
            char *norm_dname = g_utf8_normalize (dname, -1, G_NORMALIZE_NFC);
            subpath = g_build_path (PATH_SEPERATOR, path, norm_dname, NULL);
            g_free (norm_dname);
#else
            subpath = g_build_path (PATH_SEPERATOR, path, dname, NULL);
#endif
            ret = add_recursive (istate, worktree, subpath,
                                 crypt, ignore_empty_dir, ignore_list);
            g_free (subpath);
            if (ret < 0)
                break;
        }
        g_dir_close (dir);
        if (ret < 0)
            goto bad;

        if (n == 0 && !ignore_empty_dir) {
            g_debug ("Adding empty dir %s\n", path);
            add_empty_dir_to_index (istate, path);
        }
    }

    g_free (full_path);
    return 0;

bad:
    g_free (full_path);
    return -1;
}

static gboolean
is_empty_dir (const char *path, GList *ignore_list)
{
    GDir *dir;
    const char *dname;

    dir = g_dir_open (path, 0, NULL);
    if (!dir) {
        g_warning ("Failed to open dir %s: %s.\n", path, strerror(errno));
        return FALSE;
    }

    int n = 0;
    while ((dname = g_dir_read_name(dir)) != NULL) {
        if (should_ignore(path, dname, ignore_list))
            continue;
        ++n;
    }
    g_dir_close (dir);

    return (n == 0);
}

static void
remove_deleted (struct index_state *istate, const char *worktree,
                const char *prefix, GList *ignore_list)
{
    struct cache_entry **ce_array = istate->cache;
    struct cache_entry *ce;
    char path[SEAF_PATH_MAX];
    unsigned int i;
    int len = strlen(prefix);
    SeafStat st;
    int ret;

    for (i = 0; i < istate->cache_nr; ++i) {
        ce = ce_array[i];
        /* Only check entries under 'prefix'. */
        if (strncmp (ce->name, prefix, len) != 0)
            continue;
        snprintf (path, SEAF_PATH_MAX, "%s/%s", worktree, ce->name);
        ret = seaf_stat (path, &st);

        if (S_ISDIR (ce->ce_mode)) {
            if (ret < 0 || !S_ISDIR (st.st_mode) || !is_empty_dir (path, ignore_list))
                ce->ce_flags |= CE_REMOVE;
        } else {
            /* If ce->mtime is 0 and stage is 0, it was not successfully checked out.
             * In this case we don't want to mistakenly remove the file
             * from the repo.
             */
            if ((ret < 0 || !S_ISREG (st.st_mode)) &&
                (ce_array[i]->ce_mtime.sec != 0 || ce_stage(ce_array[i]) != 0))
                ce_array[i]->ce_flags |= CE_REMOVE;
        }
    }

    remove_marked_cache_entries (istate);
}

static int
index_add (SeafRepo *repo, struct index_state *istate, const char *path)
{
    SeafileCrypt *crypt = NULL;
    GList *ignore_list = NULL;

    /* Skip any leading '/'. */
    while (path[0] == '/')
        path = &path[1];

    if (repo->encrypted) {
        crypt = seafile_crypt_new (repo->enc_version, repo->enc_key, repo->enc_iv);
    }

    ignore_list = seaf_repo_load_ignore_files (repo->worktree);

    if (add_recursive (istate, repo->worktree, path, crypt, TRUE, ignore_list) < 0)
        goto error;

    remove_deleted (istate, repo->worktree, path, ignore_list);

    seaf_repo_free_ignore_files (ignore_list);
    g_free (crypt);
    return 0;

error:
    seaf_repo_free_ignore_files (ignore_list);
    g_free (crypt);
    return -1;
}

/*
 * Add the files in @worktree to index and return the corresponding
 * @root_id. The repo doesn't have to exist.
 */
int
seaf_repo_index_worktree_files (const char *repo_id,
                                const char *worktree,
                                const char *passwd,
                                char *root_id)
{
    char index_path[SEAF_PATH_MAX];
    struct index_state istate;
    unsigned char key[16], iv[16];
    SeafileCrypt *crypt = NULL;
    struct cache_tree *it = NULL;
    GList *ignore_list = NULL;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", seaf->repo_mgr->index_dir, repo_id);

    /* Remove existing index. An existing index signifies an interrupted
     * clone-merge. Removing it assures that new blocks from the worktree
     * get added into the repo again (they're deleted by GC).
     */
    g_unlink (index_path);

    if (read_index_from (&istate, index_path) < 0) {
        g_warning ("Failed to load index.\n");
        return -1;
    }

    if (passwd != NULL) {
        seafile_generate_enc_key (passwd, strlen(passwd), 1, key, iv);
        crypt = seafile_crypt_new (1, key, iv);
    }

    ignore_list = seaf_repo_load_ignore_files(worktree);

    /* Add empty dir to index. Otherwise if the repo on relay contains an empty
     * dir, we'll fail to detect fast-forward relationship later.
     */
    if (add_recursive (&istate, worktree, "", crypt, FALSE, ignore_list) < 0)
        goto error;

    remove_deleted (&istate, worktree, "", ignore_list);

    it = cache_tree ();
    if (cache_tree_update (it, istate.cache, istate.cache_nr,
                           0, 0, commit_trees_cb) < 0) {
        g_warning ("Failed to build cache tree");
        goto error;
    }

    rawdata_to_hex (it->sha1, root_id, 20);

    if (update_index (&istate, index_path) < 0)
        goto error;

    discard_index (&istate);
    g_free (crypt);
    if (it)
        cache_tree_free (&it);
    seaf_repo_free_ignore_files(ignore_list);
    return 0;

error:
    discard_index (&istate);
    g_free (crypt);
    if (it)
        cache_tree_free (&it);
    seaf_repo_free_ignore_files(ignore_list);
    return -1;
}

gboolean
seaf_repo_is_worktree_changed (SeafRepo *repo)
{
    SeafRepoManager *mgr = repo->manager;
    GList *res = NULL, *p;
    struct index_state istate;
    char index_path[SEAF_PATH_MAX];

    DiffEntry *de;
    int pos;
    struct cache_entry *ce;
    SeafStat sb;
    char *full_path;

    if (!check_worktree_common (repo))
        return FALSE;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path) < 0) {
        repo->index_corrupted = TRUE;
        g_warning ("Failed to load index.\n");
        goto error;
    }
    repo->index_corrupted = FALSE;

    wt_status_collect_changes_worktree (&istate, &res, repo->worktree);
    if (res != NULL)
        goto changed;

    wt_status_collect_untracked (&istate, &res, repo->worktree, should_ignore);
    if (res != NULL)
        goto changed;

    wt_status_collect_changes_index (&istate, &res, repo);
    if (res != NULL)
        goto changed;

    discard_index (&istate);

    repo->wt_changed = FALSE;

    /* g_debug ("%s worktree is changed\n", repo->id); */
    return FALSE;

changed:

    g_message ("Worktree changes (at most 5 files are shown):\n");
    int i = 0;
    for (p = res; p != NULL && i < 5; p = p->next, ++i) {
        de = p->data;

        full_path = g_build_path ("/", repo->worktree, de->name, NULL);
        if (seaf_stat (full_path, &sb) < 0) {
            g_warning ("Failed to stat %s: %s.\n", full_path, strerror(errno));
            g_free (full_path);
            continue;
        }
        g_free (full_path);

        pos = index_name_pos (&istate, de->name, strlen(de->name));
        if (pos < 0) {
            g_warning ("Cannot find diff entry %s in index.\n", de->name);
            continue;
        }
        ce = istate.cache[pos];

        g_message ("type: %c, status: %c, name: %s, "
                   "ce mtime: %d, ce size: %" G_GUINT64_FORMAT ", "
                   "file mtime: %d, file size: %" G_GUINT64_FORMAT "\n",
                   de->type, de->status, de->name,
                   ce->ce_mtime.sec, ce->ce_size, (int)sb.st_mtime, sb.st_size);
    }

    for (p = res; p; p = p->next) {
        de = p->data;
        diff_entry_free (de);
    }
    g_list_free (res);

    discard_index (&istate);

    repo->wt_changed = TRUE;

    /* g_debug ("%s worktree is changed\n", repo->id); */
    return TRUE;

error:
    return FALSE;
}

inline static char *
get_basename (char *path)
{
    char *slash;
    slash = strrchr (path, '/');
    if (!slash)
        return path;
    return (slash + 1);
}

static char *
status_to_description (GList *results)
{
    GList *p;
    DiffEntry *de;
    char *new_file = NULL, *removed_file = NULL;
    char *renamed_file = NULL, *modified_file = NULL;
    char *new_dir = NULL, *removed_dir = NULL;
    int n_new = 0, n_removed = 0, n_renamed = 0, n_modified = 0;
    int n_new_dir = 0, n_removed_dir = 0;
    GString *desc;

    if (results == NULL)
        return NULL;

    for (p = results; p != NULL; p = p->next) {
        de = p->data;
        switch (de->status) {
        case DIFF_STATUS_ADDED:
            if (n_new == 0)
                new_file = get_basename(de->name);
            n_new++;
            break;
        case DIFF_STATUS_DELETED:
            if (n_removed == 0)
                removed_file = get_basename(de->name);
            n_removed++;
            break;
        case DIFF_STATUS_RENAMED:
            if (n_renamed == 0)
                renamed_file = get_basename(de->name);
            n_renamed++;
            break;
        case DIFF_STATUS_MODIFIED:
            if (n_modified == 0)
                modified_file = get_basename(de->name);
            n_modified++;
            break;
        case DIFF_STATUS_DIR_ADDED:
            if (n_new_dir == 0)
                new_dir = get_basename(de->name);
            n_new_dir++;
            break;
        case DIFF_STATUS_DIR_DELETED:
            if (n_removed_dir == 0)
                removed_dir = get_basename(de->name);
            n_removed_dir++;
            break;
        }
    }

    desc = g_string_new ("");

    if (n_new == 1)
        g_string_append_printf (desc, "Added \"%s\".\n", new_file);
    else if (n_new > 1)
        g_string_append_printf (desc, "Added \"%s\" and %d more files.\n",
                                new_file, n_new - 1);

    if (n_removed == 1)
        g_string_append_printf (desc, "Deleted \"%s\".\n", removed_file);
    else if (n_removed > 1)
        g_string_append_printf (desc, "Deleted \"%s\" and %d more files.\n",
                                removed_file, n_removed - 1);

    if (n_renamed == 1)
        g_string_append_printf (desc, "Renamed \"%s\".\n", renamed_file);
    else if (n_renamed > 1)
        g_string_append_printf (desc, "Renamed \"%s\" and %d more files.\n",
                                renamed_file, n_renamed - 1);

    if (n_modified == 1)
        g_string_append_printf (desc, "Modified \"%s\".\n", modified_file);
    else if (n_modified > 1)
        g_string_append_printf (desc, "Modified \"%s\" and %d more files.\n",
                                modified_file, n_modified - 1);

    if (n_new_dir == 1)
        g_string_append_printf (desc, "Added directory \"%s\".\n", new_dir);
    else if (n_new_dir > 1)
        g_string_append_printf (desc, "Added \"%s\" and %d more directories.\n",
                                new_dir, n_new_dir - 1);

    if (n_removed_dir == 1)
        g_string_append_printf (desc, "Removed directory \"%s\".\n", removed_dir);
    else if (n_removed_dir > 1)
        g_string_append_printf (desc, "Removed \"%s\" and %d more directories.\n",
                                removed_dir, n_removed_dir - 1);

    return g_string_free (desc, FALSE);
}

/*
 * Generate commit description based on files to be commited.
 * It only checks index status, not worktree status.
 * So it should be called after "add" completes.
 * This way we can always get the correct list of files to be
 * commited, even we were interrupted in the last add-commit
 * sequence.
 */
static char *
gen_commit_description (SeafRepo *repo, struct index_state *istate)
{
    GList *p;
    GList *results = NULL;
    char *desc;
    
    wt_status_collect_changes_index (istate, &results, repo);
    diff_resolve_empty_dirs (&results);
    diff_resolve_renames (&results);

    desc = status_to_description (results);
    if (!desc)
        return NULL;

    for (p = results; p; p = p->next) {
        DiffEntry *de = p->data;
        diff_entry_free (de);
    }
    g_list_free (results);

    return desc;
}

gboolean
seaf_repo_is_index_unmerged (SeafRepo *repo)
{
    SeafRepoManager *mgr = repo->manager;
    struct index_state istate;
    char index_path[SEAF_PATH_MAX];
    gboolean ret = FALSE;

    if (!repo->head)
        return FALSE;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path) < 0) {
        g_warning ("Failed to load index.\n");
        return FALSE;
    }

    if (unmerged_index (&istate))
        ret = TRUE;

    discard_index (&istate);
    return ret;
}

static int
commit_tree (SeafRepo *repo, struct cache_tree *it,
             const char *desc, char commit_id[],
             gboolean unmerged)
{
    SeafCommit *commit;
    char root_id[41];

    rawdata_to_hex (it->sha1, root_id, 20);

    if (!unmerged) {
        commit = seaf_commit_new (NULL, repo->id, root_id,
                                  repo->email ? repo->email
                                  : seaf->session->base.user_name,
                                  seaf->session->base.id,
                                  desc, 0);
    } else {
        commit = seaf_commit_new (NULL, repo->id, root_id,
                                  repo->email ? repo->email
                                  : seaf->session->base.user_name,
                                  seaf->session->base.id,
                                  "Auto merge by seafile system",
                                  0);
    }

    if (repo->head)
        commit->parent_id = g_strdup (repo->head->commit_id);

    if (unmerged) {
        SeafRepoMergeInfo minfo;

        /* Don't use head commit of master branch since that branch may have
         * been updated after the last merge.
         */
        memset (&minfo, 0, sizeof(minfo));
        if (seaf_repo_manager_get_merge_info (repo->manager, repo->id, &minfo) < 0) {
            seaf_warning ("Failed to get merge info of repo %.10s.\n", repo->id);
            return -1;
        }

        commit->second_parent_id = g_strdup (minfo.remote_head);
    }

    seaf_repo_to_commit (repo, commit);

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0)
        return -1;

    seaf_branch_set_commit (repo->head, commit->commit_id);
    seaf_branch_manager_update_branch (seaf->branch_mgr, repo->head);

    strcpy (commit_id, commit->commit_id);
    seaf_commit_unref (commit);

    return 0;
}

char *
seaf_repo_index_commit (SeafRepo *repo, const char *desc, GError **error)
{
    SeafRepoManager *mgr = repo->manager;
    struct index_state istate;
    struct cache_tree *it;
    char index_path[SEAF_PATH_MAX];
    char commit_id[41];
    gboolean unmerged = FALSE;

    if (!check_worktree_common (repo))
        return NULL;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path) < 0) {
        g_warning ("Failed to load index.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Internal data structure error");
        return NULL;
    }

    if (unmerged_index (&istate))
        unmerged = TRUE;

    if (index_add (repo, &istate, "") < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Failed to add");
        goto error;
    }

    /* Commit before updating the index, so that new blocks won't be GC'ed. */

    char *my_desc = g_strdup(desc);
    if (!unmerged && my_desc[0] == '\0') {
        char *gen_desc = gen_commit_description (repo, &istate);
        if (!gen_desc) {
            /* error not set. */
            g_free (my_desc);

            /* Still need to update index even nothing to commit. */
            update_index (&istate, index_path);
            discard_index (&istate);

            return NULL;
        }
        g_free (my_desc);
        my_desc = gen_desc;
    }

    it = cache_tree ();
    if (cache_tree_update (it, istate.cache,
                istate.cache_nr, 0, 0, commit_trees_cb) < 0) {
        g_warning ("Failed to build cache tree");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Internal data structure error");
        cache_tree_free (&it);
        goto error;
    }

    if (commit_tree (repo, it, my_desc, commit_id, unmerged) < 0) {
        g_warning ("Failed to save commit file");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Internal error");
        cache_tree_free (&it);
        goto error;
    }
    g_free (my_desc);
    cache_tree_free (&it);

    if (update_index (&istate, index_path) < 0)
        goto error;

    discard_index (&istate);

    g_signal_emit_by_name (seaf, "repo-committed", repo);

    return g_strdup(commit_id);

error:
    discard_index (&istate);
    return NULL;
}

#ifdef DEBUG_UNPACK_TREES
static void
print_unpack_result (struct index_state *result)
{
	int i;
	struct cache_entry *ce;

	for (i = 0; i < result->cache_nr; ++i) {
		ce = result->cache[i];
		printf ("%s\t", ce->name);
		if (ce->ce_flags & CE_UPDATE)
			printf ("update/add\n");
		else if (ce->ce_flags & CE_WT_REMOVE)
			printf ("remove\n");
		else
			printf ("unchange\n");
	}
}

static int 
print_index (struct index_state *istate)
{
    printf ("Index timestamp: %d\n", istate->timestamp.sec);

    int i;
    struct cache_entry *ce;
    char id[41];
    printf ("Totally %u entries in index.\n", istate->cache_nr);
    for (i = 0; i < istate->cache_nr; ++i) {
        ce = istate->cache[i];
        rawdata_to_hex (ce->sha1, id, 20);
        printf ("%s\t%s\t%o\t%d\t%d\n", ce->name, id, ce->ce_mode, 
                ce->ce_ctime.sec, ce->ce_mtime.sec);
    }

    return 0;
}
#endif  /* DEBUG_UNPACK_TREES */

int
seaf_repo_checkout_commit (SeafRepo *repo, SeafCommit *commit, gboolean recover_merge,
                           char **error)
{
    SeafRepoManager *mgr = repo->manager;
    char index_path[SEAF_PATH_MAX];
    struct tree_desc trees[2];
    struct unpack_trees_options topts;
    struct index_state istate;
    gboolean initial_checkout;
    GString *err_msgs;
    int ret = 0;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path) < 0) {
        g_warning ("Failed to load index.\n");
        return -1;
    }
    repo->index_corrupted = FALSE;
    initial_checkout = is_index_unborn(&istate);

    if (!initial_checkout) {
        if (!repo->head) {
            /* TODO: Set error string*/
            g_warning ("Repo corrupt: Index exists but head branch is not set\n");
            return -1;
        }
        SeafCommit *head =
            seaf_commit_manager_get_commit (seaf->commit_mgr,
                                            repo->head->commit_id);
        if (!head) {
            seaf_warning ("Failed to get commit %s.\n", repo->head->commit_id);
            discard_index (&istate);
            return -1;
        }
        fill_tree_descriptor (&trees[0], head->root_id);
        seaf_commit_unref (head);
    } else {
        fill_tree_descriptor (&trees[0], NULL);
    }
    fill_tree_descriptor (&trees[1], commit->root_id);

    /* 2-way merge to the new branch */
    memset(&topts, 0, sizeof(topts));
    topts.base = repo->worktree;
    topts.head_idx = -1;
    topts.src_index = &istate;
    /* topts.dst_index = &istate; */
    topts.initial_checkout = initial_checkout;
    topts.update = 1;
    topts.merge = 1;
    topts.gently = 0;
    topts.verbose_update = 0;
    /* topts.debug_unpack = 1; */
    topts.fn = twoway_merge;
    if (repo->encrypted) {
        topts.crypt = seafile_crypt_new (repo->enc_version, 
                                         repo->enc_key, 
                                         repo->enc_iv);
    }

    if (unpack_trees (2, trees, &topts) < 0) {
        g_warning ("Failed to merge commit %s with work tree.\n", commit->commit_id);
        ret = -1;
        goto out;
    }

#ifdef WIN32
    if (!initial_checkout && !recover_merge &&
        files_locked_on_windows(&topts.result, repo->worktree)) {
        g_debug ("[checkout] files are locked, quit checkout now.\n");
        ret = -1;
        goto out;
    }
#endif

    int *finished_entries = NULL;
    CheckoutTask *c_task = seaf_repo_manager_get_checkout_task (repo->manager, repo->id);
    if (c_task) {
        finished_entries = &c_task->finished_files;
    }
    if (update_worktree (&topts, recover_merge,
                         initial_checkout ? NULL : commit->commit_id,
                         commit->creator_name,
                         finished_entries) < 0) {
        g_warning ("Failed to update worktree.\n");
        /* Still finish checkout even have I/O errors. */
    }

    discard_index (&istate);
    istate = topts.result;
    if (update_index (&istate, index_path) < 0) {
        g_warning ("Failed to update index.\n");
        ret = -1;
        goto out;
    }

out:
    err_msgs = g_string_new ("");
    get_unpack_trees_error_msgs (&topts, err_msgs, OPR_CHECKOUT);
    *error = g_string_free (err_msgs, FALSE);

    tree_desc_free (&trees[0]);
    tree_desc_free (&trees[1]);

    g_free (topts.crypt);

    discard_index (&istate);

    return ret;
}


/**
 * Checkout the content of "local" branch to <worktree_parent>/repo-name.
 * The worktree will be set to this place too.
 */
int
seaf_repo_checkout (SeafRepo *repo, const char *worktree, char **error)
{
    const char *commit_id;
    SeafBranch *branch;
    SeafCommit *commit;
    GString *err_msgs;

    /* remove original index */
    char index_path[SEAF_PATH_MAX];
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", repo->manager->index_dir, repo->id);
    g_unlink (index_path);

    branch = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                             repo->id, "local");
    if (!branch) {
        g_warning ("[repo-mgr] Checkout repo failed: local branch does not exists\n");
        *error = g_strdup ("Repo's local branch does not exists.");
        goto error;
    }
    commit_id = branch->commit_id;
        
    commit = seaf_commit_manager_get_commit (seaf->commit_mgr, commit_id);
    if (!commit) {
        err_msgs = g_string_new ("");
        g_string_append_printf (err_msgs, "Commit %s does not exist.\n",
                                commit_id);
        g_warning ("%s", err_msgs->str);
        *error = g_string_free (err_msgs, FALSE);
        seaf_branch_unref (branch);
        goto error;
    }

    if (strcmp(repo->id, commit->repo_id) != 0) {
        err_msgs = g_string_new ("");
        g_string_append_printf (err_msgs, "Commit %s is not in Repo %s.\n", 
                                commit_id, repo->id);
        g_warning ("%s", err_msgs->str);
        *error = g_string_free (err_msgs, FALSE);
        seaf_commit_unref (commit);
        if (branch)
            seaf_branch_unref (branch);
        goto error;
    }

    CheckoutTask *task = seaf_repo_manager_get_checkout_task (seaf->repo_mgr,
                                                              repo->id);
    if (!task) {
        seaf_warning ("No checkout task found for repo %.10s.\n", repo->id);
        goto error;
    }
    task->total_files = seaf_fs_manager_count_fs_files (seaf->fs_mgr, commit->root_id);

    if (task->total_files < 0) {
        seaf_warning ("Failed to count files for repo %.10s .\n", repo->id);
        goto error;
    }

    if (seaf_repo_checkout_commit (repo, commit, FALSE, error) < 0) {
        seaf_commit_unref (commit);
        if (branch)
            seaf_branch_unref (branch);
        goto error;
    }

    seaf_branch_unref (branch);
    seaf_commit_unref (commit);

    return 0;

error:
    return -1;
}

int
seaf_repo_merge (SeafRepo *repo, const char *branch, char **error,
                 gboolean *real_merge)
{
    SeafBranch *remote_branch;
    int ret = 0;

    if (!check_worktree_common (repo))
        return -1;

    remote_branch = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                    repo->id,
                                                    branch);
    if (!remote_branch) {
        *error = g_strdup("Invalid remote branch.\n");
        goto error;
    }

    if (g_strcmp0 (remote_branch->repo_id, repo->id) != 0) {
        *error = g_strdup ("Remote branch is not in this repository.\n");
        seaf_branch_unref (remote_branch);
        goto error;
    }

    ret = merge_branches (repo, remote_branch, error, real_merge);
    seaf_branch_unref (remote_branch);

    return ret;

error:
    return -1;
}

int
seaf_repo_manager_set_repo_worktree (SeafRepoManager *mgr,
                                     SeafRepo *repo,
                                     const char *worktree)
{
    if (g_access(worktree, F_OK) != 0)
        return -1;

    if (repo->worktree)
        g_free (repo->worktree);
    repo->worktree = g_strdup(worktree);
    send_wktree_notification (repo, TRUE);

    if (seaf_repo_manager_set_repo_property (mgr, repo->id,
                                             "worktree",
                                             repo->worktree) < 0)
        return -1;

    repo->worktree_invalid = FALSE;

    return 0;
}

void
seaf_repo_manager_invalidate_repo_worktree (SeafRepoManager *mgr,
                                            SeafRepo *repo)
{
    if (repo->worktree_invalid)
        return;

    repo->worktree_invalid = TRUE;

    if (repo->auto_sync) {
        if (seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo->id) < 0) {
            g_warning ("failed to unwatch repo %s.\n", repo->id);
        }
    }
}

void
seaf_repo_manager_validate_repo_worktree (SeafRepoManager *mgr,
                                          SeafRepo *repo)
{
    if (!repo->worktree_invalid)
        return;

    repo->worktree_invalid = FALSE;

    if (repo->auto_sync) {
        if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id) < 0) {
            g_warning ("failed to watch repo %s.\n", repo->id);
            /* If we fail to add watch, sync manager
             * will periodically check repo status and retry.
             */
        }
    }
}

void
seaf_repo_generate_magic (SeafRepo *repo, const char *passwd)
{
    GString *buf = g_string_new (NULL);
    unsigned char key[16], iv[16];

    /* Compute a "magic" string from repo_id and passwd.
     * This is used to verify the password given by user before decrypting
     * data.
     * We use large iteration times to defense against brute-force attack.
     */
    g_string_append_printf (buf, "%s%s", repo->id, passwd);

    seafile_generate_enc_key (buf->str, buf->len, CURRENT_ENC_VERSION, key, iv);

    g_string_free (buf, TRUE);
    rawdata_to_hex (key, repo->magic, 16);
}

static int 
compare_repo (const SeafRepo *srepo, const SeafRepo *trepo)
{
    return g_strcmp0 (srepo->id, trepo->id);
}

SeafRepoManager*
seaf_repo_manager_new (SeafileSession *seaf)
{
    SeafRepoManager *mgr = g_new0 (SeafRepoManager, 1);

    mgr->priv = g_new0 (SeafRepoManagerPriv, 1);
    mgr->seaf = seaf;
    mgr->index_dir = g_build_path (PATH_SEPERATOR, seaf->seaf_dir, INDEX_DIR, NULL);

    pthread_mutex_init (&mgr->priv->db_lock, NULL);

    mgr->priv->checkout_tasks_hash = g_hash_table_new_full
        (g_str_hash, g_str_equal, g_free, g_free);

    ignore_patterns = g_new0 (GPatternSpec*, G_N_ELEMENTS(ignore_table));
    int i;
    for (i = 0; ignore_table[i] != NULL; i++) {
        ignore_patterns[i] = g_pattern_spec_new (ignore_table[i]);
    }

    mgr->priv->repo_tree = avl_alloc_tree ((avl_compare_t)compare_repo,
                                           NULL);

    pthread_rwlock_init (&mgr->priv->lock, NULL);

    return mgr;
}

int
seaf_repo_manager_init (SeafRepoManager *mgr)
{
    if (checkdir_with_mkdir (mgr->index_dir) < 0) {
        g_warning ("Index dir %s does not exist and is unable to create\n",
                   mgr->index_dir);
        return -1;
    }

    /* Load all the repos into memory on the client side. */
    load_repos (mgr, mgr->seaf->seaf_dir);

    return 0;
}

static void
watch_repos (SeafRepoManager *mgr)
{
    avl_node_t *node;
    SeafRepo *repo;

    for (node = mgr->priv->repo_tree->head; node; node = node->next) {
        repo = node->item;
        if (repo->auto_sync && !repo->worktree_invalid) {
            if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id) < 0) {
                g_warning ("failed to watch repo %s.\n", repo->id);
                /* If we fail to add watch at the beginning, sync manager
                 * will periodically check repo status and retry.
                 */
            }
        }
    }
}

int
seaf_repo_manager_start (SeafRepoManager *mgr)
{
    watch_repos (mgr);

    return 0;
}

SeafRepo*
seaf_repo_manager_create_new_repo (SeafRepoManager *mgr,
                                   const char *name,
                                   const char *desc)
{
    SeafRepo *repo;
    char *repo_id;
    
    repo_id = gen_uuid ();
    repo = seaf_repo_new (repo_id, name, desc);
    if (!repo) {
        g_free (repo_id);
        return NULL;
    }
    g_free (repo_id);

    /* we directly create dir because it shouldn't exist */
    /* if (seaf_repo_mkdir (repo, base) < 0) { */
    /*     seaf_repo_free (repo); */
    /*     goto out; */
    /* } */

    seaf_repo_manager_add_repo (mgr, repo);
    return repo;
}

int
seaf_repo_manager_add_repo (SeafRepoManager *manager,
                            SeafRepo *repo)
{
    char sql[256];
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), "INSERT INTO Repo VALUES ('%s');", repo->id);
    sqlite_query_exec (db, sql);

    pthread_mutex_unlock (&manager->priv->db_lock);

    repo->manager = manager;

    if (pthread_rwlock_wrlock (&manager->priv->lock) < 0) {
        g_warning ("[repo mgr] failed to lock repo cache.\n");
        return -1;
    }

    avl_insert (manager->priv->repo_tree, repo);

    pthread_rwlock_unlock (&manager->priv->lock);
    send_wktree_notification (repo, TRUE);

    return 0;
}

int
seaf_repo_manager_mark_repo_deleted (SeafRepoManager *mgr, SeafRepo *repo)
{
    char sql[256];

    pthread_mutex_lock (&mgr->priv->db_lock);

    snprintf (sql, sizeof(sql), "INSERT INTO DeletedRepo VALUES ('%s')",
              repo->id);
    if (sqlite_query_exec (mgr->priv->db, sql) < 0) {
        pthread_mutex_unlock (&mgr->priv->db_lock);
        return -1;
    }

    pthread_mutex_unlock (&mgr->priv->db_lock);

    repo->delete_pending = TRUE;
    send_wktree_notification (repo, FALSE);

    return 0;
}

static void
remove_repo_ondisk (SeafRepoManager *mgr, const char *repo_id)
{
    char sql[256];

    /* We don't need to care about I/O errors here, since we can
     * GC any unreferenced repo data later.
     */

    /* Once the item in Repo table is deleted, the repo is gone.
     * This is the "commit point".
     */
    snprintf (sql, sizeof(sql), "DELETE FROM Repo WHERE repo_id = '%s'", repo_id);
    if (sqlite_query_exec (mgr->priv->db, sql) < 0)
        goto out;

    snprintf (sql, sizeof(sql), 
              "DELETE FROM DeletedRepo WHERE repo_id = '%s'", repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    /* remove index */
    char path[SEAF_PATH_MAX];
    snprintf (path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo_id);
    if (g_unlink (path) < 0) {
        if (errno != ENOENT) {
            g_warning("Cannot delete index file: %s", strerror(errno));
        }
    }

    /* remove branch */
    GList *p;
    GList *branch_list = 
        seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo_id);
    for (p = branch_list; p; p = p->next) {
        SeafBranch *b = (SeafBranch *)p->data;
        seaf_repo_manager_branch_repo_unmap (mgr, b);
        seaf_branch_manager_del_branch (seaf->branch_mgr, repo_id, b->name);
    }
    seaf_branch_list_free (branch_list);

    /* delete repo property firstly */
    seaf_repo_manager_del_repo_property (mgr, repo_id);

    pthread_mutex_lock (&mgr->priv->db_lock);
#ifdef HAVE_KEYSTORAGE_GK
    gnome_keyring_sf_delete_password(repo_id, "password");
#endif
    snprintf (sql, sizeof(sql), "DELETE FROM RepoPasswd WHERE repo_id = '%s'", 
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);
    snprintf (sql, sizeof(sql), "DELETE FROM RepoKeys WHERE repo_id = '%s'", 
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    snprintf (sql, sizeof(sql), "DELETE FROM MergeInfo WHERE repo_id = '%s'", 
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

out:
    pthread_mutex_unlock (&mgr->priv->db_lock);
}

int
seaf_repo_manager_del_repo (SeafRepoManager *mgr,
                            SeafRepo *repo)
{
    remove_repo_ondisk (mgr, repo->id);

    if (pthread_rwlock_wrlock (&mgr->priv->lock) < 0) {
        g_warning ("[repo mgr] failed to lock repo cache.\n");
        return -1;
    }

    avl_delete (mgr->priv->repo_tree, repo);

    pthread_rwlock_unlock (&mgr->priv->lock);

    send_wktree_notification (repo, FALSE);

    seaf_repo_free (repo);

    return 0;
}

SeafRepo*
seaf_repo_manager_get_repo (SeafRepoManager *manager, const gchar *id)
{
    SeafRepo repo;
    int len = strlen(id);

    if (len >= 37)
        return NULL;

    memcpy (repo.id, id, len + 1);
    if (pthread_rwlock_rdlock (&manager->priv->lock) < 0) {
        g_warning ("[repo mgr] failed to lock repo cache.\n");
        return NULL;
    }

    avl_node_t *res = avl_search (manager->priv->repo_tree, &repo);

    pthread_rwlock_unlock (&manager->priv->lock);

    if (res) {
        SeafRepo *ret = (SeafRepo *)res->item;
        if (!ret->delete_pending)
            return ret;
    }
    return NULL;
}

SeafRepo*
seaf_repo_manager_get_repo_prefix (SeafRepoManager *manager, const gchar *id)
{
    avl_node_t *node;
    SeafRepo repo, *result;
    int len = strlen(id);

    if (len >= 37)
        return NULL;

    memcpy (repo.id, id, len + 1);

    avl_search_closest (manager->priv->repo_tree, &repo, &node);
    if (node != NULL) {
        result = node->item;
        if (strncmp (id, result->id, len) == 0)
            return node->item;
    }
    return NULL;
}

gboolean
seaf_repo_manager_repo_exists (SeafRepoManager *manager, const gchar *id)
{
    SeafRepo repo;
    memcpy (repo.id, id, 37);

    if (pthread_rwlock_rdlock (&manager->priv->lock) < 0) {
        g_warning ("[repo mgr] failed to lock repo cache.\n");
        return FALSE;
    }

    avl_node_t *res = avl_search (manager->priv->repo_tree, &repo);

    pthread_rwlock_unlock (&manager->priv->lock);

    if (res) {
        SeafRepo *ret = (SeafRepo *)res->item;
        if (!ret->delete_pending)
            return TRUE;
    }
    return FALSE;
}

gboolean
seaf_repo_manager_repo_exists_prefix (SeafRepoManager *manager, const gchar *id)
{
    avl_node_t *node;
    SeafRepo repo;

    memcpy (repo.id, id, 37);

    avl_search_closest (manager->priv->repo_tree, &repo, &node);
    if (node != NULL)
        return TRUE;
    return FALSE;
}

static gboolean
get_token (sqlite3_stmt *stmt, void *data)
{
    char **token = data;

    *token = g_strdup((char *)sqlite3_column_text (stmt, 0));
    /* There should be only one result. */
    return FALSE;
}

char *
seaf_repo_manager_get_repo_lantoken (SeafRepoManager *manager,
                                     const char *repo_id)
{
    char sql[256];
    char *ret = NULL;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql),
              "SELECT token FROM RepoLanToken WHERE repo_id='%s'",
              repo_id);
    if (sqlite_foreach_selected_row (manager->priv->db, sql,
                                     get_token, &ret) < 0) {
        g_warning ("DB error when get token for repo %s.\n", repo_id);
        pthread_mutex_unlock (&manager->priv->db_lock);
        return NULL;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    return ret;
}

int
seaf_repo_manager_set_repo_lantoken (SeafRepoManager *manager,
                                     const char *repo_id,
                                     const char *token)
{
    char sql[256];
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), "REPLACE INTO RepoLanToken VALUES ('%s', '%s');",
              repo_id, token);
    if (sqlite_query_exec (db, sql) < 0) {
        pthread_mutex_unlock (&manager->priv->db_lock);
        return -1;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    return 0;
}

int
seaf_repo_manager_verify_repo_lantoken (SeafRepoManager *manager,
                                        const char *repo_id,
                                        const char *token)
{
    int ret = 0;
    if (!token)
        return 0;

    char *my_token = seaf_repo_manager_get_repo_lantoken (manager, repo_id);

    if (!my_token) {
        if (memcmp (DEFAULT_REPO_TOKEN, token, strlen(token)) == 0)
            ret = 1;
    } else {
        if (memcmp (my_token, token, strlen(token)) == 0)
            ret = 1;
        g_free (my_token);
    }

    return ret;
}

char *
seaf_repo_manager_generate_tmp_token (SeafRepoManager *manager,
                                      const char *repo_id,
                                      const char *peer_id)
{
    char sql[256];
    sqlite3 *db = manager->priv->db;

    int now = time(NULL);
    char *token = gen_uuid();
    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql),
              "REPLACE INTO RepoTmpToken VALUES ('%s', '%s', '%s', %d);",
              repo_id, peer_id, token, now);
    if (sqlite_query_exec (db, sql) < 0) {
        pthread_mutex_unlock (&manager->priv->db_lock);
        g_free (token);
        return NULL;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);
    return token;
}

int
seaf_repo_manager_verify_tmp_token (SeafRepoManager *manager,
                                    const char *repo_id,
                                    const char *peer_id,
                                    const char *token)
{
    int ret;
    char sql[512];
    if (!repo_id || !peer_id || !token)
        return 0;

    pthread_mutex_lock (&manager->priv->db_lock);
    snprintf (sql, 512, "SELECT timestamp FROM RepoTmpToken "
              "WHERE repo_id='%s' AND peer_id='%s' AND token='%s'",
              repo_id, peer_id, token);
    ret = sqlite_check_for_existence (manager->priv->db, sql);
    if (ret) {
        snprintf (sql, 512, "DELETE FROM RepoTmpToken WHERE "
                  "repo_id='%s' AND peer_id='%s'",
                  repo_id, peer_id);
        sqlite_query_exec (manager->priv->db, sql);
    }
    pthread_mutex_unlock (&manager->priv->db_lock);

    return ret;
}

static int
save_branch_repo_map (SeafRepoManager *manager, SeafBranch *branch)
{
    char *sql;
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    sql = sqlite3_mprintf ("REPLACE INTO RepoBranch VALUES (%Q, %Q)",
                           branch->repo_id, branch->name);
    sqlite_query_exec (db, sql);
    sqlite3_free (sql);

    pthread_mutex_unlock (&manager->priv->db_lock);

    return 0;
}

int
seaf_repo_manager_branch_repo_unmap (SeafRepoManager *manager, SeafBranch *branch)
{
    char *sql;
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    sql = sqlite3_mprintf ("DELETE FROM RepoBranch WHERE branch_name = %Q"
                           " AND repo_id = %Q",
                           branch->name, branch->repo_id);
    if (sqlite_query_exec (db, sql) < 0) {
        g_warning ("Unmap branch repo failed\n");
        pthread_mutex_unlock (&manager->priv->db_lock);
        sqlite3_free (sql);
        return -1;
    }

    sqlite3_free (sql);
    pthread_mutex_unlock (&manager->priv->db_lock);

    return 0;
}

static void
load_repo_commit (SeafRepoManager *manager,
                  SeafRepo *repo,
                  SeafBranch *branch)
{
    SeafCommit *commit;

    commit = seaf_commit_manager_get_commit (manager->seaf->commit_mgr,
                                             branch->commit_id);
    if (!commit) {
        g_warning ("Commit %s is missing\n", branch->commit_id);
        repo->is_corrupted = TRUE;
        return;
    }

    set_head_common (repo, branch);
    seaf_repo_from_commit (repo, commit);

    seaf_commit_unref (commit);
}

static gboolean
load_passwd_cb (sqlite3_stmt *stmt, void *vrepo)
{
    SeafRepo *repo = vrepo;

    repo->encrypted = TRUE;
    repo->passwd = g_strdup ((const char *)sqlite3_column_text(stmt, 0));

    return FALSE;
}

static gboolean
load_keys_cb (sqlite3_stmt *stmt, void *vrepo)
{
    SeafRepo *repo = vrepo;
    const char *key, *iv;

    key = (const char *)sqlite3_column_text(stmt, 0);
    iv = (const char *)sqlite3_column_text(stmt, 1);

    hex_to_rawdata (key, repo->enc_key, 16);
    hex_to_rawdata (iv, repo->enc_iv, 16);

    return FALSE;
}

static void
recover_repo_enc_keys (SeafRepoManager *manager, SeafRepo *repo)
{
    unsigned char key[16], iv[16];
    char hex_key[33], hex_iv[33];
    sqlite3 *db = manager->priv->db;
    char sql[256];

    seafile_generate_enc_key (repo->passwd, strlen(repo->passwd), 
                              repo->enc_version, key, iv);

    memcpy (repo->enc_key, key, 16);
    memcpy (repo->enc_iv, iv, 16);

    rawdata_to_hex (key, hex_key, 16);
    rawdata_to_hex (iv, hex_iv, 16);

    snprintf (sql, sizeof(sql), "INSERT INTO RepoKeys VALUES ('%s', '%s', '%s')",
              repo->id, hex_key, hex_iv);
    sqlite_query_exec (db, sql);
}

static int
load_repo_passwd (SeafRepoManager *manager, SeafRepo *repo)
{
    sqlite3 *db = manager->priv->db;
    char sql[256];
    int n;

    pthread_mutex_lock (&manager->priv->db_lock);
#ifdef HAVE_KEYSTORAGE_GK
    guint gk_item_id;
    char* gk_password;
    gk_password = gnome_keyring_sf_get_password(repo->id, "password", &gk_item_id);
    if (gk_password != NULL) {
        repo->encrypted = TRUE;
        repo->passwd = g_strdup(gk_password);
        g_free(gk_password);
        gk_password = NULL;
    } else {
#else    
    snprintf (sql, sizeof(sql), 
              "SELECT passwd FROM RepoPasswd WHERE repo_id='%s'",
              repo->id);
    if (sqlite_foreach_selected_row (db, sql, load_passwd_cb, repo) < 0)
        return -1;
#endif
#ifdef HAVE_KEYSTORAGE_GK
    }
#endif
    snprintf (sql, sizeof(sql), 
              "SELECT key, iv FROM RepoKeys WHERE repo_id='%s'",
              repo->id);
    n = sqlite_foreach_selected_row (db, sql, load_keys_cb, repo);
    if (n < 0)
        return -1;

    /* Case 1: upgrade from encryption version 0 to version 1.
     * Case 2: Database lost.
     */
    if (n == 0 && repo->passwd != NULL)
        recover_repo_enc_keys (manager, repo);

    pthread_mutex_unlock (&manager->priv->db_lock);

    return 0;
    
}

static gboolean
load_property_cb (sqlite3_stmt *stmt, void *pvalue)
{
    char **value = pvalue;

    char *v = (char *) sqlite3_column_text (stmt, 0);
    *value = g_strdup (v);

    /* Only one result. */
    return FALSE;
}

static char *
load_repo_property (SeafRepoManager *manager,
                    const char *repo_id,
                    const char *key)
{
    sqlite3 *db = manager->priv->db;
    char sql[256];
    char *value = NULL;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf(sql, 256, "SELECT value FROM RepoProperty WHERE "
             "repo_id='%s' and key='%s'", repo_id, key);
    if (sqlite_foreach_selected_row (db, sql, load_property_cb, &value) < 0) {
        g_warning ("Error read property %s for repo %s.\n", key, repo_id);
        pthread_mutex_unlock (&manager->priv->db_lock);
        return NULL;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    return value;
}

static gboolean
load_branch_cb (sqlite3_stmt *stmt, void *vrepo)
{
    SeafRepo *repo = vrepo;
    SeafRepoManager *manager = repo->manager;

    char *branch_name = (char *) sqlite3_column_text (stmt, 0);
    SeafBranch *branch =
        seaf_branch_manager_get_branch (manager->seaf->branch_mgr,
                                        repo->id, branch_name);
    if (branch == NULL) {
        g_warning ("Broken branch name for repo %s\n", repo->id); 
        repo->is_corrupted = TRUE;
        return FALSE;
    }
    load_repo_commit (manager, repo, branch);
    seaf_branch_unref (branch);

    /* Only one result. */
    return FALSE;
}

static SeafRepo *
load_repo (SeafRepoManager *manager, const char *repo_id)
{
    char sql[256];

    SeafRepo *repo = seaf_repo_new(repo_id, NULL, NULL);
    if (!repo) {
        g_warning ("[repo mgr] failed to alloc repo.\n");
        return NULL;
    }

    repo->manager = manager;

    snprintf(sql, 256, "SELECT branch_name FROM RepoBranch WHERE repo_id='%s'",
             repo->id);
    if (sqlite_foreach_selected_row (manager->priv->db, sql, 
                                     load_branch_cb, repo) < 0) {
        g_warning ("Error read branch for repo %s.\n", repo->id);
        seaf_repo_free (repo);
        return NULL;
    }

    /* If repo head is set but failed to load branch or commit. */
    if (repo->is_corrupted) {
        seaf_repo_free (repo);
        /* remove_repo_ondisk (manager, repo_id); */
        return NULL;
    }

    /* Repo head may be not set if it's just cloned but not checked out yet. */
    if (repo->head == NULL) {
        /* the repo do not have a head branch, try to load 'master' branch */
        SeafBranch *branch =
            seaf_branch_manager_get_branch (manager->seaf->branch_mgr,
                                            repo->id, "master");
        if (branch != NULL) {
             SeafCommit *commit;

             commit = seaf_commit_manager_get_commit (manager->seaf->commit_mgr,
                                                      branch->commit_id);
             if (commit) {
                 seaf_repo_from_commit (repo, commit);
                 seaf_commit_unref (commit);
             } else {
                 g_warning ("[repo-mgr] Can not find commit %s\n",
                            branch->commit_id);
                 repo->is_corrupted = TRUE;
             }

             seaf_branch_unref (branch);
        } else {
            g_warning ("[repo-mgr] Failed to get branch master");
            repo->is_corrupted = TRUE;
        }
    }

    if (repo->is_corrupted) {
        seaf_repo_free (repo);
        /* remove_repo_ondisk (manager, repo_id); */
        return NULL;
    }

    load_repo_passwd (manager, repo);

    char *value;

    value = load_repo_property (manager, repo->id, REPO_AUTO_SYNC);
    if (g_strcmp0(value, "false") == 0) {
        repo->auto_sync = 0;
    }
    g_free (value);

    repo->worktree = load_repo_property (manager, repo->id, "worktree");
    if (repo->worktree)
        repo->worktree_invalid = FALSE;

    repo->relay_id = load_repo_property (manager, repo->id, REPO_RELAY_ID);
    if (repo->relay_id && strlen(repo->relay_id) != 40) {
        g_free (repo->relay_id);
        repo->relay_id = NULL;
    }

    value = load_repo_property (manager, repo->id, REPO_NET_BROWSABLE);
    if (g_strcmp0(value, "true") == 0) {
        repo->net_browsable = 1;
    }
    g_free (value);

    repo->email = load_repo_property (manager, repo->id, REPO_PROP_EMAIL);
    repo->token = load_repo_property (manager, repo->id, REPO_PROP_TOKEN);
    
    if (repo->head != NULL && seaf_repo_check_worktree (repo) < 0) {
        seaf_message ("Worktree for repo \"%s\" is invalid, delte it.\n",
                      repo->name);
        seaf_repo_manager_del_repo (manager, repo);
        return NULL;
    }

    avl_insert (manager->priv->repo_tree, repo);
    send_wktree_notification (repo, TRUE);

    return repo;
}

static sqlite3*
open_db (SeafRepoManager *manager, const char *seaf_dir)
{
    sqlite3 *db;
    char *db_path;

    db_path = g_build_filename (seaf_dir, "repo.db", NULL);
    if (sqlite_open_db (db_path, &db) < 0)
        return NULL;
    g_free (db_path);
    manager->priv->db = db;

    char *sql = "CREATE TABLE IF NOT EXISTS Repo (repo_id TEXT PRIMARY KEY);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS DeletedRepo (repo_id TEXT PRIMARY KEY);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS RepoBranch ("
        "repo_id TEXT PRIMARY KEY, branch_name TEXT);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS RepoLanToken ("
        "repo_id TEXT PRIMARY KEY, token TEXT);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS RepoTmpToken ("
        "repo_id TEXT, peer_id TEXT, token TEXT, timestamp INTEGER, "
        "PRIMARY KEY (repo_id, peer_id));";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS RepoPasswd "
        "(repo_id TEXT PRIMARY KEY, passwd TEXT NOT NULL);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS RepoKeys "
        "(repo_id TEXT PRIMARY KEY, key TEXT NOT NULL, iv TEXT NOT NULL);";
    sqlite_query_exec (db, sql);
    
    sql = "CREATE TABLE IF NOT EXISTS RepoProperty ("
        "repo_id TEXT, key TEXT, value TEXT);";
    sqlite_query_exec (db, sql);

    sql = "CREATE INDEX IF NOT EXISTS RepoIndex ON RepoProperty (repo_id);";
    sqlite_query_exec (db, sql);

    sql = "CREATE TABLE IF NOT EXISTS MergeInfo ("
        "repo_id TEXT PRIMARY KEY, in_merge INTEGER, branch TEXT);";
    sqlite_query_exec (db, sql);

    return db;
}

static gboolean
load_repo_cb (sqlite3_stmt *stmt, void *vmanager)
{
    SeafRepoManager *manager = vmanager;
    const char *repo_id;

    repo_id = (const char *) sqlite3_column_text (stmt, 0);

    load_repo (manager, repo_id);

    return TRUE;
}

static gboolean
remove_deleted_repo (sqlite3_stmt *stmt, void *vmanager)
{
    SeafRepoManager *manager = vmanager;
    const char *repo_id;

    repo_id = (const char *) sqlite3_column_text (stmt, 0);

    remove_repo_ondisk (manager, repo_id);

    return TRUE;
}

static void
load_repos (SeafRepoManager *manager, const char *seaf_dir)
{
    sqlite3 *db = open_db(manager, seaf_dir);
    if (!db) return;

    char *sql;

    sql = "SELECT repo_id FROM DeletedRepo";
    if (sqlite_foreach_selected_row (db, sql, remove_deleted_repo, manager) < 0) {
        g_warning ("Error removing deleted repos.\n");
        return;
    }

    sql = "SELECT repo_id FROM Repo;";
    if (sqlite_foreach_selected_row (db, sql, load_repo_cb, manager) < 0) {
        g_warning ("Error read repo db.\n");
        return;
    }
}

static void
save_repo_property (SeafRepoManager *manager,
                    const char *repo_id,
                    const char *key, const char *value)
{
    char *sql;
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    sql = sqlite3_mprintf ("SELECT repo_id FROM RepoProperty WHERE repo_id=%Q AND key=%Q",
                           repo_id, key);
    if (sqlite_check_for_existence(db, sql)) {
        sqlite3_free (sql);
        sql = sqlite3_mprintf ("UPDATE RepoProperty SET value=%Q"
                               "WHERE repo_id=%Q and key=%Q",
                               value, repo_id, key);
        sqlite_query_exec (db, sql);
        sqlite3_free (sql);
    } else {
        sqlite3_free (sql);
        sql = sqlite3_mprintf ("INSERT INTO RepoProperty VALUES (%Q, %Q, %Q)",
                               repo_id, key, value);
        sqlite_query_exec (db, sql);
        sqlite3_free (sql);
    }

    pthread_mutex_unlock (&manager->priv->db_lock);
}

inline static gboolean is_peer_relay (const char *peer_id)
{
    CcnetPeer *peer = ccnet_get_peer(seaf->ccnetrpc_client, peer_id);

    if (!peer)
        return FALSE;

    gboolean is_relay = string_list_is_exists(peer->role_list, "MyRelay");
    g_object_unref (peer);
    return is_relay;
}

int
seaf_repo_manager_set_repo_relay_id (SeafRepoManager *mgr,
                                     SeafRepo *repo,
                                     const char *relay_id)
{
    if (relay_id && strlen(relay_id) != 40)
        return -1;
    if (!is_peer_relay(relay_id))
        return -1;

    save_repo_property (mgr, repo->id, REPO_RELAY_ID, relay_id);

    g_free (repo->relay_id);

    if (relay_id)
        repo->relay_id = g_strdup (relay_id);
    else
        repo->relay_id = NULL;        
    return 0;
}

int
seaf_repo_manager_set_repo_property (SeafRepoManager *manager, 
                                     const char *repo_id,
                                     const char *key,
                                     const char *value)
{
    SeafRepo *repo;

    repo = seaf_repo_manager_get_repo (manager, repo_id);
    if (!repo)
        return -1;

    if (strcmp(key, REPO_AUTO_SYNC) == 0) {
        if (!seaf->started) {
            seaf_message ("System not started, skip setting auto sync value.\n");
            return 0;
        }

        if (g_strcmp0(value, "true") == 0) {
            repo->auto_sync = 1;
            seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id);
        } else {
            repo->auto_sync = 0;
            seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo->id);
            /* Cancel current sync task if any. */
            seaf_sync_manager_cancel_sync_task (seaf->sync_mgr, repo->id);
        }
    }
    if (strcmp(key, REPO_NET_BROWSABLE) == 0) {
        if (g_strcmp0(value, "true") == 0)
            repo->net_browsable = 1;
        else
            repo->net_browsable = 0;
    }

    if (strcmp(key, REPO_RELAY_ID) == 0)
        return seaf_repo_manager_set_repo_relay_id (manager, repo, value);

    save_repo_property (manager, repo_id, key, value);
    return 0;
}

char *
seaf_repo_manager_get_repo_property (SeafRepoManager *manager, 
                                     const char *repo_id,
                                     const char *key)
{
    return load_repo_property (manager, repo_id, key);
}

static void
seaf_repo_manager_del_repo_property (SeafRepoManager *manager, 
                                     const char *repo_id)
{
    char *sql;
    sqlite3 *db = manager->priv->db;

    pthread_mutex_lock (&manager->priv->db_lock);

    sql = sqlite3_mprintf ("DELETE FROM RepoProperty WHERE repo_id = %Q", repo_id);
    sqlite_query_exec (db, sql);
    sqlite3_free (sql);

    pthread_mutex_unlock (&manager->priv->db_lock);
}

static int
save_repo_enc_info (SeafRepoManager *manager,
                    SeafRepo *repo)
{
    sqlite3 *db = manager->priv->db;
    char sql[256];
    char key[33], iv[33];

#ifdef HAVE_KEYSTORAGE_GK
    if (gnome_keyring_sf_set_password(repo->id, "password", repo->passwd) != 1)
        return -1;
#else
    sqlite3_snprintf (sizeof(sql), sql,
                      "REPLACE INTO RepoPasswd VALUES ('%s', '%q');",
                      repo->id, repo->passwd);
    if (sqlite_query_exec (db, sql) < 0)
        return -1;
#endif
    rawdata_to_hex (repo->enc_key, key, 16);
    rawdata_to_hex (repo->enc_iv, iv, 16);
    snprintf (sql, sizeof(sql), "REPLACE INTO RepoKeys VALUES ('%s', '%s', '%s')",
              repo->id, key, iv);
    if (sqlite_query_exec (db, sql) < 0)
        return -1;

    return 0;
}

static void
generate_repo_enc_key (SeafRepo *repo, const char *passwd)
{
    unsigned char key[16], iv[16];

    /* Compute encryption key from password.
     * We use large iteration times to defense against brute-force attack.
     */
    seafile_generate_enc_key (passwd, strlen(passwd), repo->enc_version, key, iv);

    memcpy (repo->enc_key, key, 16);
    memcpy (repo->enc_iv, iv, 16);
}

int 
seaf_repo_manager_set_repo_passwd (SeafRepoManager *manager,
                                   SeafRepo *repo,
                                   const char *passwd)
{
    int ret;

    generate_repo_enc_key (repo, passwd);

    repo->passwd = g_strdup(passwd);

    pthread_mutex_lock (&manager->priv->db_lock);

    ret = save_repo_enc_info (manager, repo);

    pthread_mutex_unlock (&manager->priv->db_lock);

    return ret;
}

int
seaf_repo_manager_set_merge (SeafRepoManager *manager,
                             const char *repo_id,
                             const char *remote_head)
{
    char sql[256];

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), "REPLACE INTO MergeInfo VALUES ('%s', 1, '%s');",
              repo_id, remote_head);
    int ret = sqlite_query_exec (manager->priv->db, sql);

    pthread_mutex_unlock (&manager->priv->db_lock);
    return ret;
}

int
seaf_repo_manager_clear_merge (SeafRepoManager *manager,
                               const char *repo_id)
{
    char sql[256];

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), "UPDATE MergeInfo SET in_merge=0 WHERE repo_id='%s';",
              repo_id);
    int ret = sqlite_query_exec (manager->priv->db, sql);

    pthread_mutex_unlock (&manager->priv->db_lock);
    return ret;
}

static gboolean
get_merge_info (sqlite3_stmt *stmt, void *vinfo)
{
    SeafRepoMergeInfo *info = vinfo;
    int in_merge;

    in_merge = sqlite3_column_int (stmt, 1);
    if (in_merge == 0)
        info->in_merge = FALSE;
    else
        info->in_merge = TRUE;

    /* 
     * Note that compatibility, we store remote_head in the "branch" column.
     */
    const char *remote_head = (const char *) sqlite3_column_text (stmt, 2);
    memcpy (info->remote_head, remote_head, 40);

    return FALSE;
}

int
seaf_repo_manager_get_merge_info (SeafRepoManager *manager,
                                  const char *repo_id,
                                  SeafRepoMergeInfo *info)
{
    char sql[256];

    /* Default not in_merge, if no row is found in db. */
    info->in_merge = FALSE;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), "SELECT * FROM MergeInfo WHERE repo_id='%s';",
              repo_id);
    if (sqlite_foreach_selected_row (manager->priv->db, sql,
                                     get_merge_info, info) < 0) {
        pthread_mutex_unlock (&manager->priv->db_lock);
        return -1;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    return 0;
}

GList*
seaf_repo_manager_get_repo_list (SeafRepoManager *manager, int start, int limit)
{
    GList *repo_list = NULL;
    avl_node_t *node, *tail;
    SeafRepo *repo;

    if (pthread_rwlock_rdlock (&manager->priv->lock) < 0) {
        g_warning ("[repo mgr] failed to lock repo cache.\n");
        return NULL;
    }

    node = manager->priv->repo_tree->head;
    tail = manager->priv->repo_tree->tail;
    if (!tail) {
        pthread_rwlock_unlock (&manager->priv->lock);
        return NULL;
    }

    for (;;) {
        repo = node->item;
        if (!repo->delete_pending)
            repo_list = g_list_prepend (repo_list, node->item);
        if (node == tail)
            break;
        node = node->next;
    }

    pthread_rwlock_unlock (&manager->priv->lock);

    return repo_list;
}

typedef struct {
    SeafRepo                *repo;
    CheckoutTask            *task;
    CheckoutDoneCallback     done_cb;
    void                    *cb_data;
} CheckoutData;

static void
checkout_job_done (void *vresult)
{
    if (!vresult)
        return;
    CheckoutData *cdata = vresult;
    SeafRepo *repo = cdata->repo;
    SeafBranch *local = NULL;

    if (!cdata->task->success)
        goto out;

    seaf_repo_manager_set_repo_worktree (repo->manager,
                                         repo,
                                         cdata->task->worktree);

    local = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "local");
    if (!local) {
        seaf_warning ("Cannot get branch local for repo %s(%.10s).\n",
                      repo->name, repo->id);
        return;
    }
    /* Set repo head to mark checkout done. */
    seaf_repo_set_head (repo, local);
    seaf_branch_unref (local);

    if (repo->auto_sync) {
        if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id) < 0) {
            seaf_warning ("failed to watch repo %s(%.10s).\n", repo->name, repo->id);
            return;
        }
    }

out:
    if (cdata->done_cb)
        cdata->done_cb (cdata->task, cdata->repo, cdata->cb_data);

    /* g_hash_table_remove (mgr->priv->checkout_tasks_hash, cdata->repo->id); */
}

static void *
checkout_repo_job (void *data)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    CheckoutData *cdata = data;
    SeafRepo *repo = cdata->repo;
    CheckoutTask *task;

    task = g_hash_table_lookup (mgr->priv->checkout_tasks_hash, repo->id);
    if (!task) {
        seaf_warning ("Failed to find checkout task for repo %.10s\n", repo->id);
        return NULL;
    }

    pthread_mutex_lock (&repo->lock);

    repo->worktree = g_strdup (task->worktree);

    char *error_msg = NULL;
    if (seaf_repo_checkout (repo, task->worktree, &error_msg) < 0) {
        seaf_warning ("Failed to checkout repo %.10s to %s : %s\n",
                      repo->id, task->worktree, error_msg);
        g_free (error_msg);
        task->success = FALSE;
        goto ret;
    }
    task->success = TRUE;

ret:
    pthread_mutex_unlock (&repo->lock);
    return data;
}

int
seaf_repo_manager_add_checkout_task (SeafRepoManager *mgr,
                                     SeafRepo *repo,
                                     const char *worktree,
                                     CheckoutDoneCallback done_cb,
                                     void *cb_data)
{
    if (!repo || !worktree) {
        seaf_warning ("Invaid args\n");
        return -1;
    }

    CheckoutTask *task = g_new0 (CheckoutTask, 1);
    memcpy (task->repo_id, repo->id, 41);
    g_return_val_if_fail (strlen(worktree) < SEAF_PATH_MAX, -1);
    strcpy (task->worktree, worktree);

    g_hash_table_insert (mgr->priv->checkout_tasks_hash,
                         g_strdup(repo->id), task);

    CheckoutData *cdata = g_new0 (CheckoutData, 1);
    cdata->repo = repo;
    cdata->task = task;
    cdata->done_cb = done_cb;
    cdata->cb_data = cb_data;
    ccnet_job_manager_schedule_job(seaf->job_mgr,
                                   (JobThreadFunc)checkout_repo_job,
                                   (JobDoneCallback)checkout_job_done,
                                   cdata);
    return 0;
}

CheckoutTask *
seaf_repo_manager_get_checkout_task (SeafRepoManager *mgr,
                                     const char *repo_id)
{
    if (!repo_id || strlen(repo_id) != 36) {
        seaf_warning ("Invalid args\n");
        return NULL;
    }

    return g_hash_table_lookup(mgr->priv->checkout_tasks_hash, repo_id);
}

int
seaf_repo_manager_set_repo_email (SeafRepoManager *mgr,
                                  SeafRepo *repo,
                                  const char *email)
{
    g_free (repo->email);
    repo->email = g_strdup(email);

    save_repo_property (mgr, repo->id, REPO_PROP_EMAIL, email);
    return 0;
}

int
seaf_repo_manager_set_repo_token (SeafRepoManager *manager, 
                                  SeafRepo *repo,
                                  const char *token)
{
    g_free (repo->token);
    repo->token = g_strdup(token);

    save_repo_property (manager, repo->id, REPO_PROP_TOKEN, token);
    return 0;
}

int
seaf_repo_manager_set_repo_relay_info (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *relay_addr,
                                       const char *relay_port)
{
    save_repo_property (mgr, repo_id, REPO_PROP_RELAY_ADDR, relay_addr);
    save_repo_property (mgr, repo_id, REPO_PROP_RELAY_PORT, relay_port);
    return 0;
}

void
seaf_repo_manager_get_repo_relay_info (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       char **relay_addr,
                                       char **relay_port)
{
    char *addr, *port;

    addr = load_repo_property (mgr, repo_id, REPO_PROP_RELAY_ADDR);
    port = load_repo_property (mgr, repo_id, REPO_PROP_RELAY_PORT);

    if (relay_addr && addr)
        *relay_addr = addr;
    if (relay_port && port)
        *relay_port = port;
}

int
seaf_repo_manager_update_repo_relay_info (SeafRepoManager *mgr,
                                          SeafRepo *repo,
                                          const char *new_addr,
                                          const char *new_port)
{
    GList *ptr, *repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, 0, -1);
    SeafRepo *r;
    for (ptr = repos; ptr; ptr = ptr->next) {
        r = ptr->data;
        if (g_strcmp0(r->relay_id, repo->relay_id) != 0)
            continue;
                
        char *relay_addr = NULL;
        char *relay_port = NULL;
        seaf_repo_manager_get_repo_relay_info (seaf->repo_mgr, r->id, 
                                               &relay_addr, &relay_port);
        if (g_strcmp0(relay_addr, new_addr) != 0 ||
            g_strcmp0(relay_port, new_port) != 0) {
            seaf_repo_manager_set_repo_relay_info (seaf->repo_mgr, r->id,
                                                   new_addr, new_port);
        }

        g_free (relay_addr);
        g_free (relay_port);
    }

    g_list_free (repos);

    return 0;
}

/*
 * Read ignored files from ignore.txt
 */
GList *seaf_repo_load_ignore_files (const char *worktree)
{
    GList *list = NULL;
    SeafStat st;
    FILE *fp;
    char *full_path, *pattern;
    char path[PATH_MAX];

    full_path = g_build_path (PATH_SEPERATOR, worktree,
                              IGNORE_FILE, NULL);
    if (g_access (full_path, F_OK) < 0)
        goto error;
    if (seaf_stat (full_path, &st) < 0)
        goto error;
    if (!S_ISREG(st.st_mode))
        goto error;
    fp = g_fopen(full_path, "r");
    if (fp == NULL)
        goto error;

    while (fgets(path, PATH_MAX, fp) != NULL) {
        /* remove leading and trailing whitespace, including \n \r. */
        g_strstrip (path);

        /* ignore comment and blank line */
        if (path[0] == '#' || path[0] == '\0')
            continue;

        /* Change 'foo/' to 'foo/ *'. */
        if (path[strlen(path)-1] == '/')
            pattern = g_strdup_printf("%s/%s*", worktree, path);
        else
            pattern = g_strdup_printf("%s/%s", worktree, path);

        list = g_list_prepend(list, pattern);
    }

    fclose(fp);
    g_free (full_path);
    return list;

error:
    g_free (full_path);
    return NULL;
}

gboolean
seaf_repo_check_ignore_file (GList *ignore_list, const char *fullpath)
{
    char *str;
    SeafStat st;
    GPatternSpec *ignore_spec;
    GList *p;

    str = g_strdup(fullpath);

    /* first check the path is a reg file or a dir */
    if (seaf_stat(str, &st) < 0) {
        g_free(str);
        return TRUE;
    }
    if (S_ISDIR(st.st_mode)) {
        g_free(str);
        str = g_strconcat (fullpath, "/", NULL);
    }

    for (p = ignore_list; p != NULL; p = p->next) {
        char *pattern = (char *)p->data;

        ignore_spec = g_pattern_spec_new(pattern);
        if (g_pattern_match_string(ignore_spec, str)) {
            g_free (str);
            g_pattern_spec_free(ignore_spec);
            return TRUE;
        }
        g_pattern_spec_free(ignore_spec);
    }

    g_free (str);
    return FALSE;
}

/*
 * Free ignored file list
 */
void seaf_repo_free_ignore_files (GList *ignore_list)
{
    GList *p;

    if (ignore_list == NULL)
        return;

    for (p = ignore_list; p != NULL; p = p->next)
        free(p->data);

    g_list_free (ignore_list);
}
