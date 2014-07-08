/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <glib/gstdio.h>

#ifdef WIN32
#include <windows.h>
#endif

#include <ccnet.h>
#include "utils.h"
#include "avl/avl.h"
#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
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
        return FALSE;
    }

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

SeafCommit *
seaf_repo_get_head_commit (const char *repo_id)
{
    SeafRepo *repo;
    SeafCommit *head;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", repo_id);
        return NULL;
    }

    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo_id, repo->version,
                                           repo->head->commit_id);
    if (!head) {
        seaf_warning ("Failed to get head for repo %s.\n", repo_id);
        return NULL;
    }

    return head;
}

void
seaf_repo_from_commit (SeafRepo *repo, SeafCommit *commit)
{
    repo->name = g_strdup (commit->repo_name);
    repo->desc = g_strdup (commit->repo_desc);
    repo->encrypted = commit->encrypted;
    if (repo->encrypted) {
        repo->enc_version = commit->enc_version;
        if (repo->enc_version == 1)
            memcpy (repo->magic, commit->magic, 32);
        else if (repo->enc_version == 2) {
            memcpy (repo->magic, commit->magic, 64);
            memcpy (repo->random_key, commit->random_key, 96);
        }
    }
    repo->no_local_history = commit->no_local_history;
    repo->version = commit->version;
}

void
seaf_repo_to_commit (SeafRepo *repo, SeafCommit *commit)
{
    commit->repo_name = g_strdup (repo->name);
    commit->repo_desc = g_strdup (repo->desc);
    commit->encrypted = repo->encrypted;
    if (commit->encrypted) {
        commit->enc_version = repo->enc_version;
        if (commit->enc_version == 1)
            commit->magic = g_strdup (repo->magic);
        else if (commit->enc_version == 2) {
            commit->magic = g_strdup (repo->magic);
            commit->random_key = g_strdup (repo->random_key);
        }
    }
    commit->no_local_history = repo->no_local_history;
    commit->version = repo->version;
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
                                                                 repo->id,
                                                                 repo->version,
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

    if (!g_utf8_validate (filename, -1, NULL)) {
        seaf_warning ("File name %s contains non-UTF8 characters, skip.\n", filename);
        return TRUE;
    }

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

    if (basepath) {
        char *fullpath = g_build_path ("/", basepath, filename, NULL);
        if (seaf_repo_check_ignore_file (ignore_list, fullpath)) {
            g_free (fullpath);
            return TRUE;
        }
        g_free (fullpath);
    }

    return FALSE;
}

static int
index_cb (const char *repo_id,
          int version,
          const char *path,
          unsigned char sha1[],
          SeafileCrypt *crypt,
          gboolean write_data)
{
    gint64 size;

    /* Check in blocks and get object ID. */
    if (seaf_fs_manager_index_blocks (seaf->fs_mgr, repo_id, version,
                                      path, sha1, &size, crypt, write_data) < 0) {
        g_warning ("Failed to index file %s.\n", path);
        return -1;
    }
    return 0;
}

#define MAX_COMMIT_SIZE 100 * (1 << 20) /* 100MB */

/*
 * @remain_files: returns the files haven't been added under this path.
 *                If it's set to NULL, no partial commit will be created.
 */
static int
add_recursive (const char *repo_id,
               int version,
               const char *modifier,
               struct index_state *istate, 
               const char *worktree,
               const char *path,
               SeafileCrypt *crypt,
               gboolean ignore_empty_dir,
               GList *ignore_list,
               gint64 *total_size,
               GQueue **remain_files)
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
        gboolean added = FALSE;
        if (!remain_files) {
            ret = add_to_index (repo_id, version, istate, path, full_path,
                                &st, 0, crypt, index_cb, modifier, &added);
        } else if (*remain_files == NULL) {
            ret = add_to_index (repo_id, version, istate, path, full_path,
                                &st, 0, crypt, index_cb, modifier, &added);
            if (added) {
                *total_size += (gint64)(st.st_size);
                if (*total_size >= MAX_COMMIT_SIZE)
                    *remain_files = g_queue_new ();
            }
        } else
            g_queue_push_tail (*remain_files, g_strdup(path));

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
            ret = add_recursive (repo_id, version, modifier,
                                 istate, worktree, subpath,
                                 crypt, ignore_empty_dir, ignore_list,
                                 total_size, remain_files);
            g_free (subpath);
            if (ret < 0)
                break;
        }
        g_dir_close (dir);
        if (ret < 0)
            goto bad;

        if (n == 0 && path[0] != 0 && !ignore_empty_dir) {
            if (!remain_files || *remain_files == NULL)
                add_empty_dir_to_index (istate, path, &st);
            else
                g_queue_push_tail (*remain_files, g_strdup(path));
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
    gboolean ret = TRUE;

    dir = g_dir_open (path, 0, NULL);
    if (!dir) {
        return FALSE;
    }

    while ((dname = g_dir_read_name(dir)) != NULL) {
        if (!should_ignore(path, dname, ignore_list)) {
            ret = FALSE;
            break;
        }
    }
    g_dir_close (dir);

    return ret;
}

static void
remove_deleted (struct index_state *istate, const char *worktree,
                GList *ignore_list)
{
    struct cache_entry **ce_array = istate->cache;
    struct cache_entry *ce;
    char path[SEAF_PATH_MAX];
    unsigned int i;
    SeafStat st;
    int ret;

    for (i = 0; i < istate->cache_nr; ++i) {
        ce = ce_array[i];
        snprintf (path, SEAF_PATH_MAX, "%s/%s", worktree, ce->name);
        ret = seaf_stat (path, &st);

        if (S_ISDIR (ce->ce_mode)) {
            if ((ret < 0 || !S_ISDIR (st.st_mode)
                 || !is_empty_dir (path, ignore_list)) &&
                (ce->ce_ctime.sec != 0 || ce_stage(ce) != 0))
                ce->ce_flags |= CE_REMOVE;
        } else {
            /* If ce->ctime is 0 and stage is 0, it was not successfully checked out.
             * In this case we don't want to mistakenly remove the file
             * from the repo.
             */
            if ((ret < 0 || !S_ISREG (st.st_mode)) &&
                (ce->ce_ctime.sec != 0 || ce_stage(ce) != 0))
                ce_array[i]->ce_flags |= CE_REMOVE;
        }
    }

    remove_marked_cache_entries (istate);
}

static int
scan_worktree_for_changes (struct index_state *istate, SeafRepo *repo,
                           SeafileCrypt *crypt, GList *ignore_list)
{
    if (add_recursive (repo->id, repo->version, repo->email,
                       istate, repo->worktree, "", crypt, FALSE, ignore_list,
                       NULL, NULL) < 0)
        return -1;

    remove_deleted (istate, repo->worktree, ignore_list);

    return 0;
}

static gboolean
check_full_path_ignore (const char *worktree, const char *path, GList *ignore_list)
{
    char **tokens;
    guint i;
    guint n;
    gboolean ret = FALSE;

    tokens = g_strsplit (path, "/", 0);
    n = g_strv_length (tokens);
    for (i = 0; i < n; ++i) {
        /* don't check ignore_list */
        if (should_ignore (NULL, tokens[i], ignore_list)) {
            ret = TRUE;
            goto out;
        }
    }

    char *full_path = g_build_path ("/", worktree, path, NULL);
    if (seaf_repo_check_ignore_file (ignore_list, full_path))
        ret = TRUE;
    g_free (full_path);

out:
    g_strfreev (tokens);
    return ret;
}

static int
add_path_to_index (SeafRepo *repo, struct index_state *istate,
                   SeafileCrypt *crypt, const char *path, GList *ignore_list,
                   GList **scanned_dirs, gint64 *total_size, GQueue **remain_files)
{
    char *full_path;
    SeafStat st;

    /* When a repo is initially added, a CREATE_OR_UPDATE event will be created
     * for the worktree root "".
     */
    if (path[0] == 0) {
        add_recursive (repo->id, repo->version, repo->email, istate,
                       repo->worktree, path,
                       crypt, FALSE, ignore_list,
                       total_size, remain_files);
        return 0;
    }

    /* If we've recursively scanned the parent directory, don't need to scan
     * any files under it any more.
     */
    GList *ptr;
    char *dir, *full_dir;
    for (ptr = *scanned_dirs; ptr; ptr = ptr->next) {
        dir = ptr->data;
        /* exact match */
        if (strcmp (dir, path) == 0) {
            seaf_debug ("%s has been scanned before, skip adding.\n", path);
            return 0;
        }

        /* prefix match. */
        full_dir = g_strconcat (dir, "/", NULL);
        if (strncmp (full_dir, path, strlen(full_dir)) == 0) {
            g_free (full_dir);
            seaf_debug ("%s has been scanned before, skip adding.\n", path);
            return 0;
        }
        g_free (full_dir);
    }

    if (check_full_path_ignore (repo->worktree, path, ignore_list))
        return 0;

    full_path = g_build_filename (repo->worktree, path, NULL);

    if (seaf_stat (full_path, &st) < 0) {
        seaf_warning ("Failed to stat %s: %s.\n", path, strerror(errno));
        g_free (full_path);
        return -1;
    }

    if (S_ISDIR(st.st_mode))
        *scanned_dirs = g_list_prepend (*scanned_dirs, g_strdup(path));

    /* Add is always recursive */
    add_recursive (repo->id, repo->version, repo->email, istate, repo->worktree, path,
                   crypt, FALSE, ignore_list, total_size, remain_files);

    g_free (full_path);
    return 0;
}

static int
add_remain_files (SeafRepo *repo, struct index_state *istate,
                  SeafileCrypt *crypt, GQueue *remain_files,
                  GList *ignore_list, gint64 *total_size)
{
    char *path;
    char *full_path;
    SeafStat st;

    while ((path = g_queue_pop_head (remain_files)) != NULL) {
        full_path = g_build_filename (repo->worktree, path, NULL);
        if (seaf_stat (full_path, &st) < 0) {
            seaf_warning ("Failed to stat %s: %s.\n", full_path, strerror(errno));
            g_free (path);
            g_free (full_path);
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            gboolean added = FALSE;
            add_to_index (repo->id, repo->version, istate, path, full_path,
                          &st, 0, crypt, index_cb, repo->email, &added);
            if (added) {
                *total_size += (gint64)(st.st_size);
                if (*total_size >= MAX_COMMIT_SIZE) {
                    g_free (path);
                    g_free (full_path);
                    break;
                }
            }
        } else if (S_ISDIR(st.st_mode)) {
            if (is_empty_dir (full_path, ignore_list))
                add_empty_dir_to_index (istate, path, &st);
        }
        g_free (path);
        g_free (full_path);
    }

    return 0;
}

static void
try_add_empty_parent_dir_entry (const char *worktree, struct index_state *istate,
                                GList *ignore_list, const char *path)
{
    if (index_name_exists (istate, path, strlen(path), 0) != NULL)
        return;

    char *parent_dir = g_path_get_dirname (path);

    /* Parent dir is the worktree dir. */
    if (strcmp (parent_dir, ".") == 0) {
        g_free (parent_dir);
        return;
    }

    char *full_dir = g_build_filename (worktree, parent_dir, NULL);
    SeafStat st;
    if (seaf_stat (full_dir, &st) < 0) {
        goto out;
    }

    if (is_empty_dir (full_dir, ignore_list))
        add_empty_dir_to_index (istate, parent_dir, &st);

out:
    g_free (parent_dir);
    g_free (full_dir);
}

static int
apply_worktree_changes_to_index (SeafRepo *repo, struct index_state *istate,
                                 SeafileCrypt *crypt, GList *ignore_list)
{
    WTStatus *status;
    WTEvent *event;

    status = seaf_wt_monitor_get_worktree_status (seaf->wt_monitor, repo->id);
    if (!status) {
        seaf_warning ("Can't find worktree status for repo %s(%.8s).\n",
                      repo->name, repo->id);
        return -1;
    }

    GList *scanned_dirs = NULL;

    WTEvent *last_event;
    if (repo->create_partial_commit && status->last_event != NULL)
        last_event = status->last_event;
    else {
        if (!repo->create_partial_commit)
            status->last_event = NULL;

        pthread_mutex_lock (&status->q_lock);
        last_event = g_queue_peek_tail (status->event_q);
        pthread_mutex_unlock (&status->q_lock);
    }
    if (!last_event)
        goto out;

    gint64 total_size = 0;

    while (1) {
        pthread_mutex_lock (&status->q_lock);
        event = g_queue_pop_head (status->event_q);
        pthread_mutex_unlock (&status->q_lock);
        if (!event)
            break;

        switch (event->ev_type) {
        case WT_EVENT_CREATE_OR_UPDATE:
            if (!repo->create_partial_commit) {
                add_path_to_index (repo, istate, crypt, event->path,
                                   ignore_list, &scanned_dirs,
                                   &total_size, NULL);
            } else if (!event->remain_files) {
                GQueue *remain_files = NULL;
                add_path_to_index (repo, istate, crypt, event->path,
                                   ignore_list, &scanned_dirs,
                                   &total_size, &remain_files);
                if (remain_files) {
                    /* Cache remaining files in the event structure. */
                    event->remain_files = remain_files;

                    pthread_mutex_lock (&status->q_lock);
                    g_queue_push_head (status->event_q, event);
                    pthread_mutex_unlock (&status->q_lock);

                    /* Set status->last_event to signify partial commit. */
                    status->last_event = last_event;
                    goto out;
                }
            } else {
                add_remain_files (repo, istate, crypt, event->remain_files,
                                  ignore_list, &total_size);
                if (g_queue_get_length (event->remain_files) != 0) {
                    pthread_mutex_lock (&status->q_lock);
                    g_queue_push_head (status->event_q, event);
                    pthread_mutex_unlock (&status->q_lock);
                    goto out;
                }
            }
            break;
        case WT_EVENT_DELETE:
            remove_from_index_with_prefix (istate, event->path);
            try_add_empty_parent_dir_entry (repo->worktree, istate,
                                            ignore_list, event->path);
            break;
        case WT_EVENT_RENAME:
            /* If the destination path is ignored, just remove the source path. */
            if (check_full_path_ignore (repo->worktree, event->new_path,
                                        ignore_list)) {
                remove_from_index_with_prefix (istate, event->path);
                break;
            }

            rename_index_entries (istate, event->path, event->new_path);

            /* Moving files out of a dir may make it empty. */
            try_add_empty_parent_dir_entry (repo->worktree, istate,
                                            ignore_list, event->path);

            /* We should always scan the destination to compare with the renamed
             * index entries. For example, in the following case:
             * 1. file a.txt is updated;
             * 2. a.txt is moved to test/a.txt;
             * If the two operations are executed in a batch, the updated content
             * of a.txt won't be committed if we don't scan the destination, because
             * when we process the update event, a.txt is already not in its original
             * place.
             */
            add_recursive (repo->id, repo->version, repo->email,
                           istate, repo->worktree, event->new_path,
                           crypt, FALSE, ignore_list,
                           NULL, NULL);
            break;
        case WT_EVENT_OVERFLOW:
            seaf_warning ("Kernel event queue overflowed, fall back to scan.\n");
            scan_worktree_for_changes (istate, repo, crypt, ignore_list);
            break;
        }

        if (event == last_event) {
            wt_event_free (event);
            if (status->last_event != NULL)
                status->last_event = NULL;
            break;
        } else
            wt_event_free (event);
    }

out:
    wt_status_unref (status);
    string_list_free (scanned_dirs);

    return 0;
}

static void
handle_unmerged_index_entries (SeafRepo *repo, struct index_state *istate,
                               SeafileCrypt *crypt, GList *ignore_list)
{
    struct cache_entry **ce_array = istate->cache;
    struct cache_entry *ce;
    char path[SEAF_PATH_MAX];
    unsigned int i;
    SeafStat st;
    int ret;
    GList *unmerged_paths = NULL;
    char *last_name = "";

retry:
    for (i = 0; i < istate->cache_nr; ++i) {
        ce = ce_array[i];

        if (ce_stage(ce) == 0)
            continue;

        snprintf (path, SEAF_PATH_MAX, "%s/%s", repo->worktree, ce->name);
        ret = seaf_stat (path, &st);

        if (S_ISDIR (ce->ce_mode)) {
            if (ret < 0 || !S_ISDIR (st.st_mode)
                || !is_empty_dir (path, ignore_list))
                ce->ce_flags |= CE_REMOVE;
            else if (strcmp (ce->name, last_name) != 0) {
                unmerged_paths = g_list_append (unmerged_paths, g_strdup(ce->name));
                last_name = ce->name;
            }
        } else {
            if (ret < 0 || !S_ISREG (st.st_mode))
                ce->ce_flags |= CE_REMOVE;
            else if (strcmp (ce->name, last_name) != 0) {
                unmerged_paths = g_list_append (unmerged_paths, g_strdup(ce->name));
                last_name = ce->name;
            }
        }
    }

    remove_marked_cache_entries (istate);

    GList *ptr;
    char *ce_name;
    for (ptr = unmerged_paths; ptr; ptr = ptr->next) {
        ce_name = ptr->data;
        snprintf (path, SEAF_PATH_MAX, "%s/%s", repo->worktree, ce_name);
        ret = seaf_stat (path, &st);
        if (ret < 0) {
            seaf_warning ("Failed to stat %s: %s.\n", path, strerror(errno));
            string_list_free (unmerged_paths);
            unmerged_paths = NULL;
            goto retry;
        }

        if (S_ISDIR (st.st_mode)) {
            if (is_empty_dir (path, ignore_list))
                add_empty_dir_to_index (istate, ce_name, &st);
        } else {
            gboolean added;
            add_to_index (repo->id, repo->version, istate, ce_name, path,
                          &st, 0, crypt, index_cb, repo->email, &added);
        }
    }

    string_list_free (unmerged_paths);
}

static int
index_add (SeafRepo *repo, struct index_state *istate,
           gboolean is_initial_commit, gboolean handle_unmerged)
{
    SeafileCrypt *crypt = NULL;
    GList *ignore_list = NULL;
    int ret = 0;

    if (repo->encrypted) {
        crypt = seafile_crypt_new (repo->enc_version, repo->enc_key, repo->enc_iv);
    }

    ignore_list = seaf_repo_load_ignore_files (repo->worktree);

    /* If this is the first commit after the client restarts, remove deleted files
     * from the index. Since the client doesn't know which files are deleted when
     * it was shutdown, the only way is to compare the index with worktree.
     */
    if (is_initial_commit)
        remove_deleted (istate, repo->worktree, ignore_list);

    if (apply_worktree_changes_to_index (repo, istate, crypt, ignore_list) < 0) {
        seaf_warning ("Failed to apply worktree changes to index.\n");
        ret = -1;
    }

    /* If the index contains unmerged entries, check and remove those entries
     * in the end, in cases where they were not completely handled in
     * apply_worktree_changes_to_index().
     */
    if (handle_unmerged)
        handle_unmerged_index_entries (repo, istate, crypt, ignore_list);

    seaf_repo_free_ignore_files (ignore_list);
    g_free (crypt);
    return ret;
}

/*
 * Add the files in @worktree to index and return the corresponding
 * @root_id. The repo doesn't have to exist.
 */
int
seaf_repo_index_worktree_files (const char *repo_id,
                                int repo_version,
                                const char *modifier,
                                const char *worktree,
                                const char *passwd,
                                int enc_version,
                                const char *random_key,
                                char *root_id)
{
    char index_path[SEAF_PATH_MAX];
    struct index_state istate;
    unsigned char key[32], iv[16];
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

    if (read_index_from (&istate, index_path, repo_version) < 0) {
        g_warning ("Failed to load index.\n");
        return -1;
    }

    if (passwd != NULL) {
        if (seafile_decrypt_repo_enc_key (enc_version, passwd,
                                          random_key, key, iv) < 0) {
            seaf_warning ("Failed to generate enc key for repo %s.\n", repo_id);
            goto error;
        }
        crypt = seafile_crypt_new (enc_version, key, iv);
    }

    ignore_list = seaf_repo_load_ignore_files(worktree);

    /* Add empty dir to index. Otherwise if the repo on relay contains an empty
     * dir, we'll fail to detect fast-forward relationship later.
     */
    if (add_recursive (repo_id, repo_version, modifier,
                       &istate, worktree, "", crypt, FALSE, ignore_list,
                       NULL, NULL) < 0)
        goto error;

    remove_deleted (&istate, worktree, ignore_list);

    it = cache_tree ();
    if (cache_tree_update (repo_id, repo_version, worktree,
                           it, istate.cache, istate.cache_nr,
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
    if (read_index_from (&istate, index_path, repo->version) < 0) {
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
                   "ce mtime: %"G_GINT64_FORMAT", ce size: %" G_GUINT64_FORMAT ", "
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

    desc = diff_results_to_description (results);
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
    if (read_index_from (&istate, index_path, repo->version) < 0) {
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

    commit = seaf_commit_new (NULL, repo->id, root_id,
                              repo->email ? repo->email
                              : seaf->session->base.user_name,
                              seaf->session->base.id,
                              desc, 0);

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
        commit->new_merge = TRUE;
        commit->conflict = TRUE;
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

static gboolean
need_handle_unmerged_index (SeafRepo *repo, struct index_state *istate)
{
    if (!unmerged_index (istate))
        return FALSE;

    /* Syncing with an existing directory may require a real merge.
     * If the merge produced conflicts, the index will be unmerged.
     * But we don't want to generate a merge commit in this case.
     * An "index" branch should exist in this case.
     */
    if (seaf_branch_manager_branch_exists (seaf->branch_mgr, repo->id, "index"))
        return FALSE;

    return TRUE;
}

#if 0
static int 
print_index (struct index_state *istate)
{
    int i;
    struct cache_entry *ce;
    char id[41];
    seaf_message ("Totally %u entries in index, version %u.\n",
                  istate->cache_nr, istate->version);
    for (i = 0; i < istate->cache_nr; ++i) {
        ce = istate->cache[i];
        rawdata_to_hex (ce->sha1, id, 20);
        seaf_message ("%s, %s, %o, %"G_GINT64_FORMAT", %s, %"G_GINT64_FORMAT", %d\n",
                      ce->name, id, ce->ce_mode, 
                      ce->ce_mtime.sec, ce->modifier, ce->ce_size, ce_stage(ce));
    }

    return 0;
}
#endif

char *
seaf_repo_index_commit (SeafRepo *repo, const char *desc, gboolean is_initial_commit,
                        GError **error)
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
    if (read_index_from (&istate, index_path, repo->version) < 0) {
        g_warning ("Failed to load index.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Internal data structure error");
        return NULL;
    }

    if (need_handle_unmerged_index (repo, &istate))
        unmerged = TRUE;

    if (index_add (repo, &istate, is_initial_commit, unmerged) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Failed to add");
        goto error;
    }

    /* Commit before updating the index, so that new blocks won't be GC'ed. */

    char *my_desc = g_strdup(desc);
    if (my_desc[0] == '\0') {
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
    if (cache_tree_update (repo->id, repo->version,
                           repo->worktree,
                           it, istate.cache,
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
    if (read_index_from (&istate, index_path, repo->version) < 0) {
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
                                            repo->id, repo->version,
                                            repo->head->commit_id);
        if (!head) {
            seaf_warning ("Failed to get commit %s.\n", repo->head->commit_id);
            discard_index (&istate);
            return -1;
        }
        fill_tree_descriptor (repo->id, repo->version, &trees[0], head->root_id);
        seaf_commit_unref (head);
    } else {
        fill_tree_descriptor (repo->id, repo->version, &trees[0], NULL);
    }
    fill_tree_descriptor (repo->id, repo->version, &trees[1], commit->root_id);

    /* 2-way merge to the new branch */
    memset(&topts, 0, sizeof(topts));
    memcpy (topts.repo_id, repo->id, 36);
    topts.version = repo->version;
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
        
    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->id,
                                             repo->version,
                                             commit_id);
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
    task->total_files = seaf_fs_manager_count_fs_files (seaf->fs_mgr,
                                                        repo->id, repo->version,
                                                        commit->root_id);

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
                 int *merge_status)
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

    ret = merge_branches (repo, remote_branch, error, merge_status);
    seaf_branch_unref (remote_branch);

    return ret;

error:
    return -1;
}

int
checkout_file (const char *repo_id,
               int repo_version,
               const char *worktree,
               const char *name,
               const char *file_id,
               gint64 mtime,
               unsigned int mode,
               SeafileCrypt *crypt,
               struct cache_entry *ce,
               TransferTask *task,
               const char *conflict_head_id,
               GHashTable *conflict_hash,
               GHashTable *no_conflict_hash)
{
    char *path;
    SeafStat st, st2;
    unsigned char sha1[20];
    gboolean path_exists = FALSE;
    gboolean case_conflict = FALSE;
    gboolean force_conflict = FALSE;

#ifndef __linux__
    path = build_case_conflict_free_path (worktree, name,
                                          conflict_hash, no_conflict_hash,
                                          &case_conflict);
#else
    path = build_checkout_path (worktree, name, strlen(name));
#endif

    if (!path)
        return FETCH_CHECKOUT_FAILED;

    hex_to_rawdata (file_id, sha1, 20);

    path_exists = (seaf_stat (path, &st) == 0);

    if (path_exists && S_ISREG(st.st_mode)) {
        if (st.st_mtime == ce->ce_mtime.sec) {
            /* Worktree and index are consistent. */
            if (memcmp (sha1, ce->sha1, 20) == 0) {
                /* Worktree and index are all uptodate, no need to checkout.
                 * This may happen after an interrupted checkout.
                 */
                seaf_debug ("wt and index are consistent. no need to checkout.\n");
                g_free (path);
                return FETCH_CHECKOUT_SUCCESS;
            }
            /* otherwise we have to checkout the file. */
        } else {
            if (compare_file_content (path, &st, sha1, crypt, repo_version) == 0) {
                /* This happens after the worktree file was updated,
                 * but the index was not. Just need to update the index.
                 */
                seaf_debug ("update index only.\n");
                goto update_cache;
            } else {
                /* Conflict. The worktree file was updated by the user. */
                seaf_debug ("File is updated. Conflict.\n");
                force_conflict = TRUE;
            }
        }
    }

    /* Download the blocks of this file. */
    int rc = seaf_transfer_manager_download_file_blocks (seaf->transfer_mgr,
                                                         task, file_id);
    switch (rc) {
    case BLOCK_CLIENT_SUCCESS:
        break;
    case BLOCK_CLIENT_UNKNOWN:
    case BLOCK_CLIENT_FAILED:
    case BLOCK_CLIENT_NET_ERROR:
    case BLOCK_CLIENT_SERVER_ERROR:
        g_free (path);
        return FETCH_CHECKOUT_FAILED;
    case BLOCK_CLIENT_CANCELED:
        g_free (path);
        return FETCH_CHECKOUT_CANCELED;
    }

    /* The worktree file may have been changed when we're downloading the blocks. */
    if (path_exists && S_ISREG(st.st_mode) && !force_conflict) {
        seaf_stat (path, &st2);
        if (st.st_mtime != st2.st_mtime)
            force_conflict = TRUE;
    }

    /* then checkout the file. */
    gboolean conflicted = FALSE;
    if (seaf_fs_manager_checkout_file (seaf->fs_mgr,
                                       repo_id,
                                       repo_version,
                                       file_id,
                                       path,
                                       mode,
                                       mtime,
                                       crypt,
                                       name,
                                       conflict_head_id,
                                       force_conflict,
                                       &conflicted) < 0) {
        seaf_warning ("Failed to checkout file %s.\n", path);
        g_free (path);
        return FETCH_CHECKOUT_FAILED;
    }

    /* If case conflict, this file has been checked out to another path.
     * Remove the current entry, otherwise it won't be removed later
     * since it's timestamp is 0.
     */
    if (case_conflict) {
        ce->ce_flags |= CE_REMOVE;
        g_free (path);
        return FETCH_CHECKOUT_SUCCESS;
    }

    if (conflicted) {
        g_free (path);
        return FETCH_CHECKOUT_SUCCESS;
    }

update_cache:
    /* finally fill cache_entry info */
    /* Only update index if we checked out the file without any error
     * or conflicts. The timestamp of the entry will remain 0 if error
     * or conflicted.
     */
    seaf_stat (path, &st);
    fill_stat_cache_info (ce, &st);

    g_free (path);
    return FETCH_CHECKOUT_SUCCESS;
}

int
checkout_empty_dir (const char *worktree,
                    const char *name,
                    gint64 mtime,
                    struct cache_entry *ce,
                    GHashTable *conflict_hash,
                    GHashTable *no_conflict_hash)
{
    char *path;
    gboolean case_conflict = FALSE;

#ifndef __linux__
    path = build_case_conflict_free_path (worktree, name,
                                          conflict_hash, no_conflict_hash,
                                          &case_conflict);
#else
    path = build_checkout_path (worktree, name, strlen(name));
#endif

    if (!path)
        return FETCH_CHECKOUT_FAILED;

    if (!g_file_test (path, G_FILE_TEST_EXISTS) && g_mkdir (path, 0777) < 0) {
        g_warning ("Failed to create empty dir %s in checkout.\n", path);
        g_free (path);
        return FETCH_CHECKOUT_FAILED;
    }

    if (mtime != 0 && seaf_set_file_time (path, mtime) < 0) {
        g_warning ("Failed to set mtime for %s.\n", path);
    }

    if (case_conflict) {
        ce->ce_flags |= CE_REMOVE;
        g_free (path);
        return FETCH_CHECKOUT_SUCCESS;
    }

    SeafStat st;
    seaf_stat (path, &st);
    fill_stat_cache_info (ce, &st);

    g_free (path);
    return FETCH_CHECKOUT_SUCCESS;
}

static struct cache_entry *
cache_entry_from_diff_entry (DiffEntry *de)
{
    int size, namelen;
    struct cache_entry *ce;

    namelen = strlen(de->name);
    size = cache_entry_size(namelen);
    ce = calloc(1, size);
    memcpy(ce->name, de->name, namelen);
    ce->ce_flags = namelen;

    memcpy (ce->sha1, de->sha1, 20);
    ce->modifier = g_strdup(de->modifier);
    ce->ce_size = de->size;
    ce->ce_mtime.sec = de->mtime;

    if (S_ISREG(de->mode))
        ce->ce_mode = create_ce_mode (de->mode);
    else
        ce->ce_mode = S_IFDIR;

    return ce;
}

static void
cleanup_file_blocks (const char *repo_id, int version, const char *file_id)
{
    Seafile *file;
    int i;

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr,
                                        repo_id, version,
                                        file_id);
    for (i = 0; i < file->n_blocks; ++i)
        seaf_block_manager_remove_block (seaf->block_mgr,
                                         repo_id, version,
                                         file->blk_sha1s[i]);

    seafile_unref (file);
}

#define UPDATE_CACHE_SIZE_LIMIT 100 * (1 << 20) /* 100MB */

int
seaf_repo_fetch_and_checkout (TransferTask *task,
                              const char *remote_head_id)
{
    SeafRepo *repo = NULL;
    SeafBranch *master = NULL;
    SeafCommit *remote_head = NULL, *master_head = NULL;
    char index_path[SEAF_PATH_MAX];
    struct index_state istate;
    int ret = FETCH_CHECKOUT_SUCCESS;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s",
              seaf->repo_mgr->index_dir, task->repo_id);
    if (read_index_from (&istate, index_path, task->repo_version) < 0) {
        g_warning ("Failed to load index.\n");
        return FETCH_CHECKOUT_FAILED;
    }

    if (!task->is_clone) {
        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, task->repo_id);
        if (!repo) {
            seaf_warning ("Failed to get repo %.8s.\n", task->repo_id);
            goto out;
        }

        master = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                 task->repo_id, "master");
        if (!master) {
            seaf_warning ("Failed to get master branch for repo %.8s.\n",
                          task->repo_id);
            ret = FETCH_CHECKOUT_FAILED;
            goto out;
        }

        master_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                      task->repo_id,
                                                      task->repo_version,
                                                      master->commit_id);
        if (!master_head) {
            seaf_warning ("Failed to get master head %s of repo %.8s.\n",
                          task->repo_id, master->commit_id);
            ret = FETCH_CHECKOUT_FAILED;
            goto out;
        }
    }

    char *worktree;
    if (!task->is_clone)
        worktree = repo->worktree;
    else
        worktree = task->worktree;

    remote_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                  task->repo_id,
                                                  task->repo_version,
                                                  remote_head_id);
    if (!remote_head) {
        seaf_warning ("Failed to get remote head %s of repo %.8s.\n",
                      task->repo_id, remote_head_id);
        ret = FETCH_CHECKOUT_FAILED;
        goto out;
    }

    GList *results = NULL;
    if (diff_commit_roots (task->repo_id, task->repo_version,
                           master_head ? master_head->root_id : EMPTY_SHA1,
                           remote_head->root_id,
                           &results, FALSE) < 0) {
        seaf_warning ("Failed to diff for repo %.8s.\n", task->repo_id);
        ret = FETCH_CHECKOUT_FAILED;
        goto out;
    }

    SeafileCrypt *crypt = NULL;
    if (remote_head->encrypted) {
        if (!task->is_clone) {
            crypt = seafile_crypt_new (repo->enc_version,
                                       repo->enc_key,
                                       repo->enc_iv);
        } else {
            unsigned char enc_key[32], enc_iv[16];
            seafile_decrypt_repo_enc_key (remote_head->enc_version,
                                          task->passwd,
                                          remote_head->random_key,
                                          enc_key, enc_iv);
            crypt = seafile_crypt_new (remote_head->enc_version,
                                       enc_key, enc_iv);
        }
    }

    GHashTable *conflict_hash, *no_conflict_hash;
    conflict_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                           g_free, g_free);
    no_conflict_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                              g_free, NULL);

    GList *ignore_list = seaf_repo_load_ignore_files (worktree);

    GList *ptr;
    DiffEntry *de;
    struct cache_entry *ce;

    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;
        if (de->status == DIFF_STATUS_ADDED || de->status == DIFF_STATUS_MODIFIED)
            ++(task->n_to_download);
    }

    /* Delete/rename files before deleting dirs,
     * because we can't delete non-empty dirs.
     */
    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;
        if (de->status == DIFF_STATUS_DELETED) {
            seaf_debug ("Delete %s.\n", de->name);

            ce = index_name_exists (&istate, de->name, strlen(de->name), 0);
            if (!ce)
                continue;

            delete_path (worktree, de->name, de->mode, ce->ce_mtime.sec);

            remove_from_index_with_prefix (&istate, de->name);
            try_add_empty_parent_dir_entry (worktree, &istate, ignore_list, de->name);
        }
    }

    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;
        if (de->status == DIFF_STATUS_RENAMED) {
            seaf_debug ("Rename %s to %s.\n", de->name, de->new_name);

            char *old_path = g_build_filename (worktree, de->name, NULL);

            char *new_path;
            gboolean case_conflict;
#ifndef __linux__
            new_path = build_case_conflict_free_path (worktree, de->new_name,
                                                      conflict_hash, no_conflict_hash,
                                                      &case_conflict);
#else
            new_path = build_checkout_path (worktree, de->new_name, strlen(de->new_name));
#endif

            if (g_file_test (old_path, G_FILE_TEST_EXISTS) &&
                g_rename (old_path, new_path) < 0)
                seaf_warning ("Failed to rename %s to %s: %s.\n",
                              old_path, new_path, strerror(errno));

            g_free (old_path);
            g_free (new_path);

            rename_index_entries (&istate, de->name, de->new_name);

            /* Moving files out of a dir may make it empty. */
            try_add_empty_parent_dir_entry (worktree, &istate, ignore_list, de->name);
        }
    }

    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;
        if (de->status == DIFF_STATUS_DIR_DELETED) {
            seaf_debug ("Delete %s.\n", de->name);

            ce = index_name_exists (&istate, de->name, strlen(de->name), 0);
            if (!ce)
                continue;

            delete_path (worktree, de->name, de->mode, ce->ce_mtime.sec);

            remove_from_index_with_prefix (&istate, de->name);
            try_add_empty_parent_dir_entry (worktree, &istate, ignore_list, de->name);
        }
    }

    if (istate.cache_changed)
        update_index (&istate, index_path);

    gint64 checkout_size = 0;
    for (ptr = results; ptr; ptr = ptr->next) {
        de = ptr->data;

        if (de->status == DIFF_STATUS_ADDED ||
            de->status == DIFF_STATUS_MODIFIED) {
            seaf_debug ("Checkout file %s.\n", de->name);

            gboolean add_ce = FALSE;
            char file_id[41];

            rawdata_to_hex (de->sha1, file_id, 20);

            ce = index_name_exists (&istate, de->name, strlen(de->name), 0);
            if (!ce) {
                ce = cache_entry_from_diff_entry (de);
                add_ce = TRUE;
            }

            int rc = checkout_file (task->repo_id,
                                    task->repo_version,
                                    worktree,
                                    de->name,
                                    file_id,
                                    de->mtime,
                                    de->mode,
                                    crypt,
                                    ce,
                                    task,
                                    remote_head_id,
                                    conflict_hash,
                                    no_conflict_hash);
            /* Even if the file failed to check out, still need to update index. */
            if (rc == FETCH_CHECKOUT_CANCELED) {
                seaf_debug ("Transfer canceled.\n");
                ret = FETCH_CHECKOUT_CANCELED;
                if (add_ce)
                    cache_entry_free (ce);
                goto out;
            }

            cleanup_file_blocks (task->repo_id, task->repo_version, file_id);

            ++(task->n_downloaded);

            if (add_ce) {
                seaf_debug ("Add cache entry.\n");
                add_index_entry (&istate, ce,
                                 (ADD_CACHE_OK_TO_ADD|ADD_CACHE_OK_TO_REPLACE));
            } else {
                ce->ce_mtime.sec = de->mtime;
                ce->ce_size = de->size;
                memcpy (ce->sha1, de->sha1, 20);
                if (ce->modifier) g_free (ce->modifier);
                ce->modifier = g_strdup(de->modifier);
                ce->ce_mode = create_ce_mode (de->mode);
            }

            /* Save index file to disk after checking out some size of files.
             * This way we don't need to re-compare too many files if this
             * checkout is interrupted.
             */
            checkout_size += ce->ce_size;
            if (checkout_size >= UPDATE_CACHE_SIZE_LIMIT) {
                seaf_debug ("Save index file.\n");
                update_index (&istate, index_path);
                checkout_size = 0;
            }
        } else if (de->status == DIFF_STATUS_DIR_ADDED) {
            seaf_debug ("Checkout empty dir %s.\n", de->name);

            gboolean add_ce = FALSE;

            ce = index_name_exists (&istate, de->name, strlen(de->name), 0);
            if (!ce) {
                ce = cache_entry_from_diff_entry (de);
                add_ce = TRUE;
            }

            checkout_empty_dir (worktree,
                                de->name,
                                de->mtime,
                                ce,
                                conflict_hash,
                                no_conflict_hash);

            if (add_ce)
                add_index_entry (&istate, ce,
                                 (ADD_CACHE_OK_TO_ADD|ADD_CACHE_OK_TO_REPLACE));
            else
                ce->ce_mtime.sec = de->mtime;
        }
    }

    update_index (&istate, index_path);

out:
    discard_index (&istate);

    seaf_branch_unref (master);
    seaf_commit_unref (master_head);
    seaf_commit_unref (remote_head);

    for (ptr = results; ptr; ptr = ptr->next)
        diff_entry_free ((DiffEntry *)ptr->data);

    g_free (crypt);
    g_hash_table_destroy (conflict_hash);
    g_hash_table_destroy (no_conflict_hash);

    seaf_repo_free_ignore_files (ignore_list);

    return ret;
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
        if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree) < 0) {
            g_warning ("failed to watch repo %s.\n", repo->id);
        }
    }
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
            if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree) < 0) {
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

    snprintf (sql, sizeof(sql), "REPLACE INTO Repo VALUES ('%s');", repo->id);
    sqlite_query_exec (db, sql);

    pthread_mutex_unlock (&manager->priv->db_lock);

    /* There may be a "deletion record" for this repo when it was deleted
     * last time.
     */
    seaf_repo_manager_remove_garbage_repo (manager, repo->id);

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

static gboolean
get_garbage_repo_id (sqlite3_stmt *stmt, void *vid_list)
{
    GList **ret = vid_list;
    char *repo_id;

    repo_id = g_strdup((const char *)sqlite3_column_text (stmt, 0));
    *ret = g_list_prepend (*ret, repo_id);

    return TRUE;
}

GList *
seaf_repo_manager_list_garbage_repos (SeafRepoManager *mgr)
{
    GList *repo_ids = NULL;

    pthread_mutex_lock (&mgr->priv->db_lock);

    sqlite_foreach_selected_row (mgr->priv->db,
                                 "SELECT repo_id FROM GarbageRepos",
                                 get_garbage_repo_id, &repo_ids);
    pthread_mutex_unlock (&mgr->priv->db_lock);

    return repo_ids;
}

void
seaf_repo_manager_remove_garbage_repo (SeafRepoManager *mgr, const char *repo_id)
{
    char sql[256];

    pthread_mutex_lock (&mgr->priv->db_lock);

    snprintf (sql, sizeof(sql), "DELETE FROM GarbageRepos WHERE repo_id='%s'",
              repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);
}

void
seaf_repo_manager_remove_repo_ondisk (SeafRepoManager *mgr,
                                      const char *repo_id,
                                      gboolean add_deleted_record)
{
    char sql[256];

    /* We don't need to care about I/O errors here, since we can
     * GC any unreferenced repo data later.
     */

    if (add_deleted_record) {
        snprintf (sql, sizeof(sql), "REPLACE INTO GarbageRepos VALUES ('%s')",
                  repo_id);
        if (sqlite_query_exec (mgr->priv->db, sql) < 0)
            goto out;
    }

    /* Once the item in Repo table is deleted, the repo is gone.
     * This is the "commit point".
     */
    pthread_mutex_lock (&mgr->priv->db_lock);

    snprintf (sql, sizeof(sql), "DELETE FROM Repo WHERE repo_id = '%s'", repo_id);
    if (sqlite_query_exec (mgr->priv->db, sql) < 0)
        goto out;

    snprintf (sql, sizeof(sql), 
              "DELETE FROM DeletedRepo WHERE repo_id = '%s'", repo_id);
    sqlite_query_exec (mgr->priv->db, sql);

    pthread_mutex_unlock (&mgr->priv->db_lock);

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
    seaf_repo_manager_remove_repo_ondisk (mgr, repo->id,
                                          (repo->version > 0) ? TRUE : FALSE);

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

    commit = seaf_commit_manager_get_commit_compatible (manager->seaf->commit_mgr,
                                                        repo->id,
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
load_keys_cb (sqlite3_stmt *stmt, void *vrepo)
{
    SeafRepo *repo = vrepo;
    const char *key, *iv;

    key = (const char *)sqlite3_column_text(stmt, 0);
    iv = (const char *)sqlite3_column_text(stmt, 1);

    if (repo->enc_version == 1) {
        hex_to_rawdata (key, repo->enc_key, 16);
        hex_to_rawdata (iv, repo->enc_iv, 16);
    } else if (repo->enc_version == 2) {
        hex_to_rawdata (key, repo->enc_key, 32);
        hex_to_rawdata (iv, repo->enc_iv, 16);
    }

    return FALSE;
}

static int
load_repo_passwd (SeafRepoManager *manager, SeafRepo *repo)
{
    sqlite3 *db = manager->priv->db;
    char sql[256];
    int n;

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql), 
              "SELECT key, iv FROM RepoKeys WHERE repo_id='%s'",
              repo->id);
    n = sqlite_foreach_selected_row (db, sql, load_keys_cb, repo);
    if (n < 0)
        return -1;

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

             commit =
                 seaf_commit_manager_get_commit_compatible (manager->seaf->commit_mgr,
                                                            repo->id,
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
        if (seafile_session_config_get_allow_invalid_worktree(seaf)) {
            seaf_warning ("Worktree for repo \"%s\" is invalid, but still keep it.\n",
                          repo->name);
            repo->worktree_invalid = TRUE;
        } else {
            seaf_message ("Worktree for repo \"%s\" is invalid, delete it.\n",
                          repo->name);
            seaf_repo_manager_del_repo (manager, repo);
            return NULL;
        }
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

    sql = "CREATE TABLE IF NOT EXISTS CommonAncestor ("
        "repo_id TEXT PRIMARY KEY, ca_id TEXT, head_id TEXT);";
    sqlite_query_exec (db, sql);

    /* Version 1 repos will be added to this table after deletion.
     * GC will scan this table and remove the objects and blocks for the repos.
     */
    sql = "CREATE TABLE IF NOT EXISTS GarbageRepos (repo_id TEXT PRIMARY KEY);";
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

    seaf_repo_manager_remove_repo_ondisk (manager, repo_id, TRUE);

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
            seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree);
            repo->last_sync_time = 0;
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
    char sql[512];
    char key[65], iv[33];

    if (repo->enc_version == 1) {
        rawdata_to_hex (repo->enc_key, key, 16);
        rawdata_to_hex (repo->enc_iv, iv, 16);
    } else if (repo->enc_version == 2) {
        rawdata_to_hex (repo->enc_key, key, 32);
        rawdata_to_hex (repo->enc_iv, iv, 16);
    }

    snprintf (sql, sizeof(sql), "REPLACE INTO RepoKeys VALUES ('%s', '%s', '%s')",
              repo->id, key, iv);
    if (sqlite_query_exec (db, sql) < 0)
        return -1;

    return 0;
}

int 
seaf_repo_manager_set_repo_passwd (SeafRepoManager *manager,
                                   SeafRepo *repo,
                                   const char *passwd)
{
    int ret;

    if (seafile_decrypt_repo_enc_key (repo->enc_version, passwd, repo->random_key,
                                      repo->enc_key, repo->enc_iv) < 0)
        return -1;

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

typedef struct {
    char common_ancestor[41];
    char head_id[41];
} CAInfo;

static gboolean
get_common_ancestor (sqlite3_stmt *stmt, void *vinfo)
{
    CAInfo *info = vinfo;

    const char *ancestor = (const char *) sqlite3_column_text (stmt, 0);
    const char *head_id = (const char *) sqlite3_column_text (stmt, 1);

    memcpy (info->common_ancestor, ancestor, 40);
    memcpy (info->head_id, head_id, 40);

    return FALSE;
}

int
seaf_repo_manager_get_common_ancestor (SeafRepoManager *manager,
                                       const char *repo_id,
                                       char *common_ancestor,
                                       char *head_id)
{
    char sql[256];
    CAInfo info;

    memset (&info, 0, sizeof(info));

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql),
              "SELECT ca_id, head_id FROM CommonAncestor WHERE repo_id='%s';",
              repo_id);
    if (sqlite_foreach_selected_row (manager->priv->db, sql,
                                     get_common_ancestor, &info) < 0) {
        pthread_mutex_unlock (&manager->priv->db_lock);
        return -1;
    }

    pthread_mutex_unlock (&manager->priv->db_lock);

    memcpy (common_ancestor, info.common_ancestor, 41);
    memcpy (head_id, info.head_id, 41);

    return 0;
}

int
seaf_repo_manager_set_common_ancestor (SeafRepoManager *manager,
                                       const char *repo_id,
                                       const char *common_ancestor,
                                       const char *head_id)
{
    char sql[256];

    pthread_mutex_lock (&manager->priv->db_lock);

    snprintf (sql, sizeof(sql),
              "REPLACE INTO CommonAncestor VALUES ('%s', '%s', '%s');",
              repo_id, common_ancestor, head_id);
    int ret = sqlite_query_exec (manager->priv->db, sql);

    pthread_mutex_unlock (&manager->priv->db_lock);
    return ret;
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
        if (seaf_wt_monitor_watch_repo (seaf->wt_monitor, repo->id, repo->worktree) < 0) {
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
