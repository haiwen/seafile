/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <glib/gstdio.h>

#include <json-glib/json-glib.h>
#include <openssl/sha.h>

#include <ccnet.h>
#include <ccnet/ccnet-object.h>
#include "utils.h"
#include "avl/avl.h"
#include "log.h"
#include "seafile.h"

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
#include "merge-new.h"
#include "monitor-rpc-wrappers.h"

#include "seaf-db.h"

#define INDEX_DIR "index"

gboolean
should_ignore_file(const char *filename, void *data);

/*
 * Repo operations.
 */

static gint
compare_dirents (gconstpointer a, gconstpointer b)
{
    const SeafDirent *ent_a = a, *ent_b = b;

    return strcmp (ent_b->name, ent_a->name);
}

static inline SeafDirent *
dup_seaf_dirent (const SeafDirent *dent)
{
    return seaf_dirent_new (dent->id, dent->mode, dent->name);
}

static inline GList *
dup_seafdir_entries (const GList *entries)
{
    const GList *p;
    GList *newentries = NULL;
    SeafDirent *dent;
    
    for (p = entries; p; p = p->next) {
        dent = p->data;
        newentries = g_list_prepend (newentries, dup_seaf_dirent(dent));
    }

    return g_list_reverse(newentries);
}

/* We need to call this function recursively because every dirs in canon_path
 * need to be updated.
 */
static char *
post_file_recursive (const char *dir_id,
                     const char *to_path,
                     SeafDirent *newdent)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    char *slash;
    char *to_path_dup = NULL;
    char *remain = NULL;
    char *id = NULL;

    olddir = seaf_fs_manager_get_seafdir_sorted(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir.  new dir entry is added */
    if (*to_path == '\0') {
        GList *newentries;

        newentries = dup_seafdir_entries (olddir->entries);

        newentries = g_list_insert_sorted (newentries,
                                           dup_seaf_dirent(newdent),
                                           compare_dirents);

        newdir = seaf_dir_new (NULL, newentries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        id = g_strndup (newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free (newdir);

        goto out;
    }

    to_path_dup = g_strdup (to_path);
    slash = strchr (to_path_dup, '/');

    if (!slash) {
        remain = to_path_dup + strlen(to_path_dup);
    } else {
        *slash = '\0';
        remain = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strcmp(dent->name, to_path_dup) != 0)
            continue;

        id = post_file_recursive (dent->id, remain, newdent);
        if (id != NULL) {
            memcpy(dent->id, id, 40);
            dent->id[40] = '\0';
        }
        break;
    }
    
    if (id != NULL) {
        /* Create a new SeafDir. */
        GList *new_entries;
        
        new_entries = dup_seafdir_entries (olddir->entries);
        newdir = seaf_dir_new (NULL, new_entries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        
        g_free(id);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        
        seaf_dir_free (newdir);
    }

out:
    g_free (to_path_dup);
    seaf_dir_free(olddir);
    return id;
}

static char *
do_post_file (const char *root_id,
              const char *parent_dir,
              SeafDirent *dent)
{
    /* if parent_dir is a absolutely path, we will remove the first '/' */
    if (*parent_dir == '/')
        parent_dir = parent_dir + 1;

    return post_file_recursive(root_id, parent_dir, dent);
}

static char *
get_canonical_path (const char *path)
{
    char *ret = g_strdup (path);
    char *p;

    for (p = ret; *p != 0; ++p) {
        if (*p == '\\')
            *p = '/';
    }

    /* Remove trailing slashes from dir path. */
    int len = strlen(ret);
    int i = len - 1;
    while (i >= 0 && ret[i] == '/')
        ret[i--] = 0;

    return ret;
}

/* Return TRUE if @filename already existing in @parent_dir. If exists, and
   @mode is not NULL, set its value to the mode of the dirent.
*/
static gboolean
check_file_exists (const char *root_id,
                   const char *parent_dir,
                   const char *filename,
                   int  *mode)
{
    SeafDir *dir;
    GList *p;
    SeafDirent *dent;
    int ret = FALSE;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr, root_id,
                                               parent_dir, NULL);
    if (!dir) {
        seaf_warning ("parent_dir %s doesn't exist.\n", parent_dir);
        return FALSE;
    }

    for (p = dir->entries; p != NULL; p = p->next) {
        dent = p->data;
        int r = strcmp (dent->name, filename);
        if (r == 0) {
            ret = TRUE;
            if (mode) {
                *mode = dent->mode;
            }
            break;
        }
    }

    seaf_dir_free (dir);

    return ret;
}

/**
  Various online file/directory operations:

  Put a file:
  1. find parent seafdir
  2. add a new dirent to parent seafdir
  2. recursively update all seafdir in the path, in a bottom-up manner
  3. commit it

  Del a file/dir:
  basically the same as put a file

  copy a file/dir:
  1. get src dirent from src repo
  2. duplicate src dirent with the new file name
  3. put the new dirent to dst repo and commit it.

  Move a file/dir:
  basically the same as a copy operation. Just one more step:
  4. remove src dirent from src repo and commit it

  Rename a file/dir:
  1. find parent seafdir
  2. update this seafdir with the old dirent replaced by a new dirent.
  3. recursively update all seafdir in the path
  
  NOTE:
  
  All operations which add a new dirent would check if a dirent with the same
  name already exists. If found, they would raise errors.

  All operations which remove a dirent would check if the dirent to be removed
  already exists. If not, they would do nothing and just return OK.

*/

#define GET_REPO_OR_FAIL(repo_var,repo_id)                              \
    do {                                                                \
        repo_var = seaf_repo_manager_get_repo (seaf->repo_mgr, (repo_id)); \
        if (!(repo_var)) {                                              \
            seaf_warning ("Repo %s doesn't exist.\n", (repo_id));       \
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo"); \
            ret = -1;                                                   \
            goto out;                                                   \
        }                                                               \
    } while (0);

#define GET_COMMIT_OR_FAIL(commit_var,commit_id)                        \
    do {                                                                \
        commit_var = seaf_commit_manager_get_commit(seaf->commit_mgr, (commit_id)); \
        if (!(commit_var)) {                                            \
            seaf_warning ("commit %s doesn't exist.\n", (commit_id));   \
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid commit"); \
            ret = -1;                                                   \
            goto out;                                                   \
        }                                                               \
    } while (0);

#define FAIL_IF_FILE_EXISTS(root_id,parent_dir,filename,mode)           \
    do {                                                                \
        if (check_file_exists ((root_id), (parent_dir), (filename), (mode))) { \
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,      \
                         "file already exists");                        \
            ret = -1;                                                   \
            goto out;                                                   \
        }                                                               \
    } while (0);

#define FAIL_IF_FILE_NOT_EXISTS(root_id,parent_dir,filename,mode)       \
    do {                                                                \
        if (!check_file_exists ((root_id), (parent_dir), (filename), (mode))) { \
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,      \
                         "file does not exist");                        \
            ret = -1;                                                   \
            goto out;                                                   \
        }                                                               \
    } while (0);

static int
gen_new_commit (const char *repo_id,
                SeafCommit *base,
                const char *new_root,
                const char *user,
                const char *desc,
                GError **error)
{
#define MAX_RETRY_COUNT 3

    SeafRepo *repo = NULL;
    SeafCommit *new_commit = NULL, *current_head = NULL, *merged_commit = NULL;
    int retry_cnt = 0;
    int ret = 0;

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Repo %s doesn't exist.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Invalid repo");
        ret = -1;
        goto out;
    }

    /* Create a new commit pointing to new_root. */
    new_commit = seaf_commit_new(NULL, repo->id, new_root,
                                 user, EMPTY_SHA1,
                                 desc, 0);
    new_commit->parent_id = g_strdup (base->commit_id);
    seaf_repo_to_commit (repo, new_commit);

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, new_commit) < 0) {
        seaf_warning ("Failed to add commit.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to add commit");
        ret = -1;
        goto out;
    }

retry:
    current_head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                   repo->head->commit_id);
    if (!current_head) {
        seaf_warning ("Failed to find head commit of %s.\n", repo_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Invalid repo");
        ret = -1;
        goto out;
    }

    /* Merge if base and head are not the same. */
    if (strcmp (base->commit_id, current_head->commit_id) != 0) {
        MergeOptions opt;
        const char *roots[3];

        memset (&opt, 0, sizeof(opt));
        opt.n_ways = 3;
        memcpy (opt.remote_head, new_commit->commit_id, 40);
        opt.do_merge = TRUE;

        roots[0] = base->root_id; /* base */
        roots[1] = current_head->root_id; /* head */
        roots[2] = new_root;      /* remote */

        if (seaf_merge_trees (3, roots, &opt) < 0) {
            seaf_warning ("Failed to merge.\n");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Internal error");
            ret = -1;
            goto out;
        }

        merged_commit = seaf_commit_new(NULL, repo->id, opt.merged_tree_root,
                                        user, EMPTY_SHA1,
                                        "Auto merge by seafile system",
                                        0);

        merged_commit->parent_id = g_strdup (current_head->commit_id);
        merged_commit->second_parent_id = g_strdup (new_commit->commit_id);
        seaf_repo_to_commit (repo, merged_commit);

        if (seaf_commit_manager_add_commit (seaf->commit_mgr, merged_commit) < 0) {
            seaf_warning ("Failed to add commit.\n");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Failed to add commit");
            ret = -1;
            goto out;
        }
    } else {
        seaf_commit_ref (new_commit);
        merged_commit = new_commit;
    }

    seaf_branch_set_commit(repo->head, merged_commit->commit_id);

    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   current_head->commit_id) < 0)
    {
        seaf_repo_unref (repo);
        repo = NULL;
        seaf_commit_unref (current_head);
        current_head = NULL;
        seaf_commit_unref (merged_commit);
        merged_commit = NULL;

        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!repo) {
            seaf_warning ("Repo %s doesn't exist.\n", repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Invalid repo");
            ret = -1;
            goto out;
        }

        if (++retry_cnt <= MAX_RETRY_COUNT) {
            seaf_message ("Concurrent branch update, retry.\n");
            /* Sleep random time between 100 and 1000 millisecs. */
            usleep (g_random_int_range(1, 11) * 100 * 1000);
            goto retry;
        } else {
            seaf_warning ("Stop retrying.\n");
            ret = -1;
            goto out;
        }
    }

out:
    seaf_commit_unref (new_commit);
    seaf_commit_unref (current_head);
    seaf_commit_unref (merged_commit);
    seaf_repo_unref (repo);
    return ret;
}

static void
update_repo_size(const char *repo_id)
{
    if (seaf->monitor_id == NULL)
        return;

    SearpcClient *ccnet_rpc_client = NULL, *monitor_rpc_client = NULL;
    GError *error = NULL;

    if (strcmp(seaf->monitor_id, seaf->session->base.id) != 0) {
        ccnet_rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                           NULL,
                                                           "ccnet-rpcserver");
        if (!ccnet_rpc_client) {
            seaf_warning ("failed to create ccnet rpc client\n");
            goto out;
        }

        if (!ccnet_peer_is_ready (ccnet_rpc_client, seaf->monitor_id)) {
            goto out;
        }
    }

    monitor_rpc_client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                                         NULL,
                                                         "monitor-rpcserver");
    if (!monitor_rpc_client) {
        seaf_warning ("failed to create monitor rpc client\n");
        goto out;
    }

    searpc_client_call__int (monitor_rpc_client, "compute_repo_size",
                             &error, 1, "string", repo_id);

    if (error) {
        seaf_warning ("error when compute_repo_size: %s", error->message);
        g_error_free (error);
    }

out:
    if (ccnet_rpc_client)
        ccnet_rpc_client_free (ccnet_rpc_client);
    if (monitor_rpc_client)
        ccnet_rpc_client_free (monitor_rpc_client);
}

int
seaf_repo_manager_post_file (SeafRepoManager *mgr,
                             const char *repo_id,
                             const char *temp_file_path,
                             const char *parent_dir,
                             const char *file_name,
                             const char *user,
                             GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    unsigned char sha1[20];
    char buf[SEAF_PATH_MAX];
    char *root_id = NULL;
    SeafileCrypt *crypt = NULL;
    SeafDirent *new_dent = NULL;
    char hex[41];
    int ret = 0;

    if (access (temp_file_path, R_OK) != 0) {
        seaf_warning ("[post file] File %s doesn't exist or not readable.\n",
                      temp_file_path);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid input file");
        return -1;
    }

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit,repo->head->commit_id);

    if (!canon_path)
        canon_path = get_canonical_path (parent_dir);

    if (should_ignore_file (file_name, NULL)) {
        seaf_warning ("[post file] Invalid filename %s.\n", file_name);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid filename");
        ret = -1;
        goto out;
    }

    if (strstr (parent_dir, "//") != NULL) {
        seaf_warning ("[post file] parent_dir cantains // sequence.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid parent dir");
        ret = -1;
        goto out;
    }
    
    FAIL_IF_FILE_EXISTS(head_commit->root_id, canon_path, file_name, NULL);

    /* Write blocks. */
    if (repo->encrypted) {
        unsigned char key[16], iv[16];
        if (seaf_passwd_manager_get_decrypt_key_raw (seaf->passwd_mgr,
                                                     repo_id, user,
                                                     key, iv) < 0) {
            seaf_warning ("Passwd for repo %s is not set.\n", repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Passwd is not set");
            ret = -1;
            goto out;
        }
        crypt = seafile_crypt_new (repo->enc_version, key, iv);
    }

    if (seaf_fs_manager_index_blocks (seaf->fs_mgr, temp_file_path,
                                      sha1, crypt) < 0) {
        seaf_warning ("failed to index blocks");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to index blocks");
        ret = -1;
        goto out;
    }
        
    rawdata_to_hex(sha1, hex, 20);
    new_dent = seaf_dirent_new (hex, S_IFREG, file_name);

    root_id = do_post_file (head_commit->root_id, canon_path, new_dent);
    if (!root_id) {
        seaf_warning ("[post file] Failed to put file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to put file");
        ret = -1;
        goto out;
    }

    snprintf(buf, SEAF_PATH_MAX, "Added \"%s\"", file_name);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_dent)
        g_free (new_dent);
    g_free (root_id);
    g_free (canon_path);
    g_free (crypt);

    if (ret == 0)
        update_repo_size(repo_id);

    return ret;
}

static gboolean
filename_exists (GList *entries, const char *filename)
{
    GList *ptr;
    SeafDirent *dent;

    for (ptr = entries; ptr != NULL; ptr = ptr->next) {
        dent = ptr->data;
        if (strcmp (dent->name, filename) == 0)
            return TRUE;
    }

    return FALSE;
}

static void
split_filename (const char *filename, char **name, char **ext)
{
    char *dot;

    dot = strrchr (filename, '.');
    if (dot) {
        *ext = g_strdup (dot + 1);
        *name = g_strndup (filename, dot - filename);
    } else {
        *name = g_strdup (filename);
        *ext = NULL;
    }
}

static int
add_new_entries (GList **entries, GList *filenames, GList *id_list)
{
    GList *ptr1, *ptr2;
    char *file, *id;

    for (ptr1 = filenames, ptr2 = id_list;
         ptr1 && ptr2;
         ptr1 = ptr1->next, ptr2 = ptr2->next)
    {
        file = ptr1->data;
        id = ptr2->data;

        int i = 1;
        char *name, *ext, *unique_name;
        SeafDirent *newdent;

        unique_name = g_strdup(file);
        split_filename (unique_name, &name, &ext);
        while (filename_exists (*entries, unique_name) && i <= 16) {
            g_free (unique_name);
            if (ext)
                unique_name = g_strdup_printf ("%s (%d).%s", name, i, ext);
            else
                unique_name = g_strdup_printf ("%s (%d)", name, i);
            i++;
        }

        if (i <= 16) {
            newdent = seaf_dirent_new (id, S_IFREG, unique_name);
            *entries = g_list_insert_sorted (*entries, newdent, compare_dirents);
        }

        g_free (name);
        g_free (ext);
        g_free (unique_name);

        if (i > 16)
            return -1;
    }

    return 0;
}

static char *
post_multi_files_recursive (const char *dir_id,
                            const char *to_path,
                            GList *filenames,
                            GList *id_list)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    char *slash;
    char *to_path_dup = NULL;
    char *remain = NULL;
    char *id = NULL;

    olddir = seaf_fs_manager_get_seafdir_sorted(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir.  new dir entry is added */
    if (*to_path == '\0') {
        GList *newentries;

        newentries = dup_seafdir_entries (olddir->entries);

        if (add_new_entries (&newentries, filenames, id_list) < 0)
            goto out;

        newdir = seaf_dir_new (NULL, newentries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        id = g_strndup (newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free (newdir);

        goto out;
    }

    to_path_dup = g_strdup (to_path);
    slash = strchr (to_path_dup, '/');

    if (!slash) {
        remain = to_path_dup + strlen(to_path_dup);
    } else {
        *slash = '\0';
        remain = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strcmp(dent->name, to_path_dup) != 0)
            continue;

        id = post_multi_files_recursive (dent->id, remain, filenames, id_list);
        if (id != NULL) {
            memcpy(dent->id, id, 40);
            dent->id[40] = '\0';
        }
        break;
    }
    
    if (id != NULL) {
        /* Create a new SeafDir. */
        GList *new_entries;
        
        new_entries = dup_seafdir_entries (olddir->entries);
        newdir = seaf_dir_new (NULL, new_entries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        
        g_free(id);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        
        seaf_dir_free (newdir);
    }

out:
    g_free (to_path_dup);
    seaf_dir_free(olddir);
    return id;
}

static char *
do_post_multi_files (const char *root_id,
                     const char *parent_dir,
                     GList *filenames,
                     GList *id_list)
{
    /* if parent_dir is a absolutely path, we will remove the first '/' */
    if (*parent_dir == '/')
        parent_dir = parent_dir + 1;

    return post_multi_files_recursive(root_id, parent_dir, filenames, id_list);
}

static void
convert_file_list (JsonArray *array, guint index, JsonNode *element, gpointer data)
{
    GList **files = data;

    *files = g_list_prepend (*files, json_node_dup_string (element));
}

static GList *
json_to_file_list (const char *files_json)
{
    JsonParser *parser = json_parser_new ();
    JsonNode *root;
    JsonArray *array;
    GList *files = NULL;
    GError *error = NULL;

    json_parser_load_from_data (parser, files_json, strlen(files_json), &error);
    if (error) {
        seaf_warning ("Failed to load file list from json.\n");
        g_error_free (error);
        return NULL;
    }

    root = json_parser_get_root (parser);
    array = json_node_get_array (root);

    json_array_foreach_element (array, convert_file_list, &files);

    g_object_unref (parser);
    return files;
}

int
seaf_repo_manager_post_multi_files (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *parent_dir,
                                    const char *filenames_json,
                                    const char *paths_json,
                                    const char *user,
                                    GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    GList *filenames = NULL, *paths = NULL, *id_list = NULL, *ptr;
    char *filename, *path;
    unsigned char sha1[20];
    GString *buf = g_string_new (NULL);
    char *root_id = NULL;
    SeafileCrypt *crypt = NULL;
    char hex[41];
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit,repo->head->commit_id);

    canon_path = get_canonical_path (parent_dir);

    /* Decode file name and tmp file paths from json. */
    filenames = json_to_file_list (filenames_json);
    paths = json_to_file_list (paths_json);
    if (!filenames || !paths) {
        seaf_warning ("[post files] Invalid filenames or paths.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid files");
        ret = -1;
        goto out;
    }

    /* Check inputs. */
    for (ptr = filenames; ptr; ptr = ptr->next) {
        filename = ptr->data;
        if (should_ignore_file (filename, NULL)) {
            seaf_warning ("[post files] Invalid filename %s.\n", filename);
            g_set_error (error, SEAFILE_DOMAIN, POST_FILE_ERR_FILENAME,
                         "%s", filename);
            ret = -1;
            goto out;
        }
    }

    if (strstr (parent_dir, "//") != NULL) {
        seaf_warning ("[post file] parent_dir cantains // sequence.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid parent dir");
        ret = -1;
        goto out;
    }

    /* Index tmp files and get file id list. */
    if (repo->encrypted) {
        unsigned char key[16], iv[16];
        if (seaf_passwd_manager_get_decrypt_key_raw (seaf->passwd_mgr,
                                                     repo_id, user,
                                                     key, iv) < 0) {
            seaf_warning ("Passwd for repo %s is not set.\n", repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Passwd is not set");
            ret = -1;
            goto out;
        }
        crypt = seafile_crypt_new (repo->enc_version, key, iv);
    }

    for (ptr = paths; ptr; ptr = ptr->next) {
        path = ptr->data;
        if (seaf_fs_manager_index_blocks (seaf->fs_mgr, path, sha1, crypt) < 0) {
            seaf_warning ("failed to index blocks");
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Failed to index blocks");
            ret = -1;
            goto out;
        }

        rawdata_to_hex(sha1, hex, 20);
        id_list = g_list_prepend (id_list, g_strdup(hex));
    }
    id_list = g_list_reverse (id_list);

    /* Add the files to parent dir and commit. */
    root_id = do_post_multi_files (head_commit->root_id, canon_path,
                                   filenames, id_list);
    if (!root_id) {
        seaf_warning ("[post file] Failed to put file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Failed to put file");
        ret = -1;
        goto out;
    }

    guint len = g_list_length (filenames);
    if (len > 1)
        g_string_printf (buf, "Added \"%s\" and %u more files.",
                         (char *)(filenames->data), len - 1);
    else
        g_string_printf (buf, "Added \"%s\".", (char *)(filenames->data));

    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf->str, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    string_list_free (filenames);
    string_list_free (paths);
    string_list_free (id_list);
    g_string_free (buf, TRUE);
    g_free (root_id);
    g_free (canon_path);
    g_free (crypt);

    if (ret == 0)
        update_repo_size(repo_id);

    return ret;
}

static char *
del_file_recursive(const char *dir_id,
                   const char *to_path,
                   const char *filename)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    char *to_path_dup = NULL;
    char *remain = NULL;
    char *slash;
    char *id = NULL;

    olddir = seaf_fs_manager_get_seafdir_sorted(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir. Remove the given entry from it. */
    if (*to_path == '\0') {
        SeafDirent *old, *new;
        GList *newentries = NULL, *p;

        for (p = olddir->entries; p != NULL; p = p->next) {
            old = p->data;
            if (strcmp(old->name, filename) != 0) {
                new = seaf_dirent_new (old->id, old->mode, old->name);
                newentries = g_list_prepend (newentries, new);
            }
        }

        newentries = g_list_reverse (newentries);

        newdir = seaf_dir_new(NULL, newentries, 0);
        seaf_dir_save(seaf->fs_mgr, newdir);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free(newdir);

        goto out;
    }

    to_path_dup = g_strdup (to_path);
    slash = strchr (to_path_dup, '/');

    if (!slash) {
        remain = to_path_dup + strlen(to_path_dup);
    } else {
        *slash = '\0';
        remain = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strcmp(dent->name, to_path_dup) != 0)
            continue;

        id = del_file_recursive(dent->id, remain, filename);
        if (id != NULL) {
            memcpy(dent->id, id, 40);
            dent->id[40] = '\0';
        }
        break;
    }
    if (id != NULL) {
        /* Create a new SeafDir. */
        GList *new_entries;
        
        new_entries = dup_seafdir_entries (olddir->entries);
        newdir = seaf_dir_new (NULL, new_entries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        
        g_free(id);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        
        seaf_dir_free (newdir);
    }

out:
    g_free (to_path_dup);
    seaf_dir_free(olddir);
    return id;
}

static char *
do_del_file(const char *root_id,
            const char *parent_dir,
            const char *file_name)
{
    /* if parent_dir is a absolutely path, we will remove the first '/' */
    if (*parent_dir == '/')
        parent_dir = parent_dir + 1;

    return del_file_recursive(root_id, parent_dir, file_name);
}

int
seaf_repo_manager_del_file (SeafRepoManager *mgr,
                            const char *repo_id,
                            const char *parent_dir,
                            const char *file_name,
                            const char *user,
                            GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    char buf[SEAF_PATH_MAX];
    char *root_id = NULL;
    int mode = 0;
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    if (!canon_path)
        canon_path = get_canonical_path (parent_dir);
    
    if (!check_file_exists(head_commit->root_id, canon_path, file_name, &mode)) {
        seaf_warning ("[del file] target file %s/%s does not exist, skip\n",
                      canon_path, file_name);
        goto out;
    }

    root_id = do_del_file (head_commit->root_id, canon_path, file_name);
    if (!root_id) {
        seaf_warning ("[del file] Failed to del file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to del file");
        ret = -1;
        goto out;
    }

    /* Commit. */
    if (S_ISDIR(mode)) {
        snprintf(buf, SEAF_PATH_MAX, "Removed directory \"%s\"", file_name);
    } else {
        snprintf(buf, SEAF_PATH_MAX, "Deleted \"%s\"", file_name);
    }

    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    g_free (root_id);
    g_free (canon_path);

    if (ret == 0) {
        update_repo_size (repo_id);
    }

    return ret;
}

static SeafDirent *
get_dirent_by_path (SeafRepo *repo,
                    const char *path,
                    const char *file_name,
                    GError **error)
{
    SeafCommit *head_commit = NULL; 
    SeafDirent *dent = NULL;
    SeafDir *dir = NULL;
    
    head_commit = seaf_commit_manager_get_commit(seaf->commit_mgr,
                                                 repo->head->commit_id);
    if (!head_commit) {
        seaf_warning ("commit %s doesn't exist.\n", repo->head->commit_id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid commit");
        goto out;
    }

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr, head_commit->root_id,
                                              path, NULL);
    if (!dir) {
        seaf_warning ("dir %s doesn't exist in repo %s.\n", path, repo->id);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid dir");
        goto out;
    }

    GList *p;
    for (p = dir->entries; p; p = p->next) {
        SeafDirent *d = p->data;
        int r = strcmp (d->name, file_name);
        if (r == 0) {
            dent = seaf_dirent_new (d->id, d->mode, d->name);
            break;
        }
    }

    if (!dent && error && !(*error)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "failed to get dirent");
    }

out:
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (dir)
        seaf_dir_free (dir);

    return dent;
}

static int
put_dirent_and_commit (const char *repo_id,
                       const char *path,
                       SeafDirent *dent,
                       const char *user,
                       GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *root_id = NULL;
    char buf[SEAF_PATH_MAX];
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    root_id = do_post_file (head_commit->root_id, path, dent);
    if (!root_id) {
        seaf_warning ("[cp file] Failed to cp file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to cp file");
        ret = -1;
        goto out;
    }

    /* Commit. */
    if (S_ISDIR(dent->mode)) {
        snprintf(buf, sizeof(buf), "Added directory \"%s\"", dent->name);
    } else {
        snprintf(buf, sizeof(buf), "Added \"%s\"", dent->name);
    }

    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (root_id)
        g_free (root_id);
    
    return ret;
}

/**
 * Copy a SeafDirent from a SeafDir to another.
 * 
 * 1. When @src_repo and @dst_repo are not the same repo, neither of them
 *    should be encrypted.
 * 
 * 2. the file being copied must not exist in the dst path of the dst repo.
 */
int
seaf_repo_manager_copy_file (SeafRepoManager *mgr,
                             const char *src_repo_id,
                             const char *src_path,
                             const char *src_filename,
                             const char *dst_repo_id,
                             const char *dst_path,
                             const char *dst_filename,
                             const char *user,
                             GError **error)
{
    SeafRepo *src_repo = NULL, *dst_repo = NULL;
    SeafDirent *src_dent = NULL, *dst_dent = NULL;
    char *src_canon_path = NULL, *dst_canon_path = NULL;
    SeafCommit *dst_head_commit = NULL;
    int ret = 0;

    GET_REPO_OR_FAIL(src_repo, src_repo_id);

    if (strcmp(src_repo_id, dst_repo_id) != 0) {
        GET_REPO_OR_FAIL(dst_repo, dst_repo_id);

        if (src_repo->encrypted || dst_repo->encrypted) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Can't copy files between encrypted repo(s)");
            ret = -1;
            goto out;
        }
        
    } else {
        seaf_repo_ref (src_repo);
        dst_repo = src_repo;
    }
    
    src_canon_path = get_canonical_path (src_path);
    dst_canon_path = get_canonical_path (dst_path);

    /* first check whether a file with file_name already exists in destination dir */
    GET_COMMIT_OR_FAIL(dst_head_commit, dst_repo->head->commit_id);
    
    FAIL_IF_FILE_EXISTS(dst_head_commit->root_id, dst_canon_path, dst_filename, NULL);
    
    /* get src dirent */
    src_dent = get_dirent_by_path (src_repo, src_canon_path, src_filename, error);
    if (!src_dent) {
        ret = -1;
        goto out;
    }

    /* duplicate src dirent with new name */
    dst_dent = seaf_dirent_new (src_dent->id, src_dent->mode, dst_filename);

    if (put_dirent_and_commit (dst_repo_id,
                               dst_canon_path,
                               dst_dent,
                               user,
                               error) < 0) {
        if (!error)
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "failed to put dirent");
            ret = -1;
            goto out;
    }
    
out:
    if (src_repo)
        seaf_repo_unref (src_repo);
    if (dst_repo)
        seaf_repo_unref (dst_repo);
    if (dst_head_commit)
        seaf_commit_unref(dst_head_commit);
    if (src_canon_path)
        g_free (src_canon_path);
    if (dst_canon_path)
        g_free (dst_canon_path);
    if (src_dent)
        g_free(src_dent);
    if (dst_dent)
        g_free(dst_dent);

    if (ret == 0) {
        update_repo_size (dst_repo_id);
    }

    return ret;
}

static int
move_file_same_repo (const char *repo_id,
                     const char *src_path, SeafDirent *src_dent,
                     const char *dst_path, SeafDirent *dst_dent,
                     const char *user,
                     GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *root_id_after_put = NULL, *root_id = NULL;
    char buf[SEAF_PATH_MAX];
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);
    
    root_id_after_put = do_post_file (head_commit->root_id, dst_path, dst_dent);
    if (!root_id_after_put) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "move file failed");
        ret = -1;
        goto out;
    }

    root_id = do_del_file (root_id_after_put, src_path, src_dent->name);
    if (!root_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "move file failed");
        ret = -1;
        goto out;
    }

    /* Commit. */
    if (S_ISDIR(src_dent->mode)) {
        snprintf(buf, SEAF_PATH_MAX, "Moved directory \"%s\"", src_dent->name);
    } else {
        snprintf(buf, SEAF_PATH_MAX, "Moved \"%s\"", src_dent->name);
    }

    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;
    
out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    g_free (root_id_after_put);
    g_free (root_id);
    
    return ret;
}
                     
int
seaf_repo_manager_move_file (SeafRepoManager *mgr,
                             const char *src_repo_id,
                             const char *src_path,
                             const char *src_filename,
                             const char *dst_repo_id,
                             const char *dst_path,
                             const char *dst_filename,
                             const char *user,
                             GError **error)
{
    SeafRepo *src_repo = NULL, *dst_repo = NULL;
    SeafDirent *src_dent = NULL, *dst_dent = NULL;
    char *src_canon_path = NULL, *dst_canon_path = NULL;
    SeafCommit *dst_head_commit = NULL;
    int ret = 0;

    GET_REPO_OR_FAIL(src_repo, src_repo_id);

    if (strcmp(src_repo_id, dst_repo_id) != 0) {
        GET_REPO_OR_FAIL(dst_repo, dst_repo_id);

        if (src_repo->encrypted || dst_repo->encrypted) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Can't copy files between encrypted repo(s)");
            ret = -1;
            goto out;
        }
        
    } else {
        seaf_repo_ref (src_repo);
        dst_repo = src_repo;
    }
    
    src_canon_path = get_canonical_path (src_path);
    dst_canon_path = get_canonical_path (dst_path);
    /* first check whether a file with file_name already exists in destination dir */
    GET_COMMIT_OR_FAIL(dst_head_commit, dst_repo->head->commit_id);
    FAIL_IF_FILE_EXISTS(dst_head_commit->root_id, dst_canon_path, dst_filename, NULL);

    /* get src dirent */
    src_dent = get_dirent_by_path (src_repo, src_canon_path, src_filename, error);
    if (!src_dent) {
        ret = -1;
        goto out;
    }

    /* duplicate src dirent with new name */
    dst_dent = seaf_dirent_new (src_dent->id, src_dent->mode, dst_filename);

    if (src_repo == dst_repo) {
        /* move file within the same repo */
        if (move_file_same_repo (src_repo_id,
                                 src_canon_path, src_dent,
                                 dst_canon_path, dst_dent,
                                 user, error) < 0) {
            ret = -1;
            goto out;
        }
        
    } else {
        /* move between different repos */

        /* add this dirent to dst repo */
        if (put_dirent_and_commit (dst_repo_id,
                                   dst_canon_path,
                                   dst_dent,
                                   user,
                                   error) < 0) {
            if (!error)
                g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                             "failed to put dirent");
            ret = -1;
            goto out;
        }

        if (seaf_repo_manager_del_file (mgr, src_repo_id, src_path,
                                        src_filename, user, error) < 0) {
            ret = -1;
            goto out;
        }
    }

out:
    if (src_repo) seaf_repo_unref (src_repo);
    if (dst_repo) seaf_repo_unref (dst_repo);

    if (dst_head_commit) seaf_commit_unref(dst_head_commit);
    
    if (src_canon_path) g_free (src_canon_path);
    if (dst_canon_path) g_free (dst_canon_path);
    
    if (src_dent) g_free(src_dent);
    if (dst_dent) g_free(dst_dent);

    if (ret == 0) {
        update_repo_size (dst_repo_id);
    }

    return ret;
}

int
seaf_repo_manager_post_dir (SeafRepoManager *mgr,
                            const char *repo_id,
                            const char *parent_dir,
                            const char *new_dir_name,
                            const char *user,
                            GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    char buf[SEAF_PATH_MAX];
    char *root_id = NULL;
    SeafDirent *new_dent = NULL;
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    canon_path = get_canonical_path (parent_dir);

    if (should_ignore_file (new_dir_name, NULL)) {
        seaf_warning ("[post dir] Invalid dir name %s.\n", new_dir_name);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid dir name");
        ret = -1;
        goto out;
    }

    FAIL_IF_FILE_EXISTS(head_commit->root_id, canon_path, new_dir_name, NULL);

    if (!new_dent) {
        new_dent = seaf_dirent_new (EMPTY_SHA1, S_IFDIR, new_dir_name);
    }

    root_id = do_post_file (head_commit->root_id, canon_path, new_dent);
    if (!root_id) {
        seaf_warning ("[put dir] Failed to put dir.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to put dir");
        ret = -1;
        goto out;
    }

    /* Commit. */
    snprintf(buf, SEAF_PATH_MAX, "Added directory \"%s\"", new_dir_name);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_dent)
        g_free (new_dent);
    g_free (root_id);
    g_free (canon_path);

    return ret;
}

int
seaf_repo_manager_post_empty_file (SeafRepoManager *mgr,
                                   const char *repo_id,
                                   const char *parent_dir,
                                   const char *new_file_name,
                                   const char *user,
                                   GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    char buf[SEAF_PATH_MAX];
    char *root_id = NULL;
    SeafDirent *new_dent = NULL;
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    if (!canon_path)
        /* no need to call get_canonical_path again when retry */
        canon_path = get_canonical_path (parent_dir);

    if (should_ignore_file (new_file_name, NULL)) {
        seaf_warning ("[post file] Invalid file name %s.\n", new_file_name);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid file name");
        ret = -1;
        goto out;
    }

    FAIL_IF_FILE_EXISTS(head_commit->root_id, canon_path, new_file_name, NULL);

    if (!new_dent) {
        new_dent = seaf_dirent_new (EMPTY_SHA1, S_IFREG, new_file_name);
    }

    root_id = do_post_file (head_commit->root_id, canon_path, new_dent);
    if (!root_id) {
        seaf_warning ("[put dir] Failed to create empty file dir.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to put dir");
        ret = -1;
        goto out;
    }

    /* Commit. */
    snprintf(buf, SEAF_PATH_MAX, "Added \"%s\"", new_file_name);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_dent)
        g_free (new_dent);
    g_free (root_id);
    g_free (canon_path);

    return ret;
}

static char *
rename_file_recursive(const char *dir_id,
                      const char *to_path,
                      const char *oldname,
                      const char *newname)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    char *to_path_dup = NULL;
    char *remain = NULL;
    char *slash;
    char *id = NULL;

    olddir = seaf_fs_manager_get_seafdir_sorted(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir. */
    if (*to_path == '\0') {
        SeafDirent *old, *newdent = NULL;
        GList *newentries = NULL, *p;

        /* When renameing, there is a pitfall: we can't simply rename the
         * dirent, since the dirents are required to be sorted in descending
         * order. We need to copy all old dirents except the target dirent,
         * and then rename the target dirent, and then insert the new
         * dirent, so that we can maintain the descending order of dirents. */
        for (p = olddir->entries; p != NULL; p = p->next) {
            old = p->data;
            if (strcmp(old->name, oldname) != 0) {
                newentries = g_list_prepend (newentries, dup_seaf_dirent(old));
            } else {
                newdent = seaf_dirent_new (old->id, old->mode, newname);
            }
        }

        newentries = g_list_reverse (newentries);

        if (newdent) {
            newentries = g_list_insert_sorted(newentries, newdent, compare_dirents);
        }

        newdir = seaf_dir_new (NULL, newentries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        id = g_strndup (newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free (newdir);

        goto out;
    }

    to_path_dup = g_strdup (to_path);
    slash = strchr (to_path_dup, '/');

    if (!slash) {
        remain = to_path_dup + strlen(to_path_dup);
    } else {
        *slash = '\0';
        remain = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strcmp(dent->name, to_path_dup) != 0)
            continue;

        id = rename_file_recursive (dent->id, remain, oldname, newname);
        if (id != NULL) {
            memcpy(dent->id, id, 40);
            dent->id[40] = '\0';
        }
        break;
    }
    
    if (id != NULL) {
        /* Create a new SeafDir. */
        GList *new_entries;
        
        new_entries = dup_seafdir_entries (olddir->entries);
        newdir = seaf_dir_new (NULL, new_entries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        
        g_free(id);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        
        seaf_dir_free (newdir);
    }

out:
    g_free (to_path_dup);
    seaf_dir_free(olddir);
    return id;
}

static char *
do_rename_file(const char *root_id,
               const char *parent_dir,
               const char *oldname,
               const char *newname)
{
    /* if parent_dir is a absolutely path, we will remove the first '/' */
    if (*parent_dir == '/')
        parent_dir = parent_dir + 1;

    return rename_file_recursive(root_id, parent_dir, oldname, newname);
}


int
seaf_repo_manager_rename_file (SeafRepoManager *mgr,
                               const char *repo_id,
                               const char *parent_dir,
                               const char *oldname,
                               const char *newname,
                               const char *user,
                               GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *root_id = NULL;
    char *canon_path = NULL;
    char buf[SEAF_PATH_MAX];
    int mode = 0;
    int ret = 0;

    if (strcmp(oldname, newname) == 0)
        return 0;
    
    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);
    
    if (!canon_path)
        canon_path = get_canonical_path (parent_dir);

    if (should_ignore_file (newname, NULL)) {
        seaf_warning ("[rename file] Invalid filename %s.\n", newname);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid filename");
        ret = -1;
        goto out;
    }

    FAIL_IF_FILE_NOT_EXISTS(head_commit->root_id, canon_path, oldname, &mode);
    FAIL_IF_FILE_EXISTS(head_commit->root_id, canon_path, newname, NULL);

    root_id = do_rename_file (head_commit->root_id, canon_path,
                              oldname, newname);
    if (!root_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "faile to rename file %s", oldname);
        ret = -1;
        goto out;
    }

    /* Commit. */
    if (S_ISDIR(mode)) {
        snprintf(buf, SEAF_PATH_MAX, "Renamed directory \"%s\"", oldname);
    } else {
        snprintf(buf, SEAF_PATH_MAX, "Renamed \"%s\"", oldname);
    }

    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    g_free (canon_path);
    g_free (root_id);

    return ret;
}

static char *
put_file_recursive(const char *dir_id,
                   const char *to_path,
                   SeafDirent *newdent)
{
    SeafDir *olddir, *newdir;
    SeafDirent *dent;
    GList *ptr;
    char *to_path_dup = NULL;
    char *remain = NULL;
    char *slash;
    char *id = NULL;

    olddir = seaf_fs_manager_get_seafdir_sorted(seaf->fs_mgr, dir_id);
    if (!olddir)
        return NULL;

    /* we reach the target dir. Update the target dirent. */
    if (*to_path == '\0') {
        GList *newentries = NULL, *p;
        SeafDirent *dent;

        for (p = olddir->entries; p; p = p->next) {
            dent = p->data;
            if (strcmp(dent->name, newdent->name) == 0) {
                newentries = g_list_prepend (newentries, dup_seaf_dirent(newdent));
            } else {
                newentries = g_list_prepend (newentries, dup_seaf_dirent(dent));
            }
        }

        newentries = g_list_reverse (newentries);
        newdir = seaf_dir_new (NULL, newentries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        id = g_strndup (newdir->dir_id, 41);
        id[40] = '\0';
        seaf_dir_free (newdir);

        goto out;
    }

    to_path_dup = g_strdup (to_path);
    slash = strchr (to_path_dup, '/');

    if (!slash) {
        remain = to_path_dup + strlen(to_path_dup);
    } else {
        *slash = '\0';
        remain = slash + 1;
    }

    for (ptr = olddir->entries; ptr; ptr = ptr->next) {
        dent = (SeafDirent *)ptr->data;

        if (strcmp(dent->name, to_path_dup) != 0)
            continue;

        id = put_file_recursive (dent->id, remain, newdent);
        if (id != NULL) {
            memcpy(dent->id, id, 40);
            dent->id[40] = '\0';
        }
        break;
    }
    
    if (id != NULL) {
        /* Create a new SeafDir. */
        GList *new_entries;
        
        new_entries = dup_seafdir_entries (olddir->entries);
        newdir = seaf_dir_new (NULL, new_entries, 0);
        seaf_dir_save (seaf->fs_mgr, newdir);
        
        g_free(id);
        id = g_strndup(newdir->dir_id, 41);
        id[40] = '\0';
        
        seaf_dir_free (newdir);
    }

out:
    g_free (to_path_dup);
    seaf_dir_free(olddir);
    return id;
}

static char *
do_put_file (const char *root_id,
             const char *parent_dir,
             SeafDirent *dent)
{
    /* if parent_dir is a absolutely path, we will remove the first '/' */
    if (*parent_dir == '/')
        parent_dir = parent_dir + 1;

    return put_file_recursive(root_id, parent_dir, dent);
}

int
seaf_repo_manager_put_file (SeafRepoManager *mgr,
                            const char *repo_id,
                            const char *temp_file_path,
                            const char *parent_dir,
                            const char *file_name,
                            const char *user,
                            const char *head_id,
                            char **new_file_id,
                            GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    char *canon_path = NULL;
    unsigned char sha1[20];
    char buf[SEAF_PATH_MAX];
    char *root_id = NULL;
    SeafileCrypt *crypt = NULL;
    SeafDirent *new_dent = NULL;
    char hex[41];
    char *old_file_id = NULL, *fullpath = NULL;
    int ret = 0;

    if (access (temp_file_path, R_OK) != 0) {
        seaf_warning ("[put file] File %s doesn't exist or not readable.\n",
                      temp_file_path);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid input file");
        return -1;
    }

    GET_REPO_OR_FAIL(repo, repo_id);
    const char *base = head_id ? head_id : repo->head->commit_id;
    GET_COMMIT_OR_FAIL(head_commit, base);

    if (!canon_path)
        canon_path = get_canonical_path (parent_dir);

    if (should_ignore_file (file_name, NULL)) {
        seaf_warning ("[put file] Invalid filename %s.\n", file_name);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid filename");
        ret = -1;
        goto out;
    }

    if (strstr (parent_dir, "//") != NULL) {
        seaf_warning ("[put file] parent_dir cantains // sequence.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Invalid parent dir");
        ret = -1;
        goto out;
    }
    
    FAIL_IF_FILE_NOT_EXISTS(head_commit->root_id, canon_path, file_name, NULL);

    /* Write blocks. */
    if (repo->encrypted) {
        unsigned char key[16], iv[16];
        if (seaf_passwd_manager_get_decrypt_key_raw (seaf->passwd_mgr,
                                                     repo_id, user,
                                                     key, iv) < 0) {
            seaf_warning ("Passwd for repo %s is not set.\n", repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Passwd is not set");
            ret = -1;
            goto out;
        }
        crypt = seafile_crypt_new (repo->enc_version, key, iv);
    }

    if (seaf_fs_manager_index_blocks (seaf->fs_mgr, temp_file_path,
                                      sha1, crypt) < 0) {
        seaf_warning ("failed to index blocks");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to index blocks");
        ret = -1;
        goto out;
    }
        
    rawdata_to_hex(sha1, hex, 20);
    new_dent = seaf_dirent_new (hex, S_IFREG, file_name);

    if (!fullpath)
        fullpath = g_build_filename(parent_dir, file_name, NULL);

    old_file_id = seaf_fs_manager_path_to_obj_id (seaf->fs_mgr,
                                                   head_commit->root_id,
                                                   fullpath, NULL, NULL);

    if (g_strcmp0(old_file_id, new_dent->id) == 0) {
        *new_file_id = g_strdup(new_dent->id);
        goto out;
    }

    root_id = do_put_file (head_commit->root_id, canon_path, new_dent);
    if (!root_id) {
        seaf_warning ("[put file] Failed to put file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to put file");
        ret = -1;
        goto out;
    }

    /* Commit. */
    snprintf(buf, SEAF_PATH_MAX, "Modified \"%s\"", file_name);
    if (gen_new_commit (repo_id, head_commit, root_id, user, buf, error) < 0) {
        ret = -1;
        goto out;       
    }

    *new_file_id = g_strdup(new_dent->id);

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (new_dent)
        g_free (new_dent);
    g_free (root_id);
    g_free (canon_path);
    g_free (crypt);
    g_free (old_file_id);
    g_free (fullpath);

    if (ret == 0) {
        update_repo_size (repo_id);
    }

    return ret;
}

/* split filename into base and extension */
static void
filename_splitext (const char *filename,
                   char **base,
                   char **ext)
{
    char *dot = strrchr(filename, '.');
    if (!dot) {
        *base = g_strdup(filename);
        *ext = NULL;
    } else {
        *dot = '\0';
        *base = g_strdup(filename);
        *dot = '.';

        *ext = g_strdup(dot);
    }
}

static char *
revert_file_to_root (const char *root_id,
                     const char *filename,
                     const char *file_id,
                     gboolean *skipped,
                     GError **error)
{
    SeafDir *dir = NULL;
    SeafDirent *dent = NULL, *newdent = NULL;
    char *basename = NULL, *ext = NULL;
    char new_file_name[SEAF_PATH_MAX];
    char *new_root_id = NULL;
    int i = 1;
    GList *p;

    *skipped = FALSE;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                               root_id,
                                               "/", error);
    if (*error) {
        return NULL;
    }

    snprintf (new_file_name, sizeof(new_file_name), "%s", filename);

    filename_splitext(filename, &basename, &ext);
    for (;;) {
        for (p = dir->entries; p; p = p->next) {
            dent = p->data;
            if (strcmp(dent->name, new_file_name) != 0)
                continue;

            if (S_ISREG(dent->mode)) {
                /* same named file */
                if (strcmp(dent->id, file_id) == 0) {
                    *skipped = TRUE;
                    goto out;
                } else {
                    /* rename and retry */
                    snprintf (new_file_name, sizeof(new_file_name), "%s (%d)%s",
                              basename, i++, ext);
                    break;
                }
                
            } else if (S_ISDIR(dent->mode)) {
                /* rename and retry */
                snprintf (new_file_name, sizeof(new_file_name), "%s (%d)%s",
                          basename, i++, ext);
                break;
            }
        }

        if (p == NULL)
            break;
    }

    newdent = seaf_dirent_new (file_id, S_IFREG, new_file_name);
    new_root_id = do_post_file (root_id, "/", newdent);

out:
    if (dir)
        seaf_dir_free (dir);

    g_free (basename);
    g_free (ext);
    g_free (newdent);

    return new_root_id;
}

static char *
revert_file_to_parent_dir (const char *root_id,
                           const char *parent_dir,
                           const char *filename,
                           const char *file_id,
                           gboolean *skipped,
                           GError **error)
{
    SeafDir *dir = NULL;
    SeafDirent *dent = NULL, *newdent = NULL;
    char *basename = NULL, *ext = NULL;
    char new_file_name[SEAF_PATH_MAX];
    char *new_root_id = NULL;
    gboolean is_overwrite = FALSE;
    int i = 1;
    GList *p;
    
    *skipped = FALSE;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                               root_id,
                                               parent_dir, error);
    if (*error) {
        return NULL;
    }

    snprintf (new_file_name, sizeof(new_file_name), "%s", filename);
    filename_splitext(filename, &basename, &ext);
    while(TRUE) {
        for (p = dir->entries; p; p = p->next) {
            dent = p->data;
            if (strcmp(dent->name, new_file_name) != 0)
                continue;

            if (S_ISREG(dent->mode)) {
                /* same named file */
                if (strcmp(dent->id, file_id) == 0) {
                    *skipped = TRUE;
                    goto out;
                } else {
                    /* same name, different id: just overwrite */
                    is_overwrite = TRUE;
                    goto do_revert;
                }
                
            } else if (S_ISDIR(dent->mode)) {
                /* rename and retry */
                snprintf (new_file_name, sizeof(new_file_name), "%s (%d)%s",
                          basename, i++, ext);
                break;
            }
        }

        if (p == NULL)
            break;
    }

do_revert:    
    newdent = seaf_dirent_new (file_id, S_IFREG, new_file_name);
    if (is_overwrite) {
        new_root_id = do_put_file (root_id, parent_dir, newdent);
    } else {
        new_root_id = do_post_file (root_id, parent_dir, newdent);
    }

out:
    if (dir)
        seaf_dir_free (dir);

    g_free (basename);
    g_free (ext);
    g_free (newdent);

    return new_root_id;
}

static gboolean
detect_path_exist (const char *root_id,
                   const char *path,
                   GError **error)
{
    SeafDir *dir;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr, root_id, path, error);
    if (*error) {
        if (g_error_matches(*error, SEAFILE_DOMAIN, SEAF_ERR_PATH_NO_EXIST)) {
            /* path does not exist */
            g_clear_error(error);
            return FALSE;
        } else {
            /* Other error */
            return FALSE;
        }
    }

    seaf_dir_free(dir);
    return TRUE;
}

int
seaf_repo_manager_revert_file (SeafRepoManager *mgr,
                               const char *repo_id,
                               const char *old_commit_id,
                               const char *file_path,
                               const char *user,
                               GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL, *old_commit = NULL;
    char *parent_dir = NULL, *filename = NULL;
    char *revert_to_file_id = NULL;
    char *canon_path = NULL, *root_id = NULL;
    char buf[SEAF_PATH_MAX];
    char time_str[512];
    gboolean parent_dir_exist = FALSE;
    gboolean revert_to_root = FALSE;
    gboolean skipped = FALSE;
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    /* If old_commit_id is head commit, do nothing. */
    if (strcmp(repo->head->commit_id, old_commit_id) == 0) {
        g_debug ("[revert file] commit is head, do nothing\n");
        goto out;
    }

    if (!old_commit) {
        GET_COMMIT_OR_FAIL(old_commit, old_commit_id);
        if (strcmp(old_commit->repo_id, repo_id) != 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "bad commit id");
            ret = -1;
            goto out;
        }
    }

    if (!canon_path) {
        canon_path = get_canonical_path (file_path);
        if (canon_path[strlen(canon_path) -1 ] == '/') {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "bad target file path");
            ret = -1;
            goto out;
        }

        revert_to_file_id = seaf_fs_manager_get_seafile_id_by_path (
                    seaf->fs_mgr, old_commit->root_id, canon_path, error);
        if (*error) {
            seaf_warning ("[revert file] error: %s\n", (*error)->message);
            g_clear_error (error);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "internal error");
            ret = -1;
            goto out;
        }

        parent_dir  = g_path_get_dirname(canon_path);
        filename = g_path_get_basename(canon_path);
    }

    parent_dir_exist = detect_path_exist (head_commit->root_id,
                                          parent_dir, error);
    if (*error) {
        seaf_warning ("[revert file] error: %s\n", (*error)->message);
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "internal error");
        ret = -1;
        goto out;
    }
    
    if (!parent_dir_exist) {
        /* When parent dir does not exist, revert this file to root dir. */
        revert_to_root = TRUE;
        root_id = revert_file_to_root (head_commit->root_id,
                                       filename,
                                       revert_to_file_id,
                                       &skipped, error);
    } else {
        revert_to_root = FALSE;
        root_id = revert_file_to_parent_dir (head_commit->root_id, parent_dir,
                                             filename, revert_to_file_id,
                                             &skipped, error);
    }

    if (*error) {
        seaf_warning ("[revert file] error: %s\n", (*error)->message);
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "internal error");
        ret = -1;
        goto out;
    }

    if (skipped) {
        goto out;
    }
    
    if (!root_id) {
        seaf_warning ("[revert file] Failed to revert file.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to revert file");
        ret = -1;
        goto out;
    }

    /* Commit. */
#ifndef WIN32
    strftime (time_str, sizeof(time_str), "%F %T",
              localtime((time_t *)(&old_commit->ctime)));
#else
    strftime (time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S",
              localtime((time_t *)(&old_commit->ctime)));
#endif
    snprintf(buf, SEAF_PATH_MAX, "Reverted file \"%s\" to status at %s", filename, time_str);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (old_commit)
        seaf_commit_unref (old_commit);

    g_free (root_id);
    g_free (parent_dir);
    g_free (filename);

    g_free (canon_path);
    g_free (revert_to_file_id);

#define REVERT_TO_ROOT              0x1
    if (ret == 0) {
        if (revert_to_root)
            ret |= REVERT_TO_ROOT;
    }

    return ret;
}

static char *
revert_dir (const char *root_id,
            const char *parent_dir,
            const char *dirname,
            const char *dir_id,
            gboolean *skipped,
            GError **error)
{
    SeafDir *dir = NULL;
    SeafDirent *dent = NULL, *newdent = NULL;
    char new_dir_name[SEAF_PATH_MAX];
    char *new_root_id = NULL;
    int i = 1;
    GList *p;

    *skipped = FALSE;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                               root_id,
                                               parent_dir, error);
    if (*error) {
        return NULL;
    }

    snprintf (new_dir_name, sizeof(new_dir_name), "%s", dirname);

    for (;;) {
        for (p = dir->entries; p; p = p->next) {
            dent = p->data;
            if (strcmp(dent->name, new_dir_name) != 0)
                continue;

            /* the same dir */
            if (S_ISDIR(dent->mode) && strcmp(dent->id, dir_id) == 0) {
                *skipped = TRUE;
                goto out;
            } else {
                /* rename and retry */
                snprintf (new_dir_name, sizeof(new_dir_name), "%s (%d)",
                          dirname, i++);
                break;
            }
        }

        if (p == NULL)
            break;
    }

    newdent = seaf_dirent_new (dir_id, S_IFDIR, new_dir_name);
    new_root_id = do_post_file (root_id, parent_dir, newdent);

out:
    if (dir)
        seaf_dir_free (dir);

    g_free (newdent);

    return new_root_id;
}

int
seaf_repo_manager_revert_dir (SeafRepoManager *mgr,
                              const char *repo_id,
                              const char *old_commit_id,
                              const char *dir_path,
                              const char *user,
                              GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL, *old_commit = NULL;
    char *parent_dir = NULL, *dirname = NULL;
    char *revert_to_dir_id = NULL;
    char *canon_path = NULL, *root_id = NULL;
    char buf[SEAF_PATH_MAX];
    gboolean parent_dir_exist = FALSE;
    gboolean revert_to_root = FALSE;
    gboolean skipped = FALSE;
    int ret = 0;

    GET_REPO_OR_FAIL(repo, repo_id);
    GET_COMMIT_OR_FAIL(head_commit, repo->head->commit_id);

    /* If old_commit_id is head commit, do nothing. */
    if (strcmp(repo->head->commit_id, old_commit_id) == 0) {
        g_debug ("[revert dir] commit is head, do nothing\n");
        goto out;
    }

    if (!old_commit) {
        GET_COMMIT_OR_FAIL(old_commit, old_commit_id);
        if (strcmp(old_commit->repo_id, repo_id) != 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT,
                         "bad commit id");
            ret = -1;
            goto out;
        }
    }

    if (!canon_path) {
        canon_path = get_canonical_path (dir_path);

        revert_to_dir_id = seaf_fs_manager_get_seafdir_id_by_path (
                    seaf->fs_mgr, old_commit->root_id, canon_path, error);
        if (*error) {
            seaf_warning ("[revert dir] error: %s\n", (*error)->message);
            g_clear_error (error);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "internal error");
            ret = -1;
            goto out;
        }

        parent_dir  = g_path_get_dirname(canon_path);
        dirname = g_path_get_basename(canon_path);
    }

    parent_dir_exist = detect_path_exist (head_commit->root_id,
                                          parent_dir, error);
    if (*error) {
        seaf_warning ("[revert dir] error: %s\n", (*error)->message);
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "internal error");
        ret = -1;
        goto out;
    }
    
    if (!parent_dir_exist) {
        /* When parent dir does not exist, revert this file to root dir. */
        revert_to_root = TRUE;
        root_id = revert_dir (head_commit->root_id,
                              "/",
                              dirname,
                              revert_to_dir_id,
                              &skipped, error);
    } else {
        revert_to_root = FALSE;
        root_id = revert_dir (head_commit->root_id,
                              parent_dir,
                              dirname,
                              revert_to_dir_id,
                              &skipped, error);
    }

    if (*error) {
        seaf_warning ("[revert dir] error: %s\n", (*error)->message);
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "internal error");
        ret = -1;
        goto out;
    }

    if (skipped) {
        goto out;
    }
    
    if (!root_id) {
        seaf_warning ("[revert dir] Failed to revert dir.\n");
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to revert dir");
        ret = -1;
        goto out;
    }

    /* Commit. */
    snprintf(buf, SEAF_PATH_MAX, "Recovered deleted directory \"%s\"", dirname);
    if (gen_new_commit (repo_id, head_commit, root_id,
                        user, buf, error) < 0)
        ret = -1;

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref (head_commit);
    if (old_commit)
        seaf_commit_unref (old_commit);

    g_free (root_id);
    g_free (parent_dir);
    g_free (dirname);

    g_free (canon_path);
    g_free (revert_to_dir_id);

#define REVERT_TO_ROOT              0x1
    if (ret == 0) {
        if (revert_to_root)
            ret |= REVERT_TO_ROOT;
    }

    return ret;
}

typedef struct CollectRevisionParam CollectRevisionParam;

struct CollectRevisionParam {
    const char *path;
    GHashTable *wanted_commits;
    GHashTable *file_id_cache;
    
    /* 
     * > 0: stop collect when this amount of revisions are collected.
     * <= 0: no limit
     */
    int max_revision;

    /* > 0: keep a period of history;
     * == 0: N/A
     * < 0: keep all history data.
     */
    gint64 truncate_time;
    gboolean got_latest;

    GError **error;
};

static char *
get_file_id_with_cache (SeafCommit *commit,
                        const char *path,
                        GHashTable *file_id_cache,
                        GError **error)
{
    char *file_id = NULL;
    guint32 mode;

    file_id = g_hash_table_lookup (file_id_cache, commit->commit_id);
    if (file_id) {
        return g_strdup(file_id);
    }

    file_id = seaf_fs_manager_path_to_obj_id (seaf->fs_mgr,
                    commit->root_id, path, &mode, error);

    if (file_id != NULL) {
        if (S_ISDIR(mode)) {
            g_free (file_id);
            return NULL;

        } else {
            g_hash_table_insert (file_id_cache,
                                 g_strdup(commit->commit_id),
                                 g_strdup(file_id));
            return file_id;
        }
    }

    return NULL;
}

static gboolean
collect_file_revisions (SeafCommit *commit, void *vdata, gboolean *stop)
{
    CollectRevisionParam *data = vdata;
    const char *path = data->path;
    GError **error = data->error;
    GHashTable *wanted_commits = data->wanted_commits;
    GHashTable *file_id_cache = data->file_id_cache;

    SeafCommit *parent_commit = NULL;
    SeafCommit *parent_commit2 = NULL;
    char *file_id = NULL;
    char *parent_file_id = NULL;
    char *parent_file_id2 = NULL;

    gboolean ret = TRUE;

    /* At least find the latest revision. */
    if (data->got_latest && data->truncate_time == 0) {
        *stop = TRUE;
        return TRUE;
    }

    if (data->got_latest &&
        data->truncate_time > 0 &&
        (gint64)(commit->ctime) < data->truncate_time)
    {
        *stop = TRUE;
        return TRUE;
    }

    if (data->max_revision > 0
        && g_hash_table_size(wanted_commits) > data->max_revision) {
        *stop = TRUE;
        return TRUE;
    }

    file_id = get_file_id_with_cache (commit, path,
                                      file_id_cache, error);
    if (*error) {
        ret = FALSE;
        goto out;
    }

    if (!file_id) {
        /* Target file is not present in this commit. */
        goto out;
    }

    if (!commit->parent_id) {
        /* Initial commit */
        seaf_commit_ref (commit);
        g_hash_table_insert (wanted_commits, commit->commit_id, commit);
        goto out;
    }

    parent_commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             commit->parent_id);
    if (!parent_commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Faild to get commit %s", commit->parent_id);
        ret = FALSE;
        goto out;
    }

    parent_file_id = get_file_id_with_cache (parent_commit,
                                             path, file_id_cache, error);
    if (*error) {
        ret = FALSE;
        goto out;
    }

    if (g_strcmp0 (parent_file_id, file_id) == 0) {
        /* This commit does not modify the target file */
        goto out;
    }

    /* In case of a merge, the second parent also need compare */
    if (commit->second_parent_id) {
        parent_commit2 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                 commit->second_parent_id);
        if (!parent_commit2) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                         "Faild to get commit %s", commit->second_parent_id);
            ret = FALSE;
            goto out;
        }

        parent_file_id2 = get_file_id_with_cache (parent_commit2,
                                                  path, file_id_cache, error);
        if (*error) {
            ret = FALSE;
            goto out;
        }

        if (g_strcmp0 (parent_file_id2, file_id) == 0) {
            /* This commit does not modify the target file */
            goto out;
        }
    }

    if (!data->got_latest)
        data->got_latest = TRUE;

    seaf_commit_ref (commit);
    g_hash_table_insert (wanted_commits, commit->commit_id, commit);

out:
    g_free (file_id);
    g_free (parent_file_id);
    g_free (parent_file_id2);

    if (parent_commit) seaf_commit_unref (parent_commit);
    if (parent_commit2) seaf_commit_unref (parent_commit2);

    return ret;
}

static int
compare_commit_by_time (const SeafCommit *a, const SeafCommit *b)
{
    /* Latest commit comes first in the list. */
    return (b->ctime - a->ctime);
}

GList *
seaf_repo_manager_list_file_revisions (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       const char *path,
                                       int max_revision,
                                       int limit,
                                       GError **error)
{
    SeafRepo *repo = NULL;
    GList *commit_list = NULL;
    CollectRevisionParam data = {0};

    repo = seaf_repo_manager_get_repo (mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "No such repo %s", repo_id);
        goto out;
    }

    data.path = path;
    data.error = error;
    data.max_revision = max_revision;

    data.truncate_time = seaf_repo_manager_get_repo_truncate_time (mgr, repo_id);

    /* A (commit id, commit) hash table. We specify a value destroy
     * function, so that even if we fail in half way of traversing, we can
     * free all commits in the hashtbl.*/
    data.wanted_commits = g_hash_table_new_full (g_str_hash, g_str_equal,
                            NULL, (GDestroyNotify)seaf_commit_unref);

    /* A hash table to cache caculated file id of <path> in <commit> */
    data.file_id_cache = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, g_free);

    if (!seaf_commit_manager_traverse_commit_tree_with_limit (seaf->commit_mgr,
                                                        repo->head->commit_id,
                                                        (CommitTraverseFunc)collect_file_revisions,
                                                              limit, &data)) {
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "failed to traverse commit of repo %s", repo_id);
        goto out;
    }

    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, data.wanted_commits);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        SeafCommit *commit = value;
        seaf_commit_ref (commit);
        commit_list = g_list_insert_sorted (commit_list, commit,
                                            (GCompareFunc)compare_commit_by_time);
    }

out:
    if (repo)
        seaf_repo_unref (repo);
    if (data.wanted_commits)
        g_hash_table_destroy (data.wanted_commits);
    if (data.file_id_cache)
        g_hash_table_destroy (data.file_id_cache);

    return commit_list;
}

typedef struct CalcFilesLastModifiedParam CalcFilesLastModifiedParam;

struct CalcFilesLastModifiedParam {
    GError **error;
    const char *parent_dir;
    GHashTable *last_modified_hash;
    GHashTable *current_file_id_hash;
    SeafCommit *current_commit;
};

static gboolean
check_non_existing_files (void *key, void *value, void *vdata)
{
    CalcFilesLastModifiedParam *data = vdata;
    gboolean remove = FALSE;
    
    char *file_name = key;
    gint64 *ctime = g_hash_table_lookup (data->last_modified_hash, file_name);
    if (!ctime) {
        /* Impossible */
        remove = TRUE;
    } else if (*ctime != data->current_commit->ctime) {
        /* This file does not exist in this commit. So it's last modified in
         * the previous commit.
         */
        remove = TRUE;
    }

    return remove;
}

static gboolean
collect_files_last_modified (SeafCommit *commit, void *vdata, gboolean *stop)
{
    CalcFilesLastModifiedParam *data = vdata;
    GError **error = data->error;
    SeafDirent *dent = NULL;
    char *file_id = NULL;
    SeafDir *dir = NULL;
    GList *ptr;
    gboolean ret = TRUE;

    data->current_commit = commit;
    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr,
                                               commit->root_id,
                                               data->parent_dir,
                                               error);
    if (*error) {
        if (!g_error_matches(*error, SEAFILE_DOMAIN, SEAF_ERR_PATH_NO_EXIST)) {
            *stop = TRUE;
            ret = FALSE;
            goto out;
        } else {
            g_clear_error (error);
        }
    }

    if (!dir) {
        /* The directory does not exist in this commit. So all files are last
         * modified in the previous commit;
         */
        *stop = TRUE;
        goto out;
    }

    for (ptr = dir->entries; ptr; ptr = ptr->next) {
        dent = ptr->data;
        file_id = g_hash_table_lookup (data->current_file_id_hash, dent->name);
        if (file_id) {
            if (strcmp(file_id, dent->id) != 0) {
                g_hash_table_remove (data->current_file_id_hash, dent->name);
            } else {
                gint64 *ctime = g_new (gint64, 1);
                *ctime = commit->ctime;
                g_hash_table_replace (data->last_modified_hash, g_strdup(dent->name), ctime);
            }
        }

        if (g_hash_table_size(data->current_file_id_hash) == 0) {
            *stop = TRUE;
            goto out;
        }
    }

    /* Files not found in the current commit are last modified in the previous
     * commit */
    g_hash_table_foreach_remove (data->current_file_id_hash,
                                 check_non_existing_files, data);

    if (g_hash_table_size(data->current_file_id_hash) == 0) {
        /* All files under this diretory have been calculated  */
        *stop = TRUE;
        goto out;
    }

out:
    seaf_dir_free (dir);

    return ret;
}

/**
 * Give a directory, return the last modification timestamps of all the files
 * under this directory.
 *
 * First we record the current id of every file, then traverse the commit
 * tree. Give a commit, for each file, if the file id in that commit is
 * different than its current id, then this file is last modified in the
 * commit previous to that commit.
 */
GList *
seaf_repo_manager_calc_files_last_modified (SeafRepoManager *mgr,
                                            const char *repo_id,
                                            const char *parent_dir,
                                            int limit,
                                            GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    SeafDir *dir = NULL;
    GList *ptr = NULL;
    SeafDirent *dent = NULL; 
    CalcFilesLastModifiedParam data = {0};
    GList *ret_list = NULL;

    repo = seaf_repo_manager_get_repo (mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "No such repo %s", repo_id);
        goto out;
    }

    head_commit = seaf_commit_manager_get_commit (seaf->commit_mgr, repo->head->commit_id);
    if (!head_commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Failed to get commit %s", repo->head->commit_id);
        goto out;
    }

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr, head_commit->root_id,
                                               parent_dir, error);
    if (*error || !dir) {
        goto out;
    }
    
    /* A hash table of pattern (file_name, current_file_id) */
    data.current_file_id_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                       g_free, g_free);
    /* A (file_name, last_modified) hashtable. <last_modified> is a heap
       allocated gint64
    */
    data.last_modified_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                     g_free, g_free);
    for (ptr = dir->entries; ptr; ptr = ptr->next) {
        dent = ptr->data;
        g_hash_table_insert (data.current_file_id_hash,
                             g_strdup(dent->name),
                             g_strdup(dent->id));

        gint64 *ctime = g_new (gint64, 1);
        *ctime = head_commit->ctime;
        g_hash_table_insert (data.last_modified_hash,
                             g_strdup(dent->name), 
                             ctime);
    }

    if (g_hash_table_size (data.current_file_id_hash) == 0) {
        /* An empty directory, no need to traverse */
        goto out;
    }

    data.parent_dir = parent_dir;
    data.error = error;

    if (!seaf_commit_manager_traverse_commit_tree_with_limit (seaf->commit_mgr,
                                                        repo->head->commit_id,
                                (CommitTraverseFunc)collect_files_last_modified,
                                                              limit, &data)) {
        seaf_warning ("error when travsersing commits: %s\n", (*error)->message);
        g_clear_error (error);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "failed to traverse commit of repo %s", repo_id);
        goto out;
    }

    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init (&iter, data.last_modified_hash);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        SeafileFileLastModifiedInfo *info;
        gint64 last_modified = *(gint64 *)value;
        info = g_object_new (SEAFILE_TYPE_FILE_LAST_MODIFIED_INFO,
                             "file_name", key,
                             "last_modified", last_modified,
                             NULL);
        ret_list = g_list_prepend (ret_list, info);
    }

out:
    if (repo)
        seaf_repo_unref (repo);
    if (head_commit)
        seaf_commit_unref(head_commit);
    if (data.last_modified_hash)
        g_hash_table_destroy (data.last_modified_hash);
    if (data.current_file_id_hash)
        g_hash_table_destroy (data.current_file_id_hash);
    if (dir)
        seaf_dir_free (dir);

    return g_list_reverse(ret_list);
}

int
seaf_repo_manager_revert_on_server (SeafRepoManager *mgr,
                                    const char *repo_id,
                                    const char *commit_id,
                                    const char *user_name,
                                    GError **error)
{
    SeafRepo *repo;
    SeafCommit *commit, *new_commit;
    char desc[512];
    int ret = 0;

retry:
    repo = seaf_repo_manager_get_repo (mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "No such repo");
        return -1;
    }

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr, commit_id);
    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Commit doesn't exist");
        ret = -1;
        goto out;
    }

#ifndef WIN32
    strftime (desc, sizeof(desc), "Reverted repo to status at %F %T.", 
              localtime((time_t *)(&commit->ctime)));
#else
    strftime (desc, sizeof(desc), "Reverted repo to status at %%Y-%m-%d %H:%M:%S.", 
              localtime((time_t *)(&commit->ctime)));
#endif

    new_commit = seaf_commit_new (NULL, repo->id, commit->root_id,
                                  user_name, EMPTY_SHA1,
                                  desc, 0);

    new_commit->parent_id = g_strdup (repo->head->commit_id);

    seaf_repo_to_commit (repo, new_commit);

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, new_commit) < 0) {
        ret = -1;
        goto out;
    }

    seaf_branch_set_commit (repo->head, new_commit->commit_id);
    if (seaf_branch_manager_test_and_update_branch (seaf->branch_mgr,
                                                    repo->head,
                                                    new_commit->parent_id) < 0)
    {
        seaf_warning ("[revert] Concurrent branch update, retry.\n");
        seaf_repo_unref (repo);
        seaf_commit_unref (commit);
        seaf_commit_unref (new_commit);
        repo = NULL;
        commit = new_commit = NULL;
        goto retry;
    }

out:
    if (new_commit)
        seaf_commit_unref (new_commit);
    if (commit)
        seaf_commit_unref (commit);
    if (repo)
        seaf_repo_unref (repo);

    if (ret == 0) {
        update_repo_size (repo_id);
    }

    return ret;
}

static void
add_deleted_entry (GHashTable *entries,
                   SeafDirent *dent,
                   const char *base,
                   SeafCommit *child,
                   SeafCommit *parent)
{
    char *path = g_strconcat (base, dent->name, NULL);
    SeafileDeletedEntry *entry;
    Seafile *file;

    if (g_hash_table_lookup (entries, path) != NULL) {
        /* g_debug ("found dup deleted entry for %s.\n", path); */
        g_free (path);
        return;
    }

    /* g_debug ("Add deleted entry for %s.\n", path); */

    entry = g_object_new (SEAFILE_TYPE_DELETED_ENTRY,
                          "commit_id", parent->commit_id,
                          "obj_id", dent->id,
                          "obj_name", dent->name,
                          "basedir", base,
                          "mode", dent->mode,
                          "delete_time", child->ctime,
                          NULL);

    if (S_ISREG(dent->mode)) {
        file = seaf_fs_manager_get_seafile (seaf->fs_mgr, dent->id);
        if (!file) {
            g_free (path);
            g_object_unref (entry);
            return;
        }
        g_object_set (entry, "file_size", file->file_size, NULL);
    }

    g_hash_table_insert (entries, path, entry);
}

static int
find_deleted_recursive (const char *root1,
                        const char *root2,
                        const char *base,
                        SeafCommit *child,
                        SeafCommit *parent,
                        GHashTable *entries)
{
    SeafDir *d1, *d2;
    GList *p1, *p2;
    SeafDirent *dent1, *dent2;
    int res, ret = 0;

    if (strcmp (root1, root2) == 0)
        return 0;

    d1 = seaf_fs_manager_get_seafdir_sorted (seaf->fs_mgr, root1);
    if (!d1) {
        seaf_warning ("Failed to find dir %s.\n", root1);
        return -1;
    }
    d2 = seaf_fs_manager_get_seafdir_sorted (seaf->fs_mgr, root2);
    if (!d2) {
        seaf_warning ("Failed to find dir %s.\n", root2);
        seaf_dir_free (d1);
        return -1;
    }

    p1 = d1->entries;
    p2 = d2->entries;

    /* Since dirents are sorted in descending order, we can use merge
     * algorithm to find out deleted entries.
     * Deleted entries are those:
     * 1. exists in d2 but absent in d1.
     * 2. exists in both d1 and d2 but with different type.
     */

    while (p1 && p2) {
        dent1 = p1->data;
        dent2 = p2->data;

        res = g_strcmp0 (dent1->name, dent2->name);
        if (res < 0) {
            /* exists in d2 but absent in d1. */
            add_deleted_entry (entries, dent2, base, child, parent);
            p2 = p2->next;
        } else if (res == 0) {
            if ((dent1->mode & S_IFMT) != (dent2->mode & S_IFMT)) {
                /* both exists but with diffent type. */
                add_deleted_entry (entries, dent2, base, child, parent);
            } else if (S_ISDIR(dent1->mode)) {
                char *new_base = g_strconcat (base, dent1->name, "/", NULL);
                ret = find_deleted_recursive (dent1->id, dent2->id, new_base,
                                              child, parent, entries);
                g_free (new_base);
                if (ret < 0)
                    goto out;
            }
            p1 = p1->next;
            p2 = p2->next;
        } else {
            p1 = p1->next;
        }
    }

    for ( ; p2 != NULL; p2 = p2->next) {
        dent2 = p2->data;
        add_deleted_entry (entries, dent2, base, child, parent);
    }

out:
    seaf_dir_free (d1);
    seaf_dir_free (d2);
    return ret;
}

typedef struct CollectDelData {
    GHashTable *entries;
    gint64 truncate_time;
} CollectDelData;

#define DEFAULT_RECYCLE_DAYS 7

static gboolean
collect_deleted (SeafCommit *commit, void *vdata, gboolean *stop)
{
    CollectDelData *data = vdata;
    GHashTable *entries = data->entries;
    gint64 truncate_time = data->truncate_time;
    SeafCommit *p1, *p2;

    if ((gint64)(commit->ctime) < truncate_time) {
        *stop = TRUE;
        return TRUE;
    }

    if (commit->parent_id == NULL)
        return TRUE;

    p1 = seaf_commit_manager_get_commit (commit->manager, commit->parent_id);
    if (!p1) {
        seaf_warning ("Failed to find commit %s.\n", commit->parent_id);
        return FALSE;
    }
    if ((gint64)(p1->ctime) >= truncate_time) {
        if (find_deleted_recursive (commit->root_id, p1->root_id, "/",
                                    commit, p1, entries) < 0) {
            seaf_commit_unref (p1);
            return FALSE;
        }
    }
    seaf_commit_unref (p1);

    if (commit->second_parent_id) {
        p2 = seaf_commit_manager_get_commit (commit->manager,
                                             commit->second_parent_id);
        if (!p2) {
            seaf_warning ("Failed to find commit %s.\n",
                          commit->second_parent_id);
            return FALSE;
        }
        if ((gint64)(p2->ctime) >= truncate_time) {
            if (find_deleted_recursive (commit->root_id, p2->root_id, "/",
                                        commit, p2, entries) < 0) {
                seaf_commit_unref (p2);
                return FALSE;
            }
        }
        seaf_commit_unref (p2);
    }

    return TRUE;
}

static gboolean
remove_existing (gpointer key, gpointer value, gpointer user_data)
{
    SeafileDeletedEntry *e = value;
    SeafCommit *head = user_data;
    guint32 mode = seafile_deleted_entry_get_mode(e), mode_out = 0;
    char *path = key;

    char *obj_id = seaf_fs_manager_path_to_obj_id (seaf->fs_mgr, head->root_id,
                                                    path, &mode_out, NULL);
    if (obj_id == NULL)
        return FALSE;
    g_free (obj_id);

    /* If path exist in head commit and with the same type,
     * remove it from deleted entries.
     */
    if ((mode & S_IFMT) == (mode_out & S_IFMT)) {
        /* g_debug ("%s exists in head commit.\n", path); */
        return TRUE;
    }

    return FALSE;
}

static int
filter_out_existing_entries (GHashTable *entries, const char *head_id)
{
    SeafCommit *head;

    head = seaf_commit_manager_get_commit (seaf->commit_mgr, head_id);
    if (!head) {
        seaf_warning ("Failed to find head commit %s.\n", head_id);
        return -1;
    }

    g_hash_table_foreach_remove (entries, remove_existing, head);

    seaf_commit_unref (head);
    return 0;
}

static gboolean
hash_to_list (gpointer key, gpointer value, gpointer user_data)
{
    GList **plist = (GList **)user_data;

    g_free (key);
    *plist = g_list_prepend (*plist, value);

    return TRUE;
}

GList *
seaf_repo_manager_get_deleted_entries (SeafRepoManager *mgr,
                                       const char *repo_id,
                                       int show_days,
                                       GError **error)
{
    SeafRepo *repo;
    gint64 truncate_time, show_time;
    GList *ret = NULL;

    truncate_time = seaf_repo_manager_get_repo_truncate_time (mgr, repo_id);
    if (truncate_time == 0)
        return NULL;

    if (show_days <= 0)
        show_time = -1;
    else
        show_time = (gint64)time(NULL) - show_days * 24 * 3600;

    repo = seaf_repo_manager_get_repo (mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Invalid repo id");
        return NULL;
    }

    CollectDelData data = {0};
    GHashTable *entries = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                 g_free, g_object_unref);
    data.entries = entries;
    data.truncate_time = MAX (show_time, truncate_time);

    if (!seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                   repo->head->commit_id,
                                                   collect_deleted,
                                                   &data))
    {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Internal error");
        g_hash_table_destroy (entries);
        seaf_repo_unref (repo);
        return NULL;
    }

    /* Remove entries exist in the current commit.
     * This is necessary because some files may be added back after deletion.
     */
    filter_out_existing_entries (entries, repo->head->commit_id);

    g_hash_table_foreach_steal (entries, hash_to_list, &ret);
    g_hash_table_destroy (entries);

    return ret;
}



static SeafCommit *
get_commit(SeafRepo *repo, const char *branch_or_commit)
{
    SeafBranch *b;
    SeafCommit *c;

    b = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id,
                                        branch_or_commit);
    if (!b) {
        if (strcmp(branch_or_commit, "HEAD") == 0)
            c = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                repo->head->commit_id);
        else
            c = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                branch_or_commit);
    } else {
        c = seaf_commit_manager_get_commit (seaf->commit_mgr, b->commit_id);
    }

    if (b)
        seaf_branch_unref (b);
    
    return c;
}

GList *
seaf_repo_diff (SeafRepo *repo, const char *old, const char *new, char **error)
{
    SeafCommit *c1 = NULL, *c2 = NULL;
    int ret = 0;
    GList *diff_entries = NULL;

    g_return_val_if_fail (*error == NULL, NULL);

    c2 = get_commit (repo, new);
    if (!c2) {
        *error = g_strdup("Can't find new commit");
        return NULL;
    }
    
    if (old == NULL || old[0] == '\0') {
        if (c2->parent_id && c2->second_parent_id) {
            ret = diff_merge (c2, &diff_entries);
            if (ret < 0) {
                *error = g_strdup("Failed to do diff");
                seaf_commit_unref (c2);
                return NULL;
            }
            seaf_commit_unref (c2);
            return diff_entries;
        }

        if (!c2->parent_id) {
            seaf_commit_unref (c2);
            return NULL;
        }
        c1 = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             c2->parent_id);
    } else {
        c1 = get_commit (repo, old);
    }

    if (!c1) {
        *error = g_strdup("Can't find old commit");
        seaf_commit_unref (c2);
        return NULL;
    }

    /* do diff */
    ret = diff_commits (c1, c2, &diff_entries);
    if (ret < 0)
        *error = g_strdup("Failed to do diff");

    seaf_commit_unref (c1);
    seaf_commit_unref (c2);

    return diff_entries;
}
