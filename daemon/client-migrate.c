
#ifdef WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x500
#endif
#include <windows.h>

#endif  /* WIN32 */

#include "common.h"

#include "seafile-session.h"
#include "client-migrate.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

typedef struct {
    SeafRepo *repo;
    GHashTable *visited;
    char remote_end_commit[41];
    char local_end_commit[41];

    int traversed_commits;
    gint64 traversed_blocks;
    gboolean migrate_block_failed;
} GCData;

static char *block_dir;
static char *v0_block_dir;

static char *
get_block_path (const char *block_sha1,
                char path[],
                const char *store_id,
                int version)
{
    char *pos = path;
    int n;

    if (version > 0) {
        n = snprintf (path, SEAF_PATH_MAX, "%s/%s/", block_dir, store_id);
        pos += n;
    } else {
        n = snprintf (path, SEAF_PATH_MAX, "%s/", v0_block_dir);
        pos += n;
    }

    memcpy (pos, block_sha1, 2);
    pos[2] = '/';
    pos += 3;

    memcpy (pos, block_sha1 + 2, 41 - 2);

    return path;
}

static int
create_parent_path (const char *path)
{
    char *dir = g_path_get_dirname (path);
    if (!dir)
        return -1;

    if (g_file_test (dir, G_FILE_TEST_EXISTS)) {
        g_free (dir);
        return 0;
    }

    if (g_mkdir_with_parents (dir, 0777) < 0) {
        seaf_warning ("Failed to create object parent path: %s.\n", dir);
        g_free (dir);
        return -1;
    }

    g_free (dir);
    return 0;
}

static int
migrate_block (const char *repo_id,
               const char *block_id)
{
    char src_path[SEAF_PATH_MAX];
    char dst_path[SEAF_PATH_MAX];

    get_block_path (block_id, src_path, repo_id, 0);
    get_block_path (block_id, dst_path, repo_id, 1);

    /* If src block doesn't exist, no need to migrate. */
    if (!g_file_test (src_path, G_FILE_TEST_EXISTS))
        return 0;

    if (g_file_test (dst_path, G_FILE_TEST_EXISTS))
        return 0;

    if (create_parent_path (dst_path) < 0) {
        seaf_warning ("Failed to create dst path %s for block %s.\n",
                      dst_path, block_id);
        return -1;
    }

#ifdef WIN32
    if (!CreateHardLink (dst_path, src_path, NULL)) {
        seaf_warning ("Failed to link %s to %s: %d.\n",
                      src_path, dst_path, GetLastError());
        return -1;
    }
    return 0;
#else
    int ret = link (src_path, dst_path);
    if (ret < 0 && errno != EEXIST) {
        seaf_warning ("Failed to link %s to %s: %s.\n",
                      src_path, dst_path, strerror(errno));
        return -1;
    }
    return ret;
#endif
}

static int
migrate_blocks (SeafFSManager *mgr,
                const char *repo_id, int repo_version,
                GCData *data, const char *file_id)
{
    Seafile *seafile;
    int i;

    seafile = seaf_fs_manager_get_seafile (mgr,
                                           repo_id,
                                           repo_version,
                                           file_id);
    if (!seafile) {
        seaf_warning ("Failed to find file %s.\n", file_id);
        return 0;
    }

    for (i = 0; i < seafile->n_blocks; ++i) {
        if (migrate_block (repo_id, seafile->blk_sha1s[i]) < 0)
            data->migrate_block_failed = TRUE;
        ++data->traversed_blocks;
    }

    seafile_unref (seafile);

    return 0;
}

static gboolean
fs_callback (SeafFSManager *mgr,
             const char *repo_id,
             int version,
             const char *obj_id,
             int type,
             void *user_data,
             gboolean *stop)
{
    GCData *data = user_data;

    if (data->visited != NULL) {
        if (g_hash_table_lookup (data->visited, obj_id) != NULL) {
            *stop = TRUE;
            return TRUE;
        }

        char *key = g_strdup(obj_id);
        g_hash_table_insert (data->visited, key, key);
    }

    if (type == SEAF_METADATA_TYPE_FILE &&
        migrate_blocks (mgr, repo_id, version, data, obj_id) < 0)
        return FALSE;

    return TRUE;
}

static gboolean
traverse_commit (SeafCommit *commit, void *vdata, gboolean *stop)
{
    GCData *data = vdata;

    if (strcmp (commit->commit_id, data->local_end_commit) == 0 ||
        strcmp (commit->commit_id, data->remote_end_commit) == 0) {
        *stop = TRUE;
        return TRUE;
    }

    seaf_debug ("Traversed commit %.8s.\n", commit->commit_id);
    ++data->traversed_commits;

    seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                   data->repo->id,
                                   data->repo->version,
                                   commit->root_id,
                                   fs_callback,
                                   data, TRUE);

    return TRUE;
}

static int
migrate_repo_blocks (SeafRepo *repo)
{
    GList *branches, *ptr;
    SeafBranch *branch;
    GCData *data;
    int ret = 0;

    seaf_message ("Migrating blocks for repo %s(%.8s).\n", repo->name, repo->id);

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        seaf_warning ("Failed to get branch list of repo %s.\n", repo->id);
        return -1;
    }

    data = g_new0(GCData, 1);
    data->repo = repo;
    data->visited = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    char *remote_head = seaf_repo_manager_get_repo_property (repo->manager,
                                                             repo->id,
                                                             REPO_REMOTE_HEAD);
    if (remote_head)
        memcpy (data->remote_end_commit, remote_head, 41);
    g_free (remote_head);

    char *local_head = seaf_repo_manager_get_repo_property (repo->manager,
                                                            repo->id,
                                                            REPO_LOCAL_HEAD);
    if (local_head)
        memcpy (data->local_end_commit, local_head, 41);
    g_free (local_head);

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        seaf_commit_manager_traverse_commit_tree_truncated (seaf->commit_mgr,
                                                            repo->id,
                                                            repo->version,
                                                            branch->commit_id,
                                                            traverse_commit,
                                                            data,
                                                            TRUE);
        seaf_branch_unref (branch);
    }

    if (data->migrate_block_failed)
        ret = -1;

    seaf_message ("Traversed %d commits, %"G_GINT64_FORMAT" blocks.\n",
                  data->traversed_commits, data->traversed_blocks);

    g_list_free (branches);
    g_hash_table_destroy (data->visited);
    g_free (data);

    return ret;
}

static int
remove_recursive (const char *dir_path)
{
    GDir *dir;
    const char *dname;
    char *sub_path;
    SeafStat st;
    GError *error = NULL;
    int ret = 0;

    dir = g_dir_open (dir_path, 0, &error);
    if (!dir) {
        seaf_warning ("Failed to open dir %s: %s.\n", dir_path, error->message);
        g_clear_error (&error);
        return -1;
    }

    while ((dname = g_dir_read_name(dir)) != NULL) {
        sub_path = g_build_filename (dir_path, dname, NULL);
        if (seaf_stat (sub_path, &st) < 0) {
            seaf_warning ("Failed to stat %s: %s.\n", sub_path, strerror(errno));
            g_free (sub_path);
            ret = -1;
            break;
        }

        if (S_ISREG(st.st_mode))
            g_unlink (sub_path);
        else if (S_ISDIR(st.st_mode)) {
            if (remove_recursive (sub_path) < 0) {
                ret = -1;
                g_free (sub_path);
                break;
            }
        }

        g_free (sub_path);
    }

    g_dir_close (dir);
    if (ret == 0 && g_rmdir (dir_path) < 0) {
        seaf_warning ("Failed to remove dir %s: %s.\n", dir_path, strerror(errno));
        return -1;
    }

    return ret;
}

int
migrate_client_v0_repos ()
{
    gboolean migrate_block_failed = FALSE;

    v0_block_dir = g_build_filename (seaf->seaf_dir, "blocks", NULL);

    /* If "seafile-data/blocks" dir doesn't exist, it has been migrated. */
    if (!g_file_test (v0_block_dir, G_FILE_TEST_IS_DIR)) {
        g_free (v0_block_dir);
        return 0;
    }

    block_dir = g_build_filename (seaf->seaf_dir, "storage", "blocks", NULL);

    GList *repos, *ptr;
    SeafRepo *repo;
    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    for (ptr = repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        /* migrate_repo_blocks() only returns error when failed to copy a block.
         * But it still copies the remaining blocks.
         */
        if (repo->version == 0 && migrate_repo_blocks (repo) < 0)
            migrate_block_failed = TRUE;
    }

    /* Remove the old blocks dir. If some blocks are not migrated, don't
     * remove old blocks dir so that the user can switch back to old client.
     */
    if (!migrate_block_failed && remove_recursive (v0_block_dir) < 0) {
        seaf_warning ("Failed to remove old blocks dir.\n");
    }

    g_free (block_dir);
    g_free (v0_block_dir);

    return 0;
}
