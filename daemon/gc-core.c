/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "bloom-filter.h"
#include "gc-core.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

#define MAX_BF_SIZE (((size_t)1) << 29)   /* 64 MB */

/* Total number of blocks to be scanned. */
static guint64 total_blocks;
static guint64 removed_blocks;
static guint64 reachable_blocks;

/*
 * The number of bits in the bloom filter is 4 times the number of all blocks.
 * Let m be the bits in the bf, n be the number of blocks to be added to the bf
 * (the number of live blocks), and k = 3 (closed to optimal for m/n = 4),
 * the probability of false-positive is
 *
 *     p = (1 - e^(-kn/m))^k = 0.15
 *
 * Because m = 4 * total_blocks >= 4 * (live blocks) = 4n, we should have p <= 0.15.
 * Put it another way, we'll clean up at least 85% dead blocks in each gc operation.
 * See http://en.wikipedia.org/wiki/Bloom_filter.
 *
 * Supose we have 8TB space, and the avg block size is 1MB, we'll have 8M blocks, then
 * the size of bf is (8M * 4)/8 = 4MB.
 *
 * If total_blocks is a small number (e.g. < 100), we should try to clean all dead blocks.
 * So we set the minimal size of the bf to 1KB.
 */
static Bloom *
alloc_gc_index ()
{
    size_t size;

    size = (size_t) MAX(total_blocks << 2, 1 << 13);
    size = MIN (size, MAX_BF_SIZE);

    seaf_message ("GC index size is %u Byte.\n", (int)size >> 3);

    return bloom_create (size, 3, 0);
}

typedef struct {
    SeafRepo *repo;
    Bloom *index;
    GHashTable *visited;
    gboolean no_history;
    char remote_end_commit[41];
    char local_end_commit[41];

    int traversed_commits;
    gint64 traversed_blocks;
    gboolean ignore_errors;
} GCData;

static int
add_blocks_to_index (SeafFSManager *mgr,
                     const char *repo_id, int repo_version,
                     GCData *data, const char *file_id)
{
    Bloom *index = data->index;
    Seafile *seafile;
    int i;

    seafile = seaf_fs_manager_get_seafile (mgr,
                                           repo_id,
                                           repo_version,
                                           file_id);
    if (!seafile) {
        seaf_warning ("Failed to find file %s.\n", file_id);
        return -1;
    }

    for (i = 0; i < seafile->n_blocks; ++i) {
        bloom_add (index, seafile->blk_sha1s[i]);
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
        add_blocks_to_index (mgr, repo_id, version, data, obj_id) < 0)
        return FALSE;

    return TRUE;
}

static gboolean
traverse_commit (SeafCommit *commit, void *vdata, gboolean *stop)
{
    GCData *data = vdata;
    int ret;

    if (data->no_history && 
        (strcmp (commit->commit_id, data->local_end_commit) == 0 ||
         strcmp (commit->commit_id, data->remote_end_commit) == 0)) {
        *stop = TRUE;
        return TRUE;
    }

    seaf_debug ("Traversed commit %.8s.\n", commit->commit_id);
    ++data->traversed_commits;

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         data->repo->id,
                                         data->repo->version,
                                         commit->root_id,
                                         fs_callback,
                                         data, data->ignore_errors);
    if (ret < 0 && !data->ignore_errors)
        return FALSE;

    return TRUE;
}

static int
populate_gc_index_for_repo (SeafRepo *repo, Bloom *index, gboolean ignore_errors)
{
    GList *branches, *ptr;
    SeafBranch *branch;
    GCData *data;
    int ret = 0;

    seaf_message ("Populating index for repo %s(%.8s).\n", repo->name, repo->id);

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        seaf_warning ("[GC] Failed to get branch list of repo %s.\n", repo->id);
        return -1;
    }

    data = g_new0(GCData, 1);
    data->repo = repo;
    data->index = index;
    data->visited = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    data->no_history = TRUE;
    if (data->no_history) {
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
    }

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        gboolean res = seaf_commit_manager_traverse_commit_tree_truncated (seaf->commit_mgr,
                                                                 repo->id,
                                                                 repo->version,
                                                                 branch->commit_id,
                                                                 traverse_commit,
                                                                 data,
                                                                 ignore_errors);
        seaf_branch_unref (branch);
        if (!res && !ignore_errors) {
            ret = -1;
            break;
        }
    }

    seaf_message ("Traversed %d commits, %"G_GINT64_FORMAT" blocks.\n",
                  data->traversed_commits, data->traversed_blocks);
    reachable_blocks += data->traversed_blocks;

    g_list_free (branches);
    g_hash_table_destroy (data->visited);
    g_free (data);

    return ret;
}

static int
populate_gc_index_for_head (const char *repo_id, int version,
                            const char *head_id, Bloom *index)
{
    SeafCommit *head;
    GCData *data;
    gboolean ret;

    seaf_message ("Populating index for clone head %s.\n", head_id);

    /* We just need to traverse the head for clone tasks. */
    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo_id, version,
                                           head_id);
    if (!head) {
        seaf_warning ("Failed to find clone head %s.\n", head_id);
        return -1;
    }

    data = g_new0 (GCData, 1);
    data->index = index;

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         repo_id,
                                         version,
                                         head->root_id,
                                         fs_callback,
                                         data, FALSE);

    seaf_message ("Traversed %"G_GINT64_FORMAT" blocks.\n", data->traversed_blocks);

    g_free (data);
    seaf_commit_unref (head);
    return ret;
}

static int
populate_gc_index_for_precheckout_repo (SeafRepo *repo, Bloom *index)
{
    SeafBranch *master;
    SeafCommit *head;
    GCData *data;
    gboolean ret;

    seaf_message ("Populating index for precheckout repo %s.\n", repo->id);

    /* For repos that are cloned but not checked out yet, it's sufficient
     * to traverse the head commit of master branch.
     */
    master = seaf_branch_manager_get_branch (seaf->branch_mgr, repo->id, "master");
    if (!master) {
        seaf_warning ("Failed to get master branch.\n");
        return -1;
    }
    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id, repo->version,
                                           master->commit_id);
    if (!head) {
        seaf_warning ("Failed to get commit %s.\n", master->commit_id);
        seaf_branch_unref (master);
        return -1;
    }

    data = g_new0 (GCData, 1);
    data->index = index;

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         repo->id,
                                         repo->version,
                                         head->root_id,
                                         fs_callback,
                                         data, FALSE);

    seaf_message ("Traversed %"G_GINT64_FORMAT" blocks.\n", data->traversed_blocks);

    g_free (data);
    seaf_branch_unref (master);
    seaf_commit_unref (head);
    return ret;
}

typedef struct {
    Bloom *index;
    int dry_run;
} CheckBlocksData;

static gboolean
check_block_liveness (const char *repo_id,
                      int version,
                      const char *block_id,
                      void *vdata)
{
    CheckBlocksData *data = vdata;
    Bloom *index = data->index;

    if (!bloom_test (index, block_id)) {
        ++removed_blocks;
        if (!data->dry_run)
            seaf_block_manager_remove_block (seaf->block_mgr,
                                             repo_id, version,
                                             block_id);
    }

    return TRUE;
}

int
gc_v0_repos (GList *repos, int dry_run, int ignore_errors)
{
    Bloom *index;
    GList *clone_heads = NULL, *ptr;
    int ret;

    total_blocks = seaf_block_manager_get_block_number (seaf->block_mgr,
                                                        NULL, 0);
    removed_blocks = 0;
    reachable_blocks = 0;

    if (total_blocks == 0) {
        seaf_message ("No blocks. Skip GC.\n");
        return 0;
    }

    seaf_message ("GC started. Total block number is %"G_GUINT64_FORMAT".\n", total_blocks);

    /*
     * Store the index of live blocks in bloom filter to save memory.
     * Since bloom filters only have false-positive, we
     * may skip some garbage blocks, but we won't delete
     * blocks that are still alive.
     */
    index = alloc_gc_index ();
    if (!index) {
        seaf_warning ("GC: Failed to allocate index.\n");
        return -1;
    }

    seaf_message ("Populating index.\n");

    for (ptr = repos; ptr != NULL; ptr = ptr->next) {
        SeafRepo *repo = ptr->data;
        if (repo->head)
            ret = populate_gc_index_for_repo (repo, index, ignore_errors);
        else
            ret = populate_gc_index_for_precheckout_repo (repo, index);
        if (ret < 0 && !ignore_errors)
            goto out;
    }

    /* If seaf-daemon exits while downloading blocks, the downloaded new
     * blocks won't be refered by any repo_id. So after restart
     * those blocks will be GC'ed. To prevent this, we get a list of commit
     * head ids for thoes new repos.
     */
    clone_heads = seaf_transfer_manager_get_clone_heads (seaf->transfer_mgr);
    for (ptr = clone_heads; ptr != NULL; ptr = ptr->next) {
        populate_gc_index_for_head (NULL, 0, (char *)ptr->data, index);
        g_free (ptr->data);
    }

    if (!dry_run)
        seaf_message ("Scanning and deleting unused blocks.\n");
    else
        seaf_message ("Scanning unused blocks.\n");

    CheckBlocksData data;
    data.index = index;
    data.dry_run = dry_run;

    ret = seaf_block_manager_foreach_block (seaf->block_mgr,
                                            NULL, 0,
                                            check_block_liveness,
                                            &data);
    if (ret < 0) {
        seaf_warning ("GC: Failed to clean dead blocks.\n");
        goto out;
    }

    if (!dry_run)
        seaf_message ("GC finished. %"G_GUINT64_FORMAT" blocks total, "
                      "about %"G_GUINT64_FORMAT" reachable blocks, "
                      "%"G_GUINT64_FORMAT" blocks are removed.\n",
                      total_blocks, reachable_blocks, removed_blocks);
    else
        seaf_message ("GC finished. %"G_GUINT64_FORMAT" blocks total, "
                      "about %"G_GUINT64_FORMAT" reachable blocks, "
                      "%"G_GUINT64_FORMAT" blocks can be removed.\n",
                      total_blocks, reachable_blocks, removed_blocks);

out:
    bloom_destroy (index);
    g_list_free (clone_heads);
    return ret;
}

int
gc_v1_repo (SeafRepo *repo, int dry_run, int ignore_errors)
{
    Bloom *index;
    int ret;

    if (!repo->head) {
        seaf_message ("Repo %s(%.8s) is not checked out. Skip GC.\n",
                      repo->name, repo->id);
        return 0;
    }

    total_blocks = seaf_block_manager_get_block_number (seaf->block_mgr,
                                                        repo->id, repo->version);
    removed_blocks = 0;
    reachable_blocks = 0;

    if (total_blocks == 0) {
        seaf_message ("No blocks. Skip GC.\n");
        return 0;
    }

    seaf_message ("GC started. Total block number is %"G_GUINT64_FORMAT".\n", total_blocks);

    /*
     * Store the index of live blocks in bloom filter to save memory.
     * Since bloom filters only have false-positive, we
     * may skip some garbage blocks, but we won't delete
     * blocks that are still alive.
     */
    index = alloc_gc_index ();
    if (!index) {
        seaf_warning ("GC: Failed to allocate index.\n");
        return -1;
    }

    seaf_message ("Populating index.\n");

    ret = populate_gc_index_for_repo (repo, index, ignore_errors);
    if (ret < 0 && !ignore_errors) 
        goto out;

    /* If seaf-daemon exits while downloading blocks, the downloaded new
     * blocks won't be refered by any repo_id. So after restart
     * those blocks will be GC'ed. To prevent this, we get the commit
     * head id for the new repo.
     */
    char *clone_head = seaf_transfer_manager_get_clone_head (seaf->transfer_mgr,
                                                             repo->id);
    if (clone_head) {
        ret = populate_gc_index_for_head (repo->id, repo->version,
                                          clone_head, index);
        g_free (clone_head);
        if (ret < 0 && !ignore_errors)
            goto out;
    }

    if (!dry_run)
        seaf_message ("Scanning and deleting unused blocks.\n");
    else
        seaf_message ("Scanning unused blocks.\n");

    CheckBlocksData data;
    data.index = index;
    data.dry_run = dry_run;

    ret = seaf_block_manager_foreach_block (seaf->block_mgr,
                                            repo->id,
                                            repo->version,
                                            check_block_liveness,
                                            &data);
    if (ret < 0) {
        seaf_warning ("GC: Failed to clean dead blocks.\n");
        goto out;
    }

    if (!dry_run)
        seaf_message ("GC finished. %"G_GUINT64_FORMAT" blocks total, "
                      "about %"G_GUINT64_FORMAT" reachable blocks, "
                      "%"G_GUINT64_FORMAT" blocks are removed.\n",
                      total_blocks, reachable_blocks, removed_blocks);
    else
        seaf_message ("GC finished. %"G_GUINT64_FORMAT" blocks total, "
                      "about %"G_GUINT64_FORMAT" reachable blocks, "
                      "%"G_GUINT64_FORMAT" blocks can be removed.\n",
                      total_blocks, reachable_blocks, removed_blocks);

out:
    bloom_destroy (index);
    return ret;
}

int
gc_core_run (int dry_run, int ignore_errors)
{
    GList *repos = NULL, *v0_repos = NULL, *del_repos = NULL, *ptr;
    SeafRepo *repo;

    seaf_message ("=== GC version 1 repos ===\n");

    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    for (ptr = repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        if (repo->version > 0) {
            seaf_message ("GC version %d repo %s(%.8s)\n",
                          repo->version, repo->name, repo->id);
            gc_v1_repo (repo, dry_run, ignore_errors);
        } else
            v0_repos = g_list_prepend (v0_repos, repo);
    }
    g_list_free (repos);

    seaf_message ("=== GC version 0 repos ===\n");
    gc_v0_repos (v0_repos, dry_run, ignore_errors);
    g_list_free (v0_repos);

    seaf_message ("=== GC deleted version 1 repos ===\n");
    del_repos = seaf_repo_manager_list_garbage_repos (seaf->repo_mgr);
    for (ptr = del_repos; ptr; ptr = ptr->next) {
        char *repo_id = ptr->data;

        /* Confirm repo doesn't exist before removing blocks. */
        if (!seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id)) {
            seaf_message ("GC deleted repo %.8s.\n", repo_id);
            seaf_block_manager_remove_store (seaf->block_mgr, repo_id);
        }

        seaf_repo_manager_remove_garbage_repo (seaf->repo_mgr, repo_id);
        g_free (repo_id);
    }
    g_list_free (del_repos);

    return 0;
}
