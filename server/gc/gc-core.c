/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "bloom-filter.h"
#include "gc-core.h"
#include "utils.h"

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

    /* > 0: keep a period of history;
     * == 0: only keep data in head commit;
     * < 0: keep all history data.
     */
    gint64 truncate_time;
    gboolean traversed_head;

    int traversed_commits;
    gint64 traversed_blocks;

    int verbose;
    gint64 traversed_fs_objs;
} GCData;

static int
add_blocks_to_index (SeafFSManager *mgr, GCData *data, const char *file_id)
{
    SeafRepo *repo = data->repo;
    Bloom *index = data->index;
    Seafile *seafile;
    int i;

    seafile = seaf_fs_manager_get_seafile (mgr, repo->store_id, repo->version, file_id);
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
             const char *store_id,
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
        g_hash_table_replace (data->visited, key, key);
    }

    ++(data->traversed_fs_objs);

    if (type == SEAF_METADATA_TYPE_FILE &&
        add_blocks_to_index (mgr, data, obj_id) < 0)
        return FALSE;

    return TRUE;
}

static gboolean
traverse_commit (SeafCommit *commit, void *vdata, gboolean *stop)
{
    GCData *data = vdata;
    int ret;

    if (data->truncate_time == 0)
    {
        *stop = TRUE;
        /* Stop after traversing the head commit. */
    }
    else if (data->truncate_time > 0 &&
             (gint64)(commit->ctime) < data->truncate_time &&
             data->traversed_head)
    {
        /* Still traverse the first commit older than truncate_time.
         * If a file in the child commit of this commit is deleted,
         * we need to access this commit in order to restore it
         * from trash.
         */
        *stop = TRUE;
    }

    if (!data->traversed_head)
        data->traversed_head = TRUE;

    if (data->verbose)
        seaf_message ("Traversing commit %.8s.\n", commit->commit_id);

    ++data->traversed_commits;

    data->traversed_fs_objs = 0;

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         data->repo->store_id, data->repo->version,
                                         commit->root_id,
                                         fs_callback,
                                         data, FALSE);
    if (ret < 0)
        return FALSE;

    if (data->verbose)
        seaf_message ("Traversed %"G_GINT64_FORMAT" fs objects.\n",
                      data->traversed_fs_objs);

    return TRUE;
}

static int
populate_gc_index_for_repo (SeafRepo *repo, Bloom *index, int verbose)
{
    GList *branches, *ptr;
    SeafBranch *branch;
    GCData *data;
    int ret = 0;

    if (!repo->is_virtual)
        seaf_message ("Populating index for repo %.8s.\n", repo->id);
    else
        seaf_message ("Populating index for sub-repo %.8s.\n", repo->id);

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        seaf_warning ("[GC] Failed to get branch list of repo %s.\n", repo->id);
        return -1;
    }

    data = g_new0(GCData, 1);
    data->repo = repo;
    data->index = index;
    data->visited = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
    data->verbose = verbose;

    gint64 truncate_time = seaf_repo_manager_get_repo_truncate_time (repo->manager,
                                                                     repo->id);
    if (truncate_time > 0) {
        seaf_repo_manager_set_repo_valid_since (repo->manager,
                                                repo->id,
                                                truncate_time);
    } else if (truncate_time == 0) {
        /* Only the head commit is valid after GC if no history is kept. */
        SeafCommit *head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                           repo->id, repo->version,
                                                           repo->head->commit_id);
        if (head)
            seaf_repo_manager_set_repo_valid_since (repo->manager,
                                                    repo->id,
                                                    head->ctime);
        seaf_commit_unref (head);
    }

    data->truncate_time = truncate_time;

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 repo->id,
                                                                 repo->version,
                                                                 branch->commit_id,
                                                                 traverse_commit,
                                                                 data,
                                                                 FALSE);
        seaf_branch_unref (branch);
        if (!res) {
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

typedef struct {
    Bloom *index;
    int dry_run;
} CheckBlocksData;

static gboolean
check_block_liveness (const char *store_id, int version,
                      const char *block_id, void *vdata)
{
    CheckBlocksData *data = vdata;
    Bloom *index = data->index;

    if (!bloom_test (index, block_id)) {
        ++removed_blocks;
        if (!data->dry_run)
            seaf_block_manager_remove_block (seaf->block_mgr,
                                             store_id, version,
                                             block_id);
    }

    return TRUE;
}

static int
populate_gc_index_for_virtual_repos (SeafRepo *repo, Bloom *index, int verbose)
{
    GList *vrepo_ids = NULL, *ptr;
    char *repo_id;
    SeafRepo *vrepo;
    int ret = 0;

    vrepo_ids = seaf_repo_manager_get_virtual_repo_ids_by_origin (seaf->repo_mgr,
                                                                  repo->id);
    for (ptr = vrepo_ids; ptr; ptr = ptr->next) {
        repo_id = ptr->data;
        vrepo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!vrepo) {
            seaf_warning ("Failed to get repo %s.\n", repo_id);
            ret = -1;
            goto out;
        }

        ret = populate_gc_index_for_repo (vrepo, index, verbose);
        seaf_repo_unref (vrepo);
        if (ret < 0)
            goto out;
    }

out:
    string_list_free (vrepo_ids);
    return ret;
}

int
gc_v1_repo (SeafRepo *repo, int dry_run, int verbose)
{
    Bloom *index;
    int ret;

    total_blocks = seaf_block_manager_get_block_number (seaf->block_mgr,
                                                        repo->store_id, repo->version);
    removed_blocks = 0;
    reachable_blocks = 0;

    if (total_blocks == 0) {
        seaf_message ("No blocks. Skip GC.\n\n");
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

    ret = populate_gc_index_for_repo (repo, index, verbose);
    if (ret < 0)
        goto out;

    /* Since virtual repos share fs and block store with the origin repo,
     * it's necessary to do GC for them together.
     */
    ret = populate_gc_index_for_virtual_repos (repo, index, verbose);
    if (ret < 0)
        goto out;

    if (!dry_run)
        seaf_message ("Scanning and deleting unused blocks.\n");
    else
        seaf_message ("Scanning unused blocks.\n");

    CheckBlocksData data;
    data.index = index;
    data.dry_run = dry_run;

    ret = seaf_block_manager_foreach_block (seaf->block_mgr,
                                            repo->store_id, repo->version,
                                            check_block_liveness,
                                            &data);
    if (ret < 0) {
        seaf_warning ("GC: Failed to clean dead blocks.\n");
        goto out;
    }

    ret = removed_blocks;

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
    printf ("\n");

    bloom_destroy (index);
    return ret;
}

void
delete_garbaged_repos (int dry_run)
{
    GList *del_repos = NULL;
    GList *ptr;

    seaf_message ("=== Repos deleted by users ===\n");
    del_repos = seaf_repo_manager_list_garbage_repos (seaf->repo_mgr);
    for (ptr = del_repos; ptr; ptr = ptr->next) {
        char *repo_id = ptr->data;

        /* Confirm repo doesn't exist before removing blocks. */
        if (!seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id)) {
            if (!dry_run) {
                seaf_message ("GC deleted repo %.8s.\n", repo_id);
                seaf_block_manager_remove_store (seaf->block_mgr, repo_id);
            } else {
                seaf_message ("Repo %.8s can be GC'ed.\n", repo_id);
            }
        }

        if (!dry_run)
            seaf_repo_manager_remove_garbage_repo (seaf->repo_mgr, repo_id);
        g_free (repo_id);
    }
    g_list_free (del_repos);
}

int
gc_core_run (GList *repo_id_list, int dry_run, int verbose)
{
    GList *ptr;
    SeafRepo *repo;
    GList *corrupt_repos = NULL;
    GList *del_block_repos = NULL;
    gboolean del_garbage = FALSE;
    int gc_ret;
    char *repo_id;

    if (repo_id_list == NULL) {
        repo_id_list = seaf_repo_manager_get_repo_id_list (seaf->repo_mgr);
        del_garbage = TRUE;
    }

    for (ptr = repo_id_list; ptr; ptr = ptr->next) {
        repo = seaf_repo_manager_get_repo_ex (seaf->repo_mgr, (const gchar *)ptr->data);

        g_free (ptr->data);

        if (!repo)
            continue;

        if (repo->is_corrupted) {
            corrupt_repos = g_list_prepend (corrupt_repos, g_strdup(repo->id));
            seaf_message ("Repo %s is corrupted, skip GC.\n\n", repo->id);
            continue;
        }

        if (!repo->is_virtual) {
            seaf_message ("GC version %d repo %s(%s)\n",
                          repo->version, repo->name, repo->id);
            gc_ret = gc_v1_repo (repo, dry_run, verbose);
            if (gc_ret < 0) {
                corrupt_repos = g_list_prepend (corrupt_repos, g_strdup(repo->id));
            } else if (dry_run && gc_ret) {
                del_block_repos = g_list_prepend (del_block_repos, g_strdup(repo->id));
            }
        }
        seaf_repo_unref (repo);
    }
    g_list_free (repo_id_list);

    if (del_garbage) {
        delete_garbaged_repos (dry_run);
    }

    seaf_message ("=== GC is finished ===\n");

    if (corrupt_repos) {
        seaf_message ("The following repos are corrupted. "
                      "You can run seaf-fsck to fix them.\n");
        for (ptr = corrupt_repos; ptr; ptr = ptr->next) {
            repo_id = ptr->data;
            seaf_message ("%s\n", repo_id);
            g_free (repo_id);
        }
        g_list_free (corrupt_repos);
    }

    if (del_block_repos) {
        printf("\n");
        seaf_message ("The following repos have blocks to be removed:\n");
        for (ptr = del_block_repos; ptr; ptr = ptr->next) {
            repo_id = ptr->data;
            seaf_message ("%s\n", repo_id);
            g_free (repo_id);
        }
        g_list_free (del_block_repos);
    }

    return 0;
}
