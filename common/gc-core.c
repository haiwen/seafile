/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "bloom-filter.h"
#include "gc-core.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

/* Total number of blocks to be scanned. */
static guint64 total_blocks;
static guint64 removed_blocks;

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
    size_t size = (size_t) MAX(total_blocks << 2, 1 << 13);

    g_message ("GC index size is %u Byte.\n", (int)size >> 3);

    return bloom_create (size, 3, 0);
}

typedef struct {
    Bloom *index;
    GHashTable *visited;
#ifndef SEAFILE_SERVER
    gboolean no_history;
    char end_commit[41];
#endif

#ifdef SEAFILE_SERVER
    /* > 0: keep a period of history;
     * == 0: only keep data in head commit;
     * < 0: keep all history data.
     */
    gint64 truncate_time;
    gboolean traversed_head;
#endif
} GCData;

static int
add_blocks_to_index (SeafFSManager *mgr, Bloom *index, const char *file_id)
{
    Seafile *seafile;
    int i;

    seafile = seaf_fs_manager_get_seafile (mgr, file_id);
    if (!seafile) {
        seaf_warning ("Failed to find file %s.\n", file_id);
        return -1;
    }

    for (i = 0; i < seafile->n_blocks; ++i)
        bloom_add (index, seafile->blk_sha1s[i]);

    seafile_unref (seafile);

    return 0;
}

static gboolean
fs_callback (SeafFSManager *mgr,
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
        add_blocks_to_index (mgr, data->index, obj_id) < 0)
        return FALSE;

    return TRUE;
}

static gboolean
traverse_commit (SeafCommit *commit, void *vdata, gboolean *stop)
{
    GCData *data = vdata;
    int ret;

#ifndef SEAFILE_SERVER
    if (data->no_history && 
        strcmp (commit->commit_id, data->end_commit) == 0) {
        *stop = TRUE;
        return TRUE;
    }
#endif

#ifdef SEAFILE_SERVER
    if (data->truncate_time == 0)
    {
        *stop = TRUE;
        /* Stop after traversing the head commit. */
    }
    else if (data->truncate_time > 0 &&
             (gint64)(commit->ctime) < data->truncate_time &&
             data->traversed_head)
    {
        *stop = TRUE;
        return TRUE;
    }

    if (!data->traversed_head)
        data->traversed_head = TRUE;
#endif

    seaf_debug ("[GC] traversed commit %s.\n", commit->commit_id);

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         commit->root_id,
                                         fs_callback,
                                         data);
    if (ret < 0)
        return FALSE;

    return TRUE;
}

static int
populate_gc_index_for_repo (SeafRepo *repo, Bloom *index)
{
    GList *branches, *ptr;
    SeafBranch *branch;
    GCData *data;
    int ret = 0;

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        seaf_warning ("[GC] Failed to get branch list of repo %s.\n", repo->id);
        return -1;
    }

    data = g_new0(GCData, 1);
    data->index = index;
    data->visited = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
#ifndef SEAFILE_SERVER
    data->no_history = TRUE;
    if (data->no_history) {
        char *remote_head = seaf_repo_manager_get_repo_property (repo->manager,
                                                                 repo->id,
                                                                 REPO_REMOTE_HEAD);
        if (remote_head)
            memcpy (data->end_commit, remote_head, 41);
        g_free (remote_head);
    }
#endif

#ifdef SEAFILE_SERVER
    gint64 truncate_time = seaf_repo_manager_get_repo_truncate_time (repo->manager,
                                                                     repo->id);
    if (truncate_time > 0) {
        seaf_repo_manager_set_repo_valid_since (repo->manager,
                                                repo->id,
                                                truncate_time);
    } else if (truncate_time == 0) {
        /* Only the head commit is valid after GC if no history is kept. */
        SeafCommit *head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                                           repo->head->commit_id);
        if (head)
            seaf_repo_manager_set_repo_valid_since (repo->manager,
                                                    repo->id,
                                                    head->ctime);
        seaf_commit_unref (head);
    }

    data->truncate_time = truncate_time;
#endif

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 branch->commit_id,
                                                                 traverse_commit,
                                                                 data);
        seaf_branch_unref (branch);
        if (!res) {
            ret = -1;
            break;
        }
    }

    g_list_free (branches);
    g_hash_table_destroy (data->visited);
    g_free (data);

    return ret;
}

#ifndef SEAFILE_SERVER
static int
populate_gc_index_for_head (const char *head_id, Bloom *index)
{
    SeafCommit *head;
    GCData *data;
    gboolean ret;

    /* We just need to traverse the head for clone tasks. */
    head = seaf_commit_manager_get_commit (seaf->commit_mgr, head_id);
    if (!head) {
        seaf_warning ("Failed to find clone head %s.\n", head_id);
        return -1;
    }

    data = g_new0 (GCData, 1);
    data->index = index;

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         head->root_id,
                                         fs_callback,
                                         data);

    g_free (data);
    seaf_commit_unref (head);
    return ret;
}
#endif

static gboolean
check_block_liveness (const char *block_id, void *vindex)
{
    Bloom *index = vindex;

    if (!bloom_test (index, block_id)) {
        ++removed_blocks;
        seaf_block_manager_remove_block (seaf->block_mgr, block_id);
    }

    return TRUE;
}

int
gc_core_run ()
{
    Bloom *index;
    GList *repos = NULL, *clone_heads = NULL, *ptr;
    int ret;

    total_blocks = seaf_block_manager_get_block_number (seaf->block_mgr);
    removed_blocks = 0;

    g_message ("GC started. Total block number is %"G_GUINT64_FORMAT".\n", total_blocks);

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

    g_message ("Pupulating index.\n");

    /* If we meet any error when filling in the index, we should bail out.
     */
#ifdef SEAFILE_SERVER
    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    if (!repos) {
        seaf_warning ("Failed to get repo list.\n");
        return -1;
    }
#else
    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
#endif

    for (ptr = repos; ptr != NULL; ptr = ptr->next) {
        ret = populate_gc_index_for_repo ((SeafRepo *)ptr->data, index);
#ifdef SEAFILE_SERVER
        seaf_repo_unref ((SeafRepo *)ptr->data);
#endif
        if (ret < 0)
            goto out;
    }

#ifndef SEAFILE_SERVER
    /* If seaf-daemon exits while downloading a new repo, the downloaded new
     * blocks for that repo won't be refered by any repo_id. So after restart
     * those blocks will be GC'ed. To prevent this, we get a list of commit
     * head ids for thoes new repos.
     */
    clone_heads = seaf_transfer_manager_get_clone_heads (seaf->transfer_mgr);
    for (ptr = clone_heads; ptr != NULL; ptr = ptr->next) {
        ret = populate_gc_index_for_head ((char *)ptr->data, index);
        g_free (ptr->data);
        if (ret < 0)
            goto out;
    }
#endif

    g_message ("Scanning and deleting unused blocks.\n");

    ret = seaf_block_manager_foreach_block (seaf->block_mgr,
                                            check_block_liveness,
                                            index);
    if (ret < 0) {
        seaf_warning ("GC: Failed to clean dead blocks.\n");
        goto out;
    }

    g_message ("GC finished. %"G_GUINT64_FORMAT" blocks are removed.\n", removed_blocks);

out:
    bloom_destroy (index);
    g_list_free (repos);
    g_list_free (clone_heads);
    return ret;
}
