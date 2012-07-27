/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "bloom-filter.h"
#include "gc.h"
#include "info-mgr.h"

/* Total number of blocks to be scanned. */
static guint64 total_blocks;
/* Number of blocks have been scanned. */
static guint64 scanned_blocks;
static guint64 removed_blocks;

static gint gc_started = 0;

static void *gc_thread_func (void *data);
static void gc_done (void *result);

int
gc_start ()
{
    int ret;

    if (gc_started) {
        g_warning ("GC is in progress, cannot start.\n");
        return -1;
    }

    ret = ccnet_job_manager_schedule_job (seaf->job_mgr,
                                          gc_thread_func,
                                          gc_done,
                                          NULL);
    if (ret < 0)
        return ret;

    gc_started = 1;
    return 0;
}

int
gc_get_progress ()
{
    if (!g_atomic_int_get (&gc_started))
        return -1;

    return (int) (((double)scanned_blocks/total_blocks) * 100);
}

gboolean
gc_is_started ()
{
    return g_atomic_int_get (&gc_started);
}

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
#ifndef SEAFILE_SERVER
    gboolean no_history;
    char end_commit[41];
#endif
} GCData;

static void
insert_block_to_index (void *vindex, const char *block_id)
{
    Bloom *index = vindex;
    bloom_add (index, block_id);
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

    /* g_debug ("[GC] traversed commit %s.\n", commit->commit_id); */

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         commit->root_id,
                                         insert_block_to_index,
                                         data->index);
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
        g_warning ("[GC] Failed to get branch list of repo %s.\n", repo->id);
        return -1;
    }

    data = g_new0(GCData, 1);
    data->index = index;
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
    g_free (data);

    return ret;
}

#ifndef SEAFILE_SERVER
static gboolean
populate_index (SeafCommit *commit, void *vindex, gboolean *stop)
{
    int ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                             commit->root_id,
                                             insert_block_to_index,
                                             vindex);
    if (ret < 0)
        return FALSE;
    return TRUE;
}

static int
populate_gc_index_for_head (const char *head_id, Bloom *index)
{
    gboolean ret;
    ret = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                    head_id,
                                                    populate_index,
                                                    index);
    return (ret == TRUE);
}
#endif

static gboolean
check_block_liveness (const char *block_id, void *vindex)
{
    Bloom *index = vindex;

    ++scanned_blocks;

    if (!bloom_test (index, block_id)) {
        ++removed_blocks;
        seaf_block_manager_remove_block (seaf->block_mgr, block_id);
    }

    return TRUE;
}

static void *
gc_thread_func (void *data)
{
    Bloom *index;
    GList *repos = NULL, *clone_heads = NULL, *ptr;
    int ret;

    total_blocks = seaf_block_manager_get_block_number (seaf->block_mgr);
    scanned_blocks = 0;
    removed_blocks = 0;

#ifdef WIN32
    g_message ("GC started. Total block number is %I64u.\n", total_blocks);
#else
    g_message ("GC started. Total block number is %"G_GUINT64_FORMAT".\n", total_blocks);
#endif

    /*
     * Store the index of live blocks in bloom filter to save memory.
     * Since bloom filters only have false-positive, we
     * may skip some garbage blocks, but we won't delete
     * blocks that are still alive.
     */
    index = alloc_gc_index ();
    if (!index) {
        g_warning ("GC: Failed to allocate index.\n");
        return NULL;
    }

    /* If we meet any error when filling in the index, we should bail out.
     */
    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
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

    ret = seaf_block_manager_foreach_block (seaf->block_mgr,
                                            check_block_liveness,
                                            index);
    if (ret < 0) {
        g_warning ("GC: Failed to clean dead blocks.\n");
    }

out:
    bloom_destroy (index);
    g_list_free (repos);
    g_list_free (clone_heads);
    return NULL;
}

static void
gc_done (void *result)
{
    g_atomic_int_set (&gc_started, 0);

#ifdef WIN32
    g_message ("GC finished. %I64u blocks are removed.\n", removed_blocks);
#else
    g_message ("GC finished. %"G_GUINT64_FORMAT" blocks are removed.\n", removed_blocks);
#endif
}
