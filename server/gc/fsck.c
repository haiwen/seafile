#include "common.h"

#include "seafile-session.h"
#include "log.h"

#include "fsck.h"

typedef struct FsckOpt {
    gboolean dry_run;
    gboolean strict;
} FsckOpt;

static gboolean
remove_corrupt_fs_object (const char *store_id, int version,
                          const char *obj_id, void *user_data)
{
    FsckOpt *opt = user_data;
    gboolean io_error = FALSE;
    gboolean ok = TRUE;

    ok = seaf_fs_manager_verify_object (seaf->fs_mgr,
                                        store_id, version,
                                        obj_id, opt->strict, &io_error);
    if (!ok && !io_error) {
        if (opt->dry_run) {
            seaf_message ("Fs object %s is corrupted.\n", obj_id);
        } else {
            seaf_message ("Fs object %s is corrupted, remove it.\n", obj_id);
            seaf_obj_store_delete_obj (seaf->fs_mgr->obj_store,
                                       store_id, version,
                                       obj_id);
        }
    }

    return TRUE;
}

static int
remove_corrupt_fs_objects (const char *store_id, int version,
                           gboolean dry_run, gboolean strict)
{
    FsckOpt opt;

    memset (&opt, 0, sizeof(opt));
    opt.dry_run = dry_run;
    opt.strict = strict;

    return seaf_obj_store_foreach_obj (seaf->fs_mgr->obj_store,
                                       store_id, version,
                                       remove_corrupt_fs_object,
                                       &opt);
}

static gboolean
remove_corrupt_block (const char *store_id, int version,
                      const char *block_id, void *user_data)
{
    gboolean *dry_run = user_data;
    gboolean io_error = FALSE;
    gboolean ok = TRUE;

    ok = seaf_block_manager_verify_block (seaf->block_mgr,
                                          store_id, version,
                                          block_id, &io_error);
    if (!ok && !io_error) {
        if (*dry_run) {
            seaf_message ("Block %s is corrupted.\n", block_id);
        } else {
            seaf_message ("Block %s is corrupted, remove it.\n", block_id);
            seaf_block_manager_remove_block (seaf->block_mgr,
                                             store_id, version,
                                             block_id);
        }
    }

    return TRUE;
}

static int
remove_corrupt_blocks (const char *store_id, int version,
                       gboolean dry_run)
{
    return seaf_block_manager_foreach_block (seaf->block_mgr,
                                             store_id, version,
                                             remove_corrupt_block,
                                             &dry_run);
}

typedef struct FsckRes {
    SeafRepo *repo;
    char *consistent_head;
    GHashTable *existing_blocks;
} FsckRes;

static int
check_blocks (SeafFSManager *mgr, FsckRes *res, const char *file_id)
{
    SeafRepo *repo = res->repo;
    Seafile *seafile;
    int i;
    char *block_id;
    int ret = 0;
    int dummy;

    seafile = seaf_fs_manager_get_seafile (mgr, repo->store_id, repo->version, file_id);
    if (!seafile) {
        seaf_warning ("Failed to find file %s.\n", file_id);
        return -1;
    }

    /* Since we've removed corrupted blocks, we can assume existing blocks
     * are integrent.
     */
    for (i = 0; i < seafile->n_blocks; ++i) {
        block_id = seafile->blk_sha1s[i];

        if (g_hash_table_lookup (res->existing_blocks, block_id))
            continue;

        if (!seaf_block_manager_block_exists (seaf->block_mgr,
                                              repo->store_id, repo->version,
                                              block_id)) {
            seaf_message ("Block %s is missing.\n", block_id);
            ret = -1;
            break;
        }

        g_hash_table_insert (res->existing_blocks, g_strdup(block_id), &dummy);
    }

    seafile_unref (seafile);

    return ret;
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
    FsckRes *res = user_data;

    if (type == SEAF_METADATA_TYPE_FILE && check_blocks (mgr, res, obj_id) < 0)
        return FALSE;

    return TRUE;
}

static gboolean
check_fs_integrity (SeafCommit *commit, void *vdata, gboolean *stop)
{
    FsckRes *res = vdata;

    /* Stop traversing commits after finding the first consistent commit. */
    if (res->consistent_head != NULL) {
        *stop = TRUE;
        return TRUE;
    }

    int rc = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                            res->repo->store_id,
                                            res->repo->version,
                                            commit->root_id,
                                            fs_callback,
                                            res, FALSE);
    if (rc == 0) {
        *stop = TRUE;
        res->consistent_head = g_strdup (commit->commit_id);
    }

    return TRUE;
}

/*
 * Check whether the current head of @repo is consistent (including fs and block),
 * if not, find and reset its head to the last consistent commit.
 * Note that this procedure will not work with a corrupted commit object.
 */
static void
check_and_reset_consistent_state (SeafRepo *repo)
{
    FsckRes res;

    seaf_message ("Checking integrity of repo %s(%.8s)...\n", repo->name, repo->id);

    memset (&res, 0, sizeof(res));
    res.repo = repo;
    res.existing_blocks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                 g_free, NULL);

    seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                              repo->id, repo->version,
                                              repo->head->commit_id,
                                              check_fs_integrity,
                                              &res,
                                              TRUE);

    g_hash_table_destroy (res.existing_blocks);

    if (!res.consistent_head) {
        seaf_warning ("Repo %.8s doesn't have consistent history state.\n",
                      repo->id);
        return;
    }

    /* If the current head is not consistent, reset it. */
    if (strcmp (res.consistent_head, repo->head->commit_id) != 0) {
        seaf_message ("Resetting head of repo %.8s to commit %.8s.\n",
                      repo->id, res.consistent_head);
        seaf_branch_set_commit (repo->head, res.consistent_head);
        if (seaf_branch_manager_update_branch (seaf->branch_mgr, repo->head) < 0) {
            seaf_warning ("Failed to update branch head.\n");
        }
    }

    g_free (res.consistent_head);
}

static int
check_fs_block_objects_for_repo (SeafRepo *repo, gboolean dry_run, gboolean strict)
{
    seaf_message ("Checking fs objects for version %d repo %s(%.8s)...\n",
                  repo->version, repo->name, repo->id);

    if (remove_corrupt_fs_objects (repo->store_id, repo->version,
                                   dry_run, strict) < 0) {
        seaf_warning ("Failed to check fs objects.\n");
        return -1;
    }

    seaf_message ("Checking blocks for version %d repo %s(%.8s)...\n",
                  repo->version, repo->name, repo->id);

    if (remove_corrupt_blocks (repo->store_id, repo->version, dry_run) < 0) {
        seaf_warning ("Failed to check blocks.\n");
        return -1;
    }

    return 0;
}

int
seaf_fsck (GList *repo_id_list, gboolean dry_run, gboolean strict)
{
    if (!repo_id_list)
        repo_id_list = seaf_repo_manager_get_repo_id_list (seaf->repo_mgr);

    GList *ptr;
    char *repo_id;
    SeafRepo *repo;

    for (ptr = repo_id_list; ptr; ptr = ptr->next) {
        repo_id = ptr->data;
        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!repo) {
            seaf_warning ("Cannot load repo %.8s.\n", repo_id);
            continue;
        }

        if (repo->is_virtual) {
            seaf_repo_unref (repo);
            continue;
        }

        if (check_fs_block_objects_for_repo (repo, dry_run, strict) < 0) {
            seaf_warning ("Failed to check fs and blocks for repo %.8s.\n",
                          repo->id);
            continue;
        }

        if (!dry_run)
            check_and_reset_consistent_state (repo);

        seaf_repo_unref (repo);
    }

    return 0;
}
