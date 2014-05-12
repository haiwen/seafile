/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet.h>

#include "index/index.h"
#include "unpack-trees.h"
#include "merge-recursive.h"
#include "merge.h"

#include "seafile-session.h"
#include "vc-utils.h"
#include "vc-common.h"

#if 0
static int 
print_index (struct index_state *istate)
{
    int i;
    struct cache_entry *ce;
    char id[41];
    g_message ("Totally %u entries in index, version %u.\n",
               istate->cache_nr, istate->version);
    for (i = 0; i < istate->cache_nr; ++i) {
        ce = istate->cache[i];
        rawdata_to_hex (ce->sha1, id, 20);
        g_message ("%s, %s, %o, %"G_GUINT64_FORMAT", %s, %d\n",
                   ce->name, id, ce->ce_mode, 
                   ce->ce_mtime.sec, ce->modifier, ce_stage(ce));
    }

    return 0;
}
#endif

static int
do_real_merge (SeafRepo *repo, 
               SeafBranch *head_branch,
               SeafCommit *head,
               SeafBranch *remote_branch, 
               SeafCommit *remote,
               SeafCommit *common,
               gboolean recover_merge,
               char **error)
{
    struct merge_options opts;
    char index_path[SEAF_PATH_MAX];
    struct index_state istate;
    char *root_id = NULL;
    SeafCommit *merged;
    int ret = 0, clean;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", repo->manager->index_dir, repo->id);
    if (read_index_from (&istate, index_path, repo->version) < 0) {
        g_warning ("Failed to load index.\n");
        *error = g_strdup ("Internal error.\n");
        return -1;
    }

    init_merge_options (&opts);
    memcpy (opts.repo_id, repo->id, 36);
    opts.version = repo->version;
    opts.index = &istate;
    opts.worktree = repo->worktree;
    opts.ancestor = "common ancestor";
    opts.branch1 = seaf->session->base.user_name;
    opts.branch2 = remote->creator_name;
    opts.remote_head = remote->commit_id;
    opts.recover_merge = recover_merge;
    if (repo->encrypted) {
        opts.crypt = seafile_crypt_new (repo->enc_version, 
                                        repo->enc_key, 
                                        repo->enc_iv);
    }

    ret = merge_recursive (&opts,
                           head->root_id, remote->root_id, common->root_id,
                           &clean, &root_id);
    if (ret < 0)
        goto out;

    if (update_index (&istate, index_path) < 0) {
        *error = g_strdup ("Internal error.\n");
        ret = -1;
        goto out;
    }

    if (clean) {
        merged = seaf_commit_new (NULL,
                                  repo->id,
                                  root_id,
                                  repo->email ? repo->email
                                  : seaf->session->base.user_name,
                                  seaf->session->base.id,
                                  "Auto merge by system",
                                  0);

        merged->parent_id = g_strdup(head->commit_id);
        merged->second_parent_id = g_strdup(remote->commit_id);
        merged->new_merge = TRUE;

        seaf_repo_to_commit (repo, merged);

        if (seaf_commit_manager_add_commit (seaf->commit_mgr, merged) < 0) {
            seaf_commit_unref (merged);
            *error = g_strdup ("Internal error.\n");
            ret = -1;
            goto out;
        }
        seaf_branch_set_commit (head_branch, merged->commit_id);
        seaf_branch_manager_update_branch (seaf->branch_mgr, head_branch);
        g_debug ("Auto merged.\n");

        seaf_commit_unref (merged);
    } else {
        ret = -1;
        g_debug ("Auto merge failed.\n");
    }

out:
    if (root_id)
        g_free (root_id);
    g_free (opts.crypt);
    clear_merge_options (&opts);
    discard_index (&istate);
    return ret;
}

static SeafCommit *
get_common_ancestor_commit (const char *repo_id, int version)
{
    char ca_id[41], head_id[41];
    SeafCommit *commit;

    if (seaf_repo_manager_get_common_ancestor (seaf->repo_mgr,
                                               repo_id, ca_id, head_id) < 0) {
        g_warning ("Common ancestor commit id is not found in db.\n");
        return NULL;
    }

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo_id, version,
                                             ca_id);

    return commit;
}

int
merge_branches (SeafRepo *repo, SeafBranch *remote_branch, char **error,
                int *merge_status)
{
    SeafCommit *common = NULL;
    SeafCommit *head = NULL, *remote = NULL;
    int ret = 0;
#if 0
    SeafRepoMergeInfo minfo;
#endif

    g_return_val_if_fail (repo && remote_branch && error, -1);

    *merge_status = MERGE_STATUS_UNKNOWN;

#if 0
    memset (&minfo, 0, sizeof(minfo));
    if (seaf_repo_manager_get_merge_info (repo->manager, repo->id, &minfo) < 0) {
        g_warning ("Failed to get merge status of repo %s.\n", repo->id);
        return -1;
    }
#endif

    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id, repo->version,
                                           repo->head->commit_id);
    if (!head) {
        *error = g_strdup("Internal error: current branch corrupted.\n");
        return -1;
    }

    remote = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->id, repo->version,
                                             remote_branch->commit_id);
    if (!remote) {
        *error = g_strdup("Invalid remote branch.\n");
        ret = -1;
        goto free_commits;
    }

#if 0
    /* Are we going to recover from the last interrupted merge? */
    if (minfo.in_merge) {
        /* We don't need to recover 2 cases, since the last merge was actually finished.
         * - "master" and "local" are the same;
         * - index is unmerged.
         *
         * The first case is a clean merge; the second case is unclean merge.
         */
        if (strcmp (head->commit_id, remote->commit_id) == 0 ||
            seaf_repo_is_index_unmerged (repo)) {
            seaf_repo_manager_clear_merge (repo->manager, repo->id);
            goto free_commits;
        }
    }
#endif

    /* If not all commits are downloaded, find common ancestor from db;
     * otherwise we'll use the old method to calculate
     * common ancestor from local history.
     */
    if (repo->version > 0)
        common = get_common_ancestor_commit (repo->id, repo->version);
    else
        common = get_merge_base (head, remote);

    if (!common) {
        g_warning ("Cannot find common ancestor\n");
        *error = g_strdup ("Cannot find common ancestor\n");
        ret = -1;
        goto free_commits;
    }

    /* We use the same logic for normal merge and recover. */

    /* Set in_merge state. */
    seaf_repo_manager_set_merge (repo->manager, repo->id, remote_branch->commit_id);

    /* printf ("common commit id is %s.\n", common->commit_id); */

    if (strcmp(common->commit_id, remote->commit_id) == 0) {
        /* We are already up to date. */
        g_debug ("Already up to date.\n");
        *merge_status = MERGE_STATUS_UPTODATE;
    } else if (strcmp(common->commit_id, head->commit_id) == 0) {
        *merge_status = MERGE_STATUS_FAST_FORWARD;

        /* Fast forward. */
        if (seaf_repo_checkout_commit (repo, remote, FALSE, error) < 0) {
            ret = -1;
            goto out;
        }
        seaf_branch_set_commit (repo->head, remote->commit_id);
        seaf_branch_manager_update_branch (seaf->branch_mgr, repo->head);

        /* Repo info on the client is in memory. */
        g_free (repo->name);
        repo->name = g_strdup(remote->repo_name);
        g_free (repo->desc);
        repo->desc = g_strdup(remote->repo_desc);

        g_debug ("Fast forward.\n");
    } else {
        /* Not up-to-date and ff, we need a real merge. */
        *merge_status = MERGE_STATUS_REAL_MERGE;
        ret = do_real_merge (repo, 
                             repo->head, head, 
                             remote_branch, remote, common, 
                             FALSE,
                             error);
    }

out:
    /* Clear in_merge state, no matter clean or not. */
    seaf_repo_manager_clear_merge (repo->manager, repo->id);

free_commits:
    seaf_commit_unref (common);
    seaf_commit_unref (remote);
    seaf_commit_unref (head);

    return ret;
}

/*
 * Get the new blocks that need to be checked out if we ff to @remote.
 */
static int
get_new_blocks_ff (SeafRepo *repo, 
                   SeafCommit *head, 
                   SeafCommit *remote, 
                   BlockList **bl)
{
    SeafRepoManager *mgr = repo->manager;
    char index_path[SEAF_PATH_MAX];
    struct tree_desc trees[2];
    struct unpack_trees_options topts;
    struct index_state istate;
    int ret = 0;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", mgr->index_dir, repo->id);
    if (read_index_from (&istate, index_path, repo->version) < 0) {
        g_warning ("Failed to load index.\n");
        return -1;
    }

    fill_tree_descriptor (repo->id, repo->version, &trees[0], head->root_id);
    fill_tree_descriptor (repo->id, repo->version, &trees[1], remote->root_id);

    memset(&topts, 0, sizeof(topts));
    memcpy (topts.repo_id, repo->id, 36);
    topts.version = repo->version;
    topts.base = repo->worktree;
    topts.head_idx = -1;
    topts.src_index = &istate;
    topts.update = 1;
    topts.merge = 1;
    topts.fn = twoway_merge;

    /* unpack_trees() doesn't update index or worktree. */
    if (unpack_trees (2, trees, &topts) < 0) {
        g_warning ("Failed to ff to commit %s.\n", remote->commit_id);
        ret = -1;
        goto out;
    }

    *bl = block_list_new ();
    collect_new_blocks_from_index (repo->id, repo->version, &topts.result, *bl);

out:
    tree_desc_free (&trees[0]);
    tree_desc_free (&trees[1]);
    discard_index (&istate);
    discard_index (&topts.result);

    return ret;
}

/*
 * Get the new blocks that need to be checked out if we do a real merge.
 */
static int
get_new_blocks_merge (SeafRepo *repo, 
                      SeafCommit *head, 
                      SeafCommit *remote, 
                      SeafCommit *common,
                      BlockList **bl)
{
    struct merge_options opts;
    char index_path[SEAF_PATH_MAX];
    struct index_state istate;
    int ret, clean;

    memset (&istate, 0, sizeof(istate));
    snprintf (index_path, SEAF_PATH_MAX, "%s/%s", repo->manager->index_dir, repo->id);
    if (read_index_from (&istate, index_path, repo->version) < 0) {
        g_warning ("Failed to load index.\n");
        return -1;
    }

    init_merge_options (&opts);
    memcpy (opts.repo_id, repo->id, 36);
    opts.version = repo->version;
    opts.index = &istate;
    opts.worktree = repo->worktree;
    opts.ancestor = "common ancestor";
    opts.branch1 = seaf->session->base.user_name;
    opts.branch2 = remote->creator_name;
    opts.collect_blocks_only = TRUE;

    *bl = block_list_new();
    opts.bl = *bl;

    ret = merge_recursive (&opts,
                           head->root_id, remote->root_id, common->root_id,
                           &clean, NULL);

    clear_merge_options (&opts);
    discard_index (&istate);
    return ret;    
}

/*
 * Get the list of new blocks that would be checked out after
 * we merge with a branch headed by @remote.
 *
 * This function should be called before downloading any block
 * if the repo is set to not preserving history. In this case,
 * we don't want to download any block that will not be checked
 * out to the worktree (i.e. data from any historical commits).
 *
 * Return 0 if successfully calculate the block list, -1 otherwise.
 * If there is no new block to download, *@bl will be set to NULL;
 * otherwise it's set to the block list.
 */
int
merge_get_new_block_list (SeafRepo *repo, SeafCommit *remote, BlockList **bl)
{
    SeafCommit *common = NULL;
    SeafCommit *head = NULL;
    int ret = 0;

    head = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                           repo->id, repo->version,
                                           repo->head->commit_id);
    if (!head) {
        g_warning ("current branch corrupted.\n");
        return -1;
    }

    /* If not all commits are downloaded, get common ancestor from db;
     * otherwise we'll use the old method to calculate
     * common ancestor from local history.
     */
    if (repo->version > 0)
        common = get_common_ancestor_commit (repo->id, repo->version);
    else
        common = get_merge_base (head, remote);

    if (!common) {
        g_warning ("Cannot find common ancestor\n");
        ret = -1;
        goto out;
    }

    if (strcmp(common->commit_id, remote->commit_id) == 0) {
        /* We are already up to date. No new block. */
        *bl = NULL;
    } else if (strcmp(common->commit_id, head->commit_id) == 0) {
        /* Fast forward. */
        ret = get_new_blocks_ff (repo, head, remote, bl);
    } else {
        /* Not up-to-date and ff, we need a real merge. */
        ret = get_new_blocks_merge (repo, head, remote, common, bl);
    }

out:
    seaf_commit_unref (common);
    seaf_commit_unref (head);

    return ret;
}
