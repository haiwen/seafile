#include "common.h"

#include "seafile-session.h"
#include "log.h"

#include "fsck.h"

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
    gboolean io_error = FALSE;
    gboolean ok = TRUE;


    seafile = seaf_fs_manager_get_seafile (mgr, repo->store_id, repo->version, file_id);
    if (!seafile) {
        seaf_warning ("Failed to find file %s.\n", file_id);
        return -1;
    }

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

        // check block integrity, if not remove it
        ok = seaf_block_manager_verify_block (seaf->block_mgr,
                                              repo->store_id, repo->version,
                                              block_id, &io_error);
        if (!ok && !io_error) {
            seaf_message ("Block %s is corrupted, remove it.\n", block_id);
            seaf_block_manager_remove_block (seaf->block_mgr,
                                             repo->store_id, repo->version,
                                             block_id);
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

static gint
compare_commit_by_ctime (gconstpointer a, gconstpointer b)
{
    const SeafCommit *commit_a = a;
    const SeafCommit *commit_b = b;

    return (commit_b->ctime - commit_a->ctime);
}

static gboolean
fsck_get_repo_commit (const char *repo_id, int version,
                      const char *obj_id, void *commit_list)
{
    void *data = NULL;
    int data_len;
    GList **cur_list = (GList **)commit_list;

    int ret = seaf_obj_store_read_obj (seaf->commit_mgr->obj_store, repo_id,
                                       version, obj_id, &data, &data_len);
    if (ret < 0 || data == NULL)
        return TRUE;

    SeafCommit *cur_commit = seaf_commit_from_data (obj_id, data, data_len);
    if (cur_commit != NULL) {
       *cur_list = g_list_prepend (*cur_list, cur_commit);
    }

    g_free(data);
    return TRUE;
}

static SeafCommit*
cre_commit_from_parent (char *repo_id, SeafCommit *parent)
{
    SeafCommit *new_commit = NULL;
    new_commit = seaf_commit_new (NULL, repo_id, parent->root_id,
                                  parent->creator_name, parent->creator_id,
                                  parent->desc, 0);
    if (new_commit) {
        new_commit->parent_id = g_strdup (parent->commit_id);
        new_commit->repo_name = g_strdup (parent->repo_name);
        new_commit->repo_desc = g_strdup (parent->repo_desc);
        new_commit->encrypted = parent->encrypted;
        if (new_commit->encrypted) {
            new_commit->enc_version = parent->enc_version;
            if (new_commit->enc_version >= 1)
                new_commit->magic = g_strdup (parent->magic);
            if (new_commit->enc_version == 2)
                new_commit->random_key = g_strdup (parent->random_key);
        }
        new_commit->repo_category = g_strdup (parent->repo_category);
        new_commit->no_local_history = parent->no_local_history;
        new_commit->version = parent->version;
        new_commit->repaired = TRUE;
    }

    return new_commit;
}

static int
recover_corrupted_repo_head (char *repo_id)
{
    GList *commit_list = NULL;
    GList *temp_list = NULL;
    SeafCommit *temp_commit = NULL;
    SeafBranch *branch = NULL;
    SeafRepo *repo = NULL;
    SeafVirtRepo *vinfo = NULL;
    FsckRes res;
    int rc = -1;

    seaf_message ("Recovering corrupt head commit for repo %.8s.\n", repo_id);

    seaf_obj_store_foreach_obj (seaf->commit_mgr->obj_store, repo_id,
                                1, fsck_get_repo_commit, &commit_list);

    if (commit_list == NULL)
        return rc;

    commit_list = g_list_sort (commit_list, compare_commit_by_ctime);
    memset (&res, 0, sizeof(res));
    res.existing_blocks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                 g_free, NULL);


    for (temp_list = commit_list; temp_list; temp_list = temp_list->next) {
        temp_commit = temp_list->data;

        branch = seaf_branch_new ("master", repo_id, temp_commit->commit_id);
        if (branch == NULL) {
            continue;
        }
        repo = seaf_repo_new (repo_id, NULL, NULL);
        if (repo == NULL) {
            seaf_branch_unref (branch);
            continue;
        }
        repo->head = branch;
        seaf_repo_from_commit (repo, temp_commit);
        vinfo = seaf_repo_manager_get_virtual_repo_info (seaf->repo_mgr, repo_id);
        if (vinfo) {
            repo->is_virtual = TRUE;
            memcpy (repo->store_id, vinfo->origin_repo_id, 36);
        } else {
            repo->is_virtual = FALSE;
            memcpy (repo->store_id, repo->id, 36);
        }
        seaf_virtual_repo_info_free (vinfo);

        res.repo = repo;
        rc = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                            repo->store_id,
                                            repo->version,
                                            temp_commit->root_id,
                                            fs_callback,
                                            &res, FALSE);

        if (rc < 0) {
            seaf_repo_unref (repo);
        } else {
            break;
        }
    }

    if (rc < 0) {
        seaf_warning ("Failed to fix head commit of repo %.8s.\n", repo_id);
    } else {
        // create new head commit, and set it's parent commit as latest avaliable commit
        temp_commit = cre_commit_from_parent (repo_id, temp_commit);
        if (temp_commit) {
            seaf_branch_set_commit (repo->head, temp_commit->commit_id);
            // in case of branch col miss, using add_branch instead of update_branch
            if (seaf_branch_manager_add_branch (seaf->branch_mgr, repo->head) < 0) {
                seaf_warning ("Failed to fix head commit of repo %.8s.\n", repo_id);
                rc = -1;
            } else {
                seaf_commit_manager_add_commit (seaf->commit_mgr, temp_commit);
                seaf_message ("Head commit of repo %.8s has been fixed to commit %.8s.\n",
                              repo_id, temp_commit->commit_id);
            }
            seaf_commit_unref (temp_commit);
        } else {
            seaf_warning ("Failed to fix head commit of repo %.8s.\n", repo_id);
            rc = -1;
        }
    }

    g_hash_table_destroy (res.existing_blocks);
    seaf_repo_unref (repo);
    for (temp_list = commit_list; temp_list; temp_list = temp_list->next) {
        temp_commit = temp_list->data;
        seaf_commit_unref (temp_commit);
    }
    g_list_free (commit_list);

    return rc;
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
    SeafCommit *rep_commit;
    SeafCommit *new_commit;

    seaf_message ("Checking file system integrity of repo %s(%.8s)...\n",
                  repo->name, repo->id);

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
        recover_corrupted_repo_head (repo->id);
        return;
    }

    /* If the current head is not consistent, reset it. */
    if (strcmp (res.consistent_head, repo->head->commit_id) != 0) {
        rep_commit = seaf_commit_manager_get_commit (seaf->commit_mgr, repo->id,
                                                     repo->version, res.consistent_head);
        if (rep_commit) {
            new_commit = cre_commit_from_parent (repo->id, rep_commit);
            if (new_commit == NULL) {
                seaf_warning ("Failed to update branch head.\n");
            } else {
                seaf_message ("Resetting head of repo %.8s to commit %.8s.\n",
                              repo->id, new_commit->commit_id);
                seaf_branch_set_commit (repo->head, new_commit->commit_id);
                if (seaf_branch_manager_update_branch (seaf->branch_mgr, repo->head) < 0) {
                    seaf_warning ("Failed to update branch head.\n");
                } else {
                    seaf_commit_manager_add_commit (seaf->commit_mgr, new_commit);
                }
                seaf_commit_unref (new_commit);
            }
            seaf_commit_unref (rep_commit);
        } else {
            seaf_warning ("Failed to update branch head.\n");
        }
    }

    g_free (res.consistent_head);
}

int
seaf_fsck (GList *repo_id_list)
{
    if (!repo_id_list)
        repo_id_list = seaf_repo_manager_get_repo_id_list (seaf->repo_mgr);

    GList *ptr;
    char *repo_id;
    SeafRepo *repo;

    for (ptr = repo_id_list; ptr; ptr = ptr->next) {
        repo_id = ptr->data;

        seaf_message ("Running fsck for repo %.8s.\n", repo_id);

        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
        if (!repo) {
            if (recover_corrupted_repo_head (repo_id) < 0) {
                seaf_warning ("Failed to recover repo %.8s.\n\n", repo_id);
            } else
                seaf_message ("Fsck finished for repo %.8s.\n\n", repo_id);
            continue;
        }

        check_and_reset_consistent_state (repo);

        seaf_message ("Fsck finished for repo %.8s.\n\n", repo_id);

        seaf_repo_unref (repo);
    }
    return 0;
}
