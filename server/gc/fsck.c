#include "common.h"

#include "seafile-session.h"
#include "log.h"
#include "utils.h"

#include "fsck.h"

typedef struct FsckData {
    gboolean repair;
    SeafRepo *repo;
    GHashTable *existing_blocks;
} FsckData;

typedef enum VerifyType {
    VERIFY_FILE,
    VERIFY_DIR
} VerifyType;

static gboolean
fsck_verify_seafobj (const char *store_id,
                     int version,
                     const char *obj_id,
                     gboolean *io_error,
                     VerifyType type,
                     gboolean repair)
{
    gboolean valid = TRUE;

    valid = seaf_fs_manager_object_exists (seaf->fs_mgr, store_id,
                                           version, obj_id);
    if (!valid) {
        if (type == VERIFY_FILE) {
            seaf_message ("File %s is missing.\n", obj_id);
        }  else if (type == VERIFY_DIR) {
            seaf_message ("Dir %s is missing.\n", obj_id);
        }
        return valid;
    }

    if (type == VERIFY_FILE) {
        valid = seaf_fs_manager_verify_seafile (seaf->fs_mgr, store_id, version,
                                                obj_id, TRUE, io_error);
        if (!valid && !*io_error && repair) {
            seaf_message ("File %s is curropted, remove it.\n", obj_id);
            seaf_fs_manager_delete_object (seaf->fs_mgr, store_id, version, obj_id);
        }
    } else if (type == VERIFY_DIR) {
        valid = seaf_fs_manager_verify_seafdir (seaf->fs_mgr, store_id, version,
                                                obj_id, TRUE, io_error);
        if (!valid && !*io_error && repair) {
            seaf_message ("Dir %s is curropted, remove it.\n", obj_id);
            seaf_fs_manager_delete_object (seaf->fs_mgr, store_id, version, obj_id);
        }
    }

    return valid;
}

static int
check_blocks (const char *file_id, FsckData *fsck_data, gboolean *io_error)
{
    Seafile *seafile;
    int i;
    char *block_id;
    int ret = 0;
    int dummy;

    gboolean ok = TRUE;
    SeafRepo *repo = fsck_data->repo;
    const char *store_id = repo->store_id;
    int version = repo->version;

    seafile = seaf_fs_manager_get_seafile (seaf->fs_mgr, store_id,
                                           version, file_id);

    for (i = 0; i < seafile->n_blocks; ++i) {
        block_id = seafile->blk_sha1s[i];

        if (g_hash_table_lookup (fsck_data->existing_blocks, block_id))
            continue;

        if (!seaf_block_manager_block_exists (seaf->block_mgr,
                                              store_id, version,
                                              block_id)) {
            seaf_warning ("Block %s is missing.\n", block_id);
            ret = -1;
            break;
        }

        // check block integrity, if not remove it
        ok = seaf_block_manager_verify_block (seaf->block_mgr,
                                              store_id, version,
                                              block_id, io_error);
        if (!ok) {
            if (*io_error) {
                ret = -1;
                break;
            } else {
                if (fsck_data->repair) {
                    seaf_message ("Block %s is corrupted, remove it.\n", block_id);
                    seaf_block_manager_remove_block (seaf->block_mgr,
                                                     store_id, version,
                                                     block_id);
                } else {
                    seaf_message ("Block %s is corrupted.\n", block_id);
                }
                ret = -1;
                break;
            }
        }

        g_hash_table_insert (fsck_data->existing_blocks, g_strdup(block_id), &dummy);
    }

    seafile_unref (seafile);

    return ret;
}

static char*
fsck_check_dir_recursive (const char *id, const char *parent_dir, FsckData *fsck_data)
{
    SeafDir *dir;
    SeafDir *new_dir;
    GList *p;
    SeafDirent *seaf_dent;
    char *dir_id = NULL;
    char *path = NULL;
    gboolean io_error = FALSE;

    SeafFSManager *mgr = seaf->fs_mgr;
    char *store_id = fsck_data->repo->store_id;
    int version = fsck_data->repo->version;
    gboolean is_corrupted = FALSE;

    dir = seaf_fs_manager_get_seafdir (mgr, store_id, version, id);

    for (p = dir->entries; p; p = p->next) {
        seaf_dent = p->data;
        io_error = FALSE;

        if (S_ISREG(seaf_dent->mode)) {
            path = g_strdup_printf ("%s%s", parent_dir, seaf_dent->name);
            if (!path) {
                seaf_warning ("Out of memory, stop to run fsck for repo %.8s.\n",
                              fsck_data->repo->id);
                goto out;
            }
            if (!fsck_verify_seafobj (store_id, version,
                                      seaf_dent->id, &io_error,
                                      VERIFY_FILE, fsck_data->repair)) {
                if (io_error) {
                    g_free (path);
                    goto out;
                }
                is_corrupted = TRUE;
                if (fsck_data->repair) {
                    seaf_message ("File %s(%.8s) is curropted, recreate an empty file.\n",
                                  path, seaf_dent->id);
                } else {
                    seaf_message ("File %s(%.8s) is curropted.\n",
                                  path, seaf_dent->id);
                }
                // file curropted, set it empty
                memcpy (seaf_dent->id, EMPTY_SHA1, 40);
                seaf_dent->size = 0;
            } else {
                if (check_blocks (seaf_dent->id, fsck_data, &io_error) < 0) {
                    if (io_error) {
                        g_free (path);
                        goto out;
                    }
                    is_corrupted = TRUE;
                    if (fsck_data->repair) {
                        seaf_message ("File %s(%.8s) is curropted, recreate an empty file.\n",
                                      path, seaf_dent->id);
                    } else {
                        seaf_message ("File %s(%.8s) is curropted.\n",
                                      path, seaf_dent->id);
                    }
                    // file curropted, set it empty
                    memcpy (seaf_dent->id, EMPTY_SHA1, 40);
                    seaf_dent->size = 0;
                }
            }
            g_free (path);
        } else if (S_ISDIR(seaf_dent->mode)) {
            path = g_strdup_printf ("%s%s/", parent_dir, seaf_dent->name);
            if (!path) {
                seaf_warning ("Out of memory, stop to run fsck for repo %.8s.\n",
                              fsck_data->repo->id);
                goto out;
            }
            if (!fsck_verify_seafobj (store_id, version,
                                      seaf_dent->id, &io_error,
                                      VERIFY_DIR, fsck_data->repair)) {
                if (io_error) {
                    g_free (path);
                    goto out;
                }
                if (fsck_data->repair) {
                    seaf_message ("Dir %s(%.8s) is curropted, recreate an empty dir.\n",
                                  path, seaf_dent->id);
                } else {
                    seaf_message ("Dir %s(%.8s) is curropted.\n",
                                  path, seaf_dent->id);
                }
                is_corrupted = TRUE;
                // dir curropted, set it empty
                memcpy (seaf_dent->id, EMPTY_SHA1, 40);
            } else {
               dir_id = fsck_check_dir_recursive (seaf_dent->id, path, fsck_data);
               if (dir_id == NULL) {
                   // IO error
                   g_free (path);
                   goto out;
               }
               if (strcmp (dir_id, seaf_dent->id) != 0) {
                   is_corrupted = TRUE;
                   // dir curropted, set it to new dir_id
                   memcpy (seaf_dent->id, dir_id, 41);
               }
               g_free (dir_id);
           }
           g_free (path);
        }
    }

    if (is_corrupted) {
        new_dir = seaf_dir_new (NULL, dir->entries, version);
        if (fsck_data->repair) {
            seaf_dir_save (mgr, store_id, version, new_dir);
        }
        dir_id = g_strdup (new_dir->dir_id);
        seaf_dir_free (new_dir);
        dir->entries = NULL;
    } else {
        dir_id = g_strdup (dir->dir_id);
    }

out:
    seaf_dir_free (dir);

    if (io_error) {
        seaf_message ("IO error, stop to run fsck for repo %.8s.\n",
                      fsck_data->repo->id);
    }

    return dir_id;
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

static void
reset_commit_to_repair (SeafRepo *repo, SeafCommit *parent, char *new_root_id)
{
    SeafCommit *new_commit = NULL;
    new_commit = seaf_commit_new (NULL, repo->id, new_root_id,
                                  parent->creator_name, parent->creator_id,
                                  "Repaired by system", 0);
    if (!new_commit) {
        seaf_warning ("Out of memory, stop to run fsck for repo %.8s.\n",
                      repo->id);
        return;
    }

    new_commit->parent_id = g_strdup (parent->commit_id);
    seaf_repo_to_commit (repo, new_commit);
    new_commit->repaired = TRUE;

    seaf_message ("Revert repo %.8s status to commit %.8s.\n",
                  repo->id, new_commit->commit_id);
    seaf_branch_set_commit (repo->head, new_commit->commit_id);
    if (seaf_branch_manager_add_branch (seaf->branch_mgr, repo->head) < 0) {
        seaf_warning ("Reset head of repo %.8s to commit %.8s failed, "
                      "recover failed.\n", repo->id, new_commit->commit_id);
    } else {
        seaf_commit_manager_add_commit (seaf->commit_mgr, new_commit);
    }
    seaf_commit_unref (new_commit);
}

static SeafRepo*
get_available_repo (char *repo_id, gboolean repair)
{
    GList *commit_list = NULL;
    GList *temp_list = NULL;
    SeafCommit *temp_commit = NULL;
    SeafBranch *branch = NULL;
    SeafRepo *repo = NULL;
    SeafVirtRepo *vinfo = NULL;
    gboolean io_error;

    seaf_message ("Scanning available commits...\n");

    seaf_obj_store_foreach_obj (seaf->commit_mgr->obj_store, repo_id,
                                1, fsck_get_repo_commit, &commit_list);

    if (commit_list == NULL) {
        seaf_warning ("No available commits for repo %.8s, can't be repaired.\n",
                      repo_id);
        return NULL;
    }

    commit_list = g_list_sort (commit_list, compare_commit_by_ctime);

    repo = seaf_repo_new (repo_id, NULL, NULL);
    if (repo == NULL) {
        seaf_warning ("Out of memory, stop to run fsck for repo %.8s.\n",
                      repo_id);
        goto out;
    }

    vinfo = seaf_repo_manager_get_virtual_repo_info (seaf->repo_mgr, repo_id);
    if (vinfo) {
        repo->is_virtual = TRUE;
        memcpy (repo->store_id, vinfo->origin_repo_id, 36);
        seaf_virtual_repo_info_free (vinfo);
    } else {
        repo->is_virtual = FALSE;
        memcpy (repo->store_id, repo->id, 36);
    }

    for (temp_list = commit_list; temp_list; temp_list = temp_list->next) {
        temp_commit = temp_list->data;
        io_error = FALSE;

        if (!fsck_verify_seafobj (repo->store_id, 1, temp_commit->root_id,
                                  &io_error, VERIFY_DIR, repair)) {
            if (io_error) {
                seaf_warning ("IO error, stop to run fsck for repo %.8s.\n",
                              repo_id);
                seaf_repo_unref (repo);
                repo = NULL;
                goto out;
            }
            // fs object of this commit is curropted,
            // continue to verify next
            continue;
        }

        branch = seaf_branch_new ("master", repo_id, temp_commit->commit_id);
        if (branch == NULL) {
            seaf_warning ("Out of memory, stop to run fsck for repo %.8s.\n",
                          repo_id);
            seaf_repo_unref (repo);
            repo = NULL;
            goto out;
        }
        repo->head = branch;
        seaf_repo_from_commit (repo, temp_commit);

        char time_buf[64];
        strftime (time_buf, 64, "%Y-%m-%d %H:%M:%S", localtime((time_t *)&temp_commit->ctime));
        seaf_message ("Find available commit %.8s(created at %s) for repo %.8s.\n",
                      temp_commit->commit_id, time_buf, repo_id);
        break;
    }

out:
    for (temp_list = commit_list; temp_list; temp_list = temp_list->next) {
        temp_commit = temp_list->data;
        seaf_commit_unref (temp_commit);
    }
    g_list_free (commit_list);

    return repo;
}

/*
 * check and recover repo, for curropted file or folder set it empty
 */
static void
check_and_recover_repo (SeafRepo *repo, gboolean reset, gboolean repair)
{
    FsckData fsck_data;
    SeafCommit *rep_commit;

    seaf_message ("Checking file system integrity of repo %s(%.8s)...\n",
                  repo->name, repo->id);

    rep_commit = seaf_commit_manager_get_commit (seaf->commit_mgr, repo->id,
                                                 repo->version, repo->head->commit_id);

    memset (&fsck_data, 0, sizeof(fsck_data));
    fsck_data.repair = repair;
    fsck_data.repo = repo;
    fsck_data.existing_blocks = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                       g_free, NULL);

    char *root_id = fsck_check_dir_recursive (rep_commit->root_id, "/", &fsck_data);
    g_hash_table_destroy (fsck_data.existing_blocks);
    if (root_id == NULL)
        return;

    if (repair) {
        if (strcmp (root_id, rep_commit->root_id) != 0) {
            // some fs objects curropted for the head commit,
            // create new head commit using the new root_id
            reset_commit_to_repair (repo, rep_commit, root_id);
        } else if (reset) {
            // for reset commit but fs objects not curropted, also create a repaired commit
            reset_commit_to_repair (repo, rep_commit, rep_commit->root_id);
        }
    }

    g_free (root_id);
    seaf_commit_unref (rep_commit);
}

static void
enable_sync_repo (const char *repo_id)
{
    SeafRepo *repo = NULL;
    SeafCommit *parent_commit = NULL;
    SeafCommit *new_commit = NULL;
    gboolean exists;

    if (!is_uuid_valid (repo_id)) {
        seaf_warning ("Invalid repo id %s.\n", repo_id);
        return;
    }

    exists = seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id);
    if (!exists) {
        seaf_warning ("Repo %.8s doesn't exist.\n", repo_id);
        return;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo)
        return;

    parent_commit = seaf_commit_manager_get_commit_compatible (seaf->commit_mgr,
                                                               repo_id,
                                                               repo->head->commit_id);
    if (!parent_commit) {
        seaf_warning ("Commit %s is missing\n", repo->head->commit_id);
        goto out;
    }

    new_commit = seaf_commit_new (NULL, repo_id, parent_commit->root_id,
                                  parent_commit->creator_name,
                                  parent_commit->creator_id,
                                  "Enable sync repo", 0);
    if (!new_commit) {
        seaf_warning ("Out of memory when create commit.\n");
        goto out;
    }
    new_commit->parent_id = g_strdup (parent_commit->commit_id);
    seaf_repo_to_commit (repo, new_commit);
    new_commit->repaired = FALSE;

    if (seaf_commit_manager_add_commit (seaf->commit_mgr,
                                        new_commit) < 0) {
        seaf_warning ("Failed to save commit %.8s for repo %.8s.\n",
                      new_commit->commit_id, repo_id);
        goto out;
    }

    seaf_branch_set_commit (repo->head, new_commit->commit_id);
    if (seaf_branch_manager_update_branch (seaf->branch_mgr,
                                           repo->head) < 0) {
        seaf_warning ("Failed to update head commit %.8s to repo %.8s.\n",
                      new_commit->commit_id, repo_id);
    } else {
        seaf_message ("Enable sync repo %.8s success.\n",
                      repo_id);
    }

out:
    if (parent_commit)
        seaf_commit_unref (parent_commit);
    if (new_commit)
        seaf_commit_unref (new_commit);
    if (repo)
        seaf_repo_unref (repo);
}

static void
enable_sync_repos (GList *repo_id_list)
{
    GList *ptr;

    for (ptr = repo_id_list; ptr; ptr = ptr->next) {
        seaf_message ("Enabling sync repo %s.\n", (char *)ptr->data);
        enable_sync_repo (ptr->data);
    }
}

static void
repair_repos (GList *repo_id_list, gboolean repair)
{
    GList *ptr;
    char *repo_id;
    SeafRepo *repo;
    gboolean exists;
    gboolean reset;
    gboolean io_error;

    for (ptr = repo_id_list; ptr; ptr = ptr->next) {
        reset = FALSE;
        repo_id = ptr->data;

        seaf_message ("Running fsck for repo %s.\n", repo_id);

        if (!is_uuid_valid (repo_id)) {
            seaf_warning ("Invalid repo id %s.\n", repo_id);
            goto next;
        }

        exists = seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id);
        if (!exists) {
            seaf_warning ("Repo %.8s doesn't exist.\n", repo_id);
            goto next;
        }

        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);

        if (!repo) {
            seaf_message ("Repo %.8s HEAD commit is corrupted, "
                          "need to restore to an old version.\n", repo_id);
            repo = get_available_repo (repo_id, repair);
            if (!repo) {
                goto next;
            }
            reset = TRUE;
        } else {
            SeafCommit *commit = seaf_commit_manager_get_commit (seaf->commit_mgr, repo->id,
                                                                 repo->version,
                                                                 repo->head->commit_id);
            io_error = FALSE;
            if (!fsck_verify_seafobj (repo->store_id, repo->version,
                                      commit->root_id,  &io_error,
                                      VERIFY_DIR, repair)) {
                if (io_error) {
                    seaf_warning ("IO error, stop to run fsck for repo %s(%.8s).\n",
                                  repo->id, repo->name);
                    seaf_commit_unref (commit);
                    seaf_repo_unref (repo);
                    goto next;
                } else {
                    // root fs object is curropted, get available commit
                    seaf_message ("Repo %.8s HEAD commit is corrupted, "
                                  "need to restore to an old version.\n", repo_id);
                    seaf_commit_unref (commit);
                    seaf_repo_unref (repo);
                    repo = get_available_repo (repo_id, repair);
                    if (!repo) {
                        goto next;
                    }
                    reset = TRUE;
                }
            } else {
                // head commit is available
                seaf_commit_unref (commit);
            }
        }

        check_and_recover_repo (repo, reset, repair);

        seaf_repo_unref (repo);
next:
        seaf_message ("Fsck finished for repo %.8s.\n\n", repo_id);
    }
}

int
seaf_fsck (GList *repo_id_list, gboolean repair, gboolean esync)
{
    if (!repo_id_list)
        repo_id_list = seaf_repo_manager_get_repo_id_list (seaf->repo_mgr);

    if (esync) {
        enable_sync_repos (repo_id_list);
    } else {
        repair_repos (repo_id_list, repair);
    }

    while (repo_id_list) {
        g_free (repo_id_list->data);
        repo_id_list = g_list_delete_link (repo_id_list, repo_id_list);
    }

    return 0;
}
