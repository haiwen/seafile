#include "common.h"

#include <fcntl.h>

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
            seaf_message ("File %s is corrupted, remove it.\n", obj_id);
            seaf_fs_manager_delete_object (seaf->fs_mgr, store_id, version, obj_id);
        }
    } else if (type == VERIFY_DIR) {
        valid = seaf_fs_manager_verify_seafdir (seaf->fs_mgr, store_id, version,
                                                obj_id, TRUE, io_error);
        if (!valid && !*io_error && repair) {
            seaf_message ("Dir %s is corrupted, remove it.\n", obj_id);
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
                    seaf_message ("File %s(%.8s) is corrupted, recreate an empty file.\n",
                                  path, seaf_dent->id);
                } else {
                    seaf_message ("File %s(%.8s) is corrupted.\n",
                                  path, seaf_dent->id);
                }
                // file corrupted, set it empty
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
                        seaf_message ("File %s(%.8s) is corrupted, recreate an empty file.\n",
                                      path, seaf_dent->id);
                    } else {
                        seaf_message ("File %s(%.8s) is corrupted.\n",
                                      path, seaf_dent->id);
                    }
                    // file corrupted, set it empty
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
                    seaf_message ("Dir %s(%.8s) is corrupted, recreate an empty dir.\n",
                                  path, seaf_dent->id);
                } else {
                    seaf_message ("Dir %s(%.8s) is corrupted.\n",
                                  path, seaf_dent->id);
                }
                is_corrupted = TRUE;
                // dir corrupted, set it empty
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
                   // dir corrupted, set it to new dir_id
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
            // fs object of this commit is corrupted,
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
 * check and recover repo, for corrupted file or folder set it empty
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
            // some fs objects corrupted for the head commit,
            // create new head commit using the new root_id
            reset_commit_to_repair (repo, rep_commit, root_id);
        } else if (reset) {
            // for reset commit but fs objects not corrupted, also create a repaired commit
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
                    // root fs object is corrupted, get available commit
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

/*static gboolean
write_enc_block_to_file (const char *repo_id,
                         int version,
                         const char *block_id,
                         SeafileCrypt *crypt,
                         int fd,
                         const char *path)
{
    BlockHandle *handle;
    BlockMetadata *bmd;
    char buf[64 * 1024];
    int n;
    int remain;
    EVP_CIPHER_CTX ctx;
    char *dec_out;
    int dec_out_len;
    gboolean ret = TRUE;

    bmd = seaf_block_manager_stat_block (seaf->block_mgr,
                                         repo_id, version,
                                         block_id);
    if (!bmd) {
        seaf_warning ("Failed to stat block %s.\n", block_id);
        return FALSE;
    }

    handle = seaf_block_manager_open_block (seaf->block_mgr,
                                            repo_id, version,
                                            block_id, BLOCK_READ);
    if (!handle) {
        seaf_warning ("Failed to open block %s.\n", block_id);
        g_free (bmd);
        return FALSE;
    }

    if (seafile_decrypt_init (&ctx, crypt->version,
                              crypt->key, crypt->iv) < 0) {
        seaf_warning ("Failed to init decrypt.\n");
        ret = FALSE;
        goto out;
    }

    remain = bmd->size;
    while (1) {
        n = seaf_block_manager_read_block (seaf->block_mgr, handle, buf, sizeof(buf));
        if (n < 0) {
            seaf_warning ("Failed to read block %s.\n", block_id);
            ret = FALSE;
            break;
        } else if (n == 0) {
            break;
        }
        remain -= n;

        dec_out = g_new0 (char, n + 16);
        if (!dec_out) {
            seaf_warning ("Failed to alloc memory.\n");
            ret = FALSE;
            break;
        }

        if (EVP_DecryptUpdate (&ctx,
                               (unsigned char *)dec_out,
                               &dec_out_len,
                               (unsigned char *)buf,
                               n) == 0) {
            seaf_warning ("Failed to decrypt block %s .\n", block_id);
            g_free (dec_out);
            ret = FALSE;
            break;
        }

        if (writen (fd, dec_out, dec_out_len) != dec_out_len) {
            seaf_warning ("Failed to write block %s to file %s.\n",
                          block_id, path);
            g_free (dec_out);
            ret = FALSE;
            break;
        }

        if (remain == 0) {
            if (EVP_DecryptFinal_ex (&ctx,
                                     (unsigned char *)dec_out,
                                     &dec_out_len) == 0) {
                seaf_warning ("Failed to decrypt block %s .\n", block_id);
                g_free (dec_out);
                ret = FALSE;
                break;
            }
            if (dec_out_len > 0) {
                if (writen (fd, dec_out, dec_out_len) != dec_out_len) {
                    seaf_warning ("Failed to write block %s to file %s.\n",
                                  block_id, path);
                    g_free (dec_out);
                    ret = FALSE;
                    break;
                }
            }
        }

        g_free (dec_out);
    }

    EVP_CIPHER_CTX_cleanup (&ctx);

out:
    g_free (bmd);
    seaf_block_manager_close_block (seaf->block_mgr, handle);
    seaf_block_manager_block_handle_free (seaf->block_mgr, handle);

    return ret;
}*/

static gboolean
write_nonenc_block_to_file (const char *repo_id,
                            int version,
                            const char *block_id,
                            int fd,
                            const char *path)
{
    BlockHandle *handle;
    char buf[64 * 1024];
    gboolean ret = TRUE;
    int n;

    handle = seaf_block_manager_open_block (seaf->block_mgr,
                                            repo_id, version,
                                            block_id, BLOCK_READ);
    if (!handle) {
        return FALSE;
    }

    while (1) {
        n = seaf_block_manager_read_block (seaf->block_mgr, handle, buf, sizeof(buf));
        if (n < 0) {
            seaf_warning ("Failed to read block %s.\n", block_id);
            ret = FALSE;
            break;
        } else if (n == 0) {
            break;
        }

        if (writen (fd, buf, n) != n) {
            seaf_warning ("Failed to write block %s to file %s.\n",
                          block_id, path);
            ret = FALSE;
            break;
        }
    }

    seaf_block_manager_close_block (seaf->block_mgr, handle);
    seaf_block_manager_block_handle_free (seaf->block_mgr, handle);

    return ret;
}

static void
create_file (const char *repo_id,
             const char *file_id,
             const char *path)
{
    int i;
    char *block_id;
    int fd;
    Seafile *seafile;
    gboolean ret = TRUE;
    int version = 1;

    fd = g_open (path, O_CREAT | O_WRONLY | O_BINARY, 0666);
    if (fd < 0) {
        seaf_warning ("Open file %s failed: %s.\n", path, strerror (errno));
        return;
    }

    seafile = seaf_fs_manager_get_seafile (seaf->fs_mgr, repo_id,
                                           version, file_id);
    if (!seafile) {
        ret = FALSE;
        goto out;
    }

    for (i = 0; i < seafile->n_blocks; ++i) {
        block_id = seafile->blk_sha1s[i];

        ret = write_nonenc_block_to_file (repo_id, version, block_id,
                                          fd, path);
        if (!ret) {
            break;
        }
    }

out:
    close (fd);
    if (!ret) {
        if (g_unlink (path) < 0) {
            seaf_warning ("Failed to delete file %s: %s.\n", path, strerror (errno));
        }
        seaf_message ("Failed to export file %s.\n", path);
    } else {
        seaf_message ("Export file %s.\n", path);
    }
    seafile_unref (seafile);
}

static void
export_repo_files_recursive (const char *repo_id,
                             const char *id,
                             const char *parent_dir)
{
    SeafDir *dir;
    GList *p;
    SeafDirent *seaf_dent;
    char *path;

    SeafFSManager *mgr = seaf->fs_mgr;
    int version = 1;

    dir = seaf_fs_manager_get_seafdir (mgr, repo_id, version, id);
    if (!dir) {
        return;
    }

    for (p = dir->entries; p; p = p->next) {
        seaf_dent = p->data;
        path = g_build_filename (parent_dir, seaf_dent->name, NULL);

        if (S_ISREG(seaf_dent->mode)) {
            // create file
            create_file (repo_id, seaf_dent->id, path);
        } else if (S_ISDIR(seaf_dent->mode)) {
            if (g_mkdir (path, 0777) < 0) {
                seaf_warning ("Failed to mkdir %s: %s.\n", path,
                              strerror (errno));
                g_free (path);
                continue;
            } else {
                seaf_message ("Export dir %s.\n", path);
            }

            export_repo_files_recursive (repo_id, seaf_dent->id, path);
        }
        g_free (path);
    }

    seaf_dir_free (dir);
}

static SeafCommit*
get_available_commit (const char *repo_id)
{
    GList *commit_list = NULL;
    GList *temp_list = NULL;
    GList *next_list = NULL;
    SeafCommit *temp_commit = NULL;
    gboolean io_error;

    seaf_message ("Scanning available commits for repo %s...\n", repo_id);

    seaf_obj_store_foreach_obj (seaf->commit_mgr->obj_store, repo_id,
                                1, fsck_get_repo_commit, &commit_list);

    if (commit_list == NULL) {
        seaf_warning ("No available commits for repo %.8s, export failed.\n\n",
                      repo_id);
        return NULL;
    }

    commit_list = g_list_sort (commit_list, compare_commit_by_ctime);
    temp_list = commit_list;
    while (temp_list) {
        next_list = temp_list->next;
        temp_commit = temp_list->data;
        io_error = FALSE;

        if (memcmp (temp_commit->root_id, EMPTY_SHA1, 40) == 0) {
            seaf_commit_unref (temp_commit);
            temp_commit = NULL;
            temp_list = next_list;
            continue;
        } else if (!fsck_verify_seafobj (repo_id, 1, temp_commit->root_id,
                                         &io_error, VERIFY_DIR, FALSE)) {
            seaf_commit_unref (temp_commit);
            temp_commit = NULL;
            temp_list = next_list;

            if (io_error) {
                seaf_warning ("IO error, stop to export files for repo %.8s.\n\n",
                              repo_id);
                break;
            }
            // fs object of this commit is corrupted,
            // continue to verify next
            continue;
        }

        char time_buf[64];
        strftime (time_buf, 64, "%Y-%m-%d %H:%M:%S", localtime((time_t *)&temp_commit->ctime));
        seaf_message ("Find available commit %.8s(created at %s), will export files from it.\n",
                      temp_commit->commit_id, time_buf);
        temp_list = next_list;
        break;
    }

    while (temp_list) {
        seaf_commit_unref (temp_list->data);
        temp_list = temp_list->next;
    }
    g_list_free (commit_list);

    if (!temp_commit && !io_error) {
        seaf_warning ("No available commits for repo %.8s, export failed.\n\n",
                      repo_id);
    }

    return temp_commit;
}

void
export_repo_files (const char *repo_id,
                   const char *init_path,
                   GHashTable *enc_repos)
{
    SeafCommit *commit = get_available_commit (repo_id);
    if (!commit) {
        return;
    }
    if (commit->encrypted) {
        g_hash_table_insert (enc_repos, g_strdup (repo_id),
                             g_strdup (commit->repo_name));
        seaf_commit_unref (commit);
        return;
    }

    seaf_message ("Start to export files for repo %.8s(%s).\n",
                  repo_id, commit->repo_name);

    char *dir_name = g_strdup_printf ("%.8s_%s_%s", repo_id,
                                      commit->repo_name,
                                      commit->creator_name);
    char * export_path = g_build_filename (init_path, dir_name, NULL);
    g_free (dir_name);
    if (g_mkdir (export_path, 0777) < 0) {
        seaf_warning ("Failed to create export dir %s: %s, export failed.\n",
                      export_path, strerror (errno));
        g_free (export_path);
        seaf_commit_unref (commit);
        return;
    }

    export_repo_files_recursive (repo_id, commit->root_id, export_path);

    seaf_message ("Finish exporting files for repo %.8s.\n\n", repo_id);

    g_free (export_path);
    seaf_commit_unref (commit);
}

static GList *
get_repo_ids (const char *seafile_dir)
{
    GList *repo_ids = NULL;
    char *commit_path = g_build_filename (seafile_dir, "storage",
                                          "commits", NULL);
    GError *error = NULL;

    GDir *dir = g_dir_open (commit_path, 0, &error);
    if (!dir) {
        seaf_warning ("Open dir %s failed: %s.\n",
                      commit_path, error->message);
        g_clear_error (&error);
        g_free (commit_path);
        return NULL;
    }

    const char *file_name;
    while ((file_name = g_dir_read_name (dir)) != NULL) {
        repo_ids = g_list_prepend (repo_ids, g_strdup (file_name));
    }
    g_dir_close (dir);

    g_free (commit_path);

    return repo_ids;
}

static void
print_enc_repo (gpointer key, gpointer value, gpointer user_data)
{
    seaf_message ("%s(%s)\n", (char *)key, (char *)value);
}

void
export_file (GList *repo_id_list, const char *seafile_dir, char *export_path)
{
    struct stat dir_st;

    if (stat (export_path, &dir_st) < 0) {
        if (errno == ENOENT) {
            if (g_mkdir (export_path, 0777) < 0) {
                seaf_warning ("Mkdir %s failed: %s.\n",
                              export_path, strerror (errno));
                return;
            }
        } else {
            seaf_warning ("Stat path: %s failed: %s.\n",
                          export_path, strerror (errno));
            return;
        }
    } else {
        if (!S_ISDIR(dir_st.st_mode)) {
            seaf_warning ("%s already exist, but it is not a directory.\n",
                          export_path);
            return;
        }
    }

    if (!repo_id_list) {
        repo_id_list = get_repo_ids (seafile_dir);
        if (!repo_id_list)
            return;
    }

    GList *iter = repo_id_list;
    char *repo_id;
    GHashTable *enc_repos = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                   g_free, g_free);

    for (; iter; iter=iter->next) {
        repo_id = iter->data;
        if (!is_uuid_valid (repo_id)) {
            seaf_warning ("Invalid repo id: %s.\n", repo_id);
            continue;
        }

        export_repo_files (repo_id, export_path, enc_repos);
    }

    if (g_hash_table_size (enc_repos) > 0) {
        seaf_message ("The following repos are encrypted and are not exported:\n");
        g_hash_table_foreach (enc_repos, print_enc_repo, NULL);
    }

    while (repo_id_list) {
        g_free (repo_id_list->data);
        repo_id_list = g_list_delete_link (repo_id_list, repo_id_list);
    }
    g_hash_table_destroy (enc_repos);
    g_free (export_path);
}
