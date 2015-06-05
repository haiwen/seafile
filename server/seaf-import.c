#include "common.h"
#include "log.h"
#include "utils.h"

#include "seafile-session.h"

static char*
import_dir_recursive (SeafRepo *repo, const char *path,
                      const char *owner, gint64 *total_size)
{
    GError *error = NULL;
    GDir *dir = g_dir_open (path, 0, &error);
    if (!dir) {
        seaf_warning ("Failed to open dir %s: %s.\n", path, error->message);
        g_clear_error (&error);
        return NULL;
    }

    const char *file_name;
    SeafStat stat;
    char *cur_path;
    gint64 file_size;
    unsigned char sha1[20];
    char hex[41];
    SeafDirent *dirent;
    GList *dirents = NULL;
    char *cur_dir_id;
    char *root_id = NULL;

    while ((file_name = g_dir_read_name (dir)) != NULL) {
        cur_path = g_build_filename (path, file_name, NULL);
        if (seaf_stat (cur_path, &stat) < 0) {
            seaf_warning ("Failed to stat %s.\n", cur_path);
            g_free (cur_path);
            goto out;
        }

        if (S_ISREG (stat.st_mode)) {
            if (seaf_fs_manager_index_blocks (seaf->fs_mgr,
                                              repo->id, repo->version,
                                              cur_path,
                                              sha1, &file_size, NULL, TRUE) < 0) {
                seaf_warning ("Failed to index blocks for file %s.\n", cur_path);
                g_free (cur_path);
                goto out;
            }

            rawdata_to_hex (sha1, hex, 20);
            dirent = seaf_dirent_new (dir_version_from_repo_version (repo->version),
                                      hex, S_IFREG, file_name,
                                      stat.st_mtime, owner, file_size);
            dirents = g_list_prepend (dirents, dirent);
            *total_size += file_size;
            seaf_message ("Import file %s successfully.\n", cur_path);
        } else if (S_ISDIR (stat.st_mode)) {
            cur_dir_id = import_dir_recursive (repo, cur_path, owner, total_size);
            if (!cur_dir_id) {
                g_free (cur_path);
                goto out;
            }
            dirent = seaf_dirent_new (dir_version_from_repo_version (repo->version),
                                      cur_dir_id, S_IFDIR, file_name,
                                      stat.st_mtime, owner, -1);
            g_free (cur_dir_id);
            dirents = g_list_prepend (dirents, dirent);
            seaf_message ("Import dir %s successfully.\n", cur_path);
        }
        g_free (cur_path);
    }

    SeafDir *root_dir = seaf_dir_new (NULL, dirents,
                                      dir_version_from_repo_version(repo->version));
    if (seaf_dir_save (seaf->fs_mgr, repo->id, repo->version, root_dir) < 0) {
        seaf_warning ("Failed to save SeafDir to disk.\n");
        seaf_dir_free (root_dir);
        goto out;
    }
    root_id = g_strdup (root_dir->dir_id);
    seaf_dir_free (root_dir);
    g_dir_close (dir);

    return root_id;

out:
    g_dir_close (dir);
    g_list_free_full (dirents, (GDestroyNotify)seaf_dirent_free);

    return root_id;
}

static void
import_dir (const char *repo_id, const char *path, const char *owner)
{
    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get new created repo(%.8s), import failed.\n", repo_id);
        return;
    }

    gint64 size = 0;
    char *root_id = import_dir_recursive (repo, path, owner, &size);

    if (!root_id) {
        seaf_warning ("Failed to import dir %s to repo %.8s, import failed.\n",
                      path, repo_id);
        seaf_repo_unref (repo);
        return;
    }

    char *desc = g_strdup_printf ("Import dir \"%s\"", path);
    SeafCommit *new_commit = seaf_commit_new(NULL, repo->id, root_id,
                                             owner, EMPTY_SHA1,
                                             desc, 0);
    new_commit->parent_id = g_strdup (repo->head->commit_id);
    seaf_repo_to_commit (repo, new_commit);
    g_free (desc);
    g_free (root_id);

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, new_commit) < 0) {
        seaf_warning ("Failed to add new commit, import failed.\n");
        goto out;
    }

    SeafDBTrans *trans = seaf_db_begin_transaction (seaf->db);
    if (!trans) {
        seaf_warning ("Failed to begin transaction from db, import failed.\n");
        goto out;
    }

    if (seaf_db_trans_query (trans,
                             "UPDATE Branch SET commit_id = ? "
                             "WHERE name = ? AND repo_id = ?",
                             3, "string", new_commit->commit_id,
                             "string", repo->head->name, "string", repo_id) < 0) {
        seaf_warning ("Failed to update head commit, import failed.\n");
        seaf_db_rollback (trans);
        seaf_db_trans_close (trans);
        goto out;
    }

    if (seaf_db_trans_query (trans,
                             "INSERT INTO RepoSize (repo_id, head_id, size) "
                             "VALUES (?, ?, ?)", 3, "string", repo_id,
                             "string", new_commit->commit_id, "int64", size) < 0) {
        seaf_warning ("Failed to set repo size, import failed.\n");
        seaf_db_rollback (trans);
        seaf_db_trans_close (trans);
        goto out;
    }

    if (seaf_db_commit (trans) < 0) {
        seaf_warning ("Failed to commit db transaction, import failed.\n");
        seaf_db_rollback (trans);
    } else {
        seaf_message ("Import dir %s to repo %.8s successfully.\n", path, repo_id);
    }

    seaf_db_trans_close (trans);

out:
    seaf_commit_unref (new_commit);
    seaf_repo_unref (repo);
}

void
seaf_import_dir (const char *path, const char *repo_name, const char *owner)
{
    if (checkdir (path) < 0) {
        seaf_warning ("Invalid imported path: %s, import failed.\n", path);
        return;
    }

    GError *error = NULL;
    char *repo_id = seaf_repo_manager_create_new_repo (seaf->repo_mgr, repo_name,
                                                       "", owner, NULL, &error);
    if (!repo_id) {
        if (error) {
            seaf_warning ("Failed to create repo: %s, import failed.\n", error->message);
            g_clear_error (&error);
        } else {
            seaf_warning ("Failed to create repo, import failed.\n");
        }
        return;
    }

    import_dir (repo_id, path, owner);

    g_free (repo_id);
}
