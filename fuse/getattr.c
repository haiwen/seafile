#include "common.h"

#define FUSE_USE_VERSION  26
#include <fuse.h>

#include <glib.h>
#include <glib-object.h>

#include <ccnet.h>
#include <ccnet/ccnet-object.h>
#include <seaf-db.h>

#include "log.h"
#include "utils.h"

#include "seaf-fuse.h"
#include "seafile-session.h"

static CcnetEmailUser *get_user_from_ccnet (SearpcClient *client, const char *user)
{
    return (CcnetEmailUser *)searpc_client_call__object (client,
                                       "get_emailuser", CCNET_TYPE_EMAIL_USER, NULL,
                                       1, "string", user);
}

static int getattr_root(SeafileSession *seaf, struct stat *stbuf)
{
    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    stbuf->st_size = 4096;

    return 0;
}

static int getattr_user(SeafileSession *seaf, const char *user, struct stat *stbuf)
{
    SearpcClient *client;
    CcnetEmailUser *emailuser;

    client = ccnet_create_pooled_rpc_client (seaf->client_pool,
                                             NULL,
                                             "ccnet-threaded-rpcserver");
    if (!client) {
        seaf_warning ("Failed to alloc rpc client.\n");
        return -ENOMEM;
    }

    emailuser = get_user_from_ccnet (client, user);
    if (!emailuser) {
        ccnet_rpc_client_free (client);
        return -ENOENT;
    }
    g_object_unref (emailuser);
    ccnet_rpc_client_free (client);

    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;
    stbuf->st_size = 4096;

    return 0;
}

static int getattr_repo(SeafileSession *seaf,
                        const char *user, const char *repo_id, const char *repo_path,
                        struct stat *stbuf)
{
    SeafRepo *repo = NULL;
    SeafBranch *branch;
    SeafCommit *commit = NULL;
    guint32 mode = 0;
    char *id = NULL;
    int ret = 0;

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", repo_id);
        ret = -ENOENT;
        goto out;
    }

    branch = repo->head;
    commit = seaf_commit_manager_get_commit(seaf->commit_mgr,
                                            repo->id, repo->version,
                                            branch->commit_id);
    if (!commit) {
        seaf_warning ("Failed to get commit %.8s.\n", branch->commit_id);
        ret = -ENOENT;
        goto out;
    }

    id = seaf_fs_manager_path_to_obj_id(seaf->fs_mgr,
                                        repo->store_id, repo->version,
                                        commit->root_id,
                                        repo_path, &mode, NULL);
    if (!id) {
        seaf_warning ("Path %s doesn't exist in repo %s.\n", repo_path, repo_id);
        ret = -ENOENT;
        goto out;
    }

    if (S_ISDIR(mode)) {
        SeafDir *dir;
        GList *l;
        int cnt = 2; /* '.' and '..' */

        dir = seaf_fs_manager_get_seafdir(seaf->fs_mgr,
                                          repo->store_id, repo->version, id);
        if (dir) {
            for (l = dir->entries; l; l = l->next)
                cnt++;
        }

        if (strcmp (repo_path, "/") != 0) {
            // get dirent of the dir
            SeafDirent *dirent = seaf_fs_manager_get_dirent_by_path (seaf->fs_mgr,
                                                                     repo->store_id,
                                                                     repo->version,
                                                                     commit->root_id,
                                                                     repo_path, NULL);
            if (dirent && repo->version != 0)
                stbuf->st_mtime = dirent->mtime;

            seaf_dirent_free (dirent);
        }

        stbuf->st_size += cnt * sizeof(SeafDirent);
        stbuf->st_mode = mode | 0755;
        stbuf->st_nlink = 2;

        seaf_dir_free (dir);
    } else if (S_ISREG(mode)) {
        Seafile *file;

        file = seaf_fs_manager_get_seafile(seaf->fs_mgr,
                                           repo->store_id, repo->version, id);
        if (file)
            stbuf->st_size = file->file_size;

        SeafDirent *dirent = seaf_fs_manager_get_dirent_by_path (seaf->fs_mgr,
                                                                 repo->store_id,
                                                                 repo->version,
                                                                 commit->root_id,
                                                                 repo_path, NULL);
        if (dirent && repo->version != 0)
            stbuf->st_mtime = dirent->mtime;

        stbuf->st_mode = mode | 0644;
        stbuf->st_nlink = 1;

        seaf_dirent_free (dirent);
        seafile_unref (file);
    } else {
        return -ENOENT;
    }

out:
    g_free (id);
    seaf_repo_unref (repo);
    seaf_commit_unref (commit);
    return ret;
}

int do_getattr(SeafileSession *seaf, const char *path, struct stat *stbuf)
{
    int n_parts;
    char *user, *repo_id, *repo_path;
    int ret = 0;

    if (parse_fuse_path (path, &n_parts, &user, &repo_id, &repo_path) < 0) {
        return -ENOENT;
    }

    switch (n_parts) {
    case 0:
        ret = getattr_root(seaf, stbuf);
        break;
    case 1:
        ret = getattr_user(seaf, user, stbuf);
        break;
    case 2:
    case 3:
        ret = getattr_repo(seaf, user, repo_id, repo_path, stbuf);
        break;
    }

    g_free (user);
    g_free (repo_id);
    g_free (repo_path);
    return ret;
}
