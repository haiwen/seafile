#include "common.h"

#define FUSE_USE_VERSION  26
#include <fuse.h>

#include <glib.h>
#include <glib-object.h>

#include <ccnet.h>
#include <seaf-db.h>

#include "log.h"
#include "utils.h"

#include "seaf-fuse.h"
#include "seafile-session.h"

int getattr_root(SeafileSession *seaf, const char *path, struct stat *stbuf)
{
    GList *list = NULL, *p;
    int cnt = 2;

    stbuf->st_mode = S_IFDIR | 0755;
    stbuf->st_nlink = 2;

    list = seaf_repo_manager_get_repo_list(seaf->repo_mgr, -1, -1);
    if (!list)
        return 0;

    for (p = list; p; p = p->next)
        cnt++;

    stbuf->st_size = cnt * sizeof(SeafDirent);

    return 0;
}

int getattr_repo(SeafileSession *seaf, const char *path, struct stat *stbuf)
{
    char *repo_id, *repo_path;
    SeafRepo *repo = NULL;
    SeafBranch *branch;
    SeafCommit *commit = NULL;
    guint32 mode = 0;
    char *id = NULL;
    int ret = 0;

    if (parse_fuse_path (path, &repo_id, &repo_path) < 0)
        return -ENOENT;

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("Failed to get repo %s.\n", repo_id);
        ret = -ENOENT;
        goto out;
    }

    branch = repo->head;
    commit = seaf_commit_manager_get_commit(seaf->commit_mgr, branch->commit_id);
    if (!commit) {
        seaf_warning ("Failed to get commit %.8s.\n", branch->commit_id);
        ret = -ENOENT;
        goto out;
    }

    id = seaf_fs_manager_path_to_obj_id(seaf->fs_mgr, commit->root_id,
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

        dir = seaf_fs_manager_get_seafdir(seaf->fs_mgr, id);
        if (dir) {
            for (l = dir->entries; l; l = l->next)
                cnt++;
        }

        stbuf->st_size += cnt * sizeof(SeafDirent);
        stbuf->st_mode = mode | 0755;
        stbuf->st_nlink = 2;
    } else if (S_ISREG(mode)) {
        Seafile *file;

        file = seaf_fs_manager_get_seafile(seaf->fs_mgr, id);
        if (file)
            stbuf->st_size = file->file_size;

        stbuf->st_mode = mode | 0644;
        stbuf->st_nlink = 1;
    } else {
        return -ENOENT;
    }

out:
    g_free (repo_id);
    g_free (repo_path);
    g_free (id);
    seaf_repo_unref (repo);
    seaf_commit_unref (commit);
    return ret;
}
