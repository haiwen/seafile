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

int readdir_root(SeafileSession *seaf, const char *path, void *buf,
                 fuse_fill_dir_t filler, off_t offset,
                 struct fuse_file_info *info)
{
    GList *list = NULL, *p;

    list = seaf_repo_manager_get_repo_list(seaf->repo_mgr, -1, -1);
    if (!list)
        return 0;

    for (p = list; p; p = p->next) {
        SeafRepo *repo = (SeafRepo *)p->data;
        filler(buf, repo->id, NULL, 0);
    }

    return 0;
}

int readdir_repo(SeafileSession *seaf, const char *path, void *buf,
                 fuse_fill_dir_t filler, off_t offset,
                 struct fuse_file_info *info)
{
    SeafRepo *repo;
    SeafBranch *branch;
    SeafCommit *commit;
    SeafDir *dir;
    GError *error = NULL;
    GList *l;
    char *p;

    p = strchr(path, '/');
    if (p)
        *p = '\0';

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, path);
    if (!repo)
        return -ENOENT;

    branch = repo->head;
    commit = seaf_commit_manager_get_commit(seaf->commit_mgr, branch->commit_id);
    if (!commit)
        return -ENOENT;

    if (p)
        path = ++p;
    else
        path = "/";

    dir = seaf_fs_manager_get_seafdir_by_path(seaf->fs_mgr, commit->root_id,
                                              path, &error);
    if (!dir)
        return -ENOENT;

    for (l = dir->entries; l; l = l->next) {
        SeafDirent *seaf_dent = (SeafDirent *) l->data;
        /* FIXME: maybe we need to return stbuf */
        filler(buf, seaf_dent->name, NULL, 0);
    }

    return 0;
}
