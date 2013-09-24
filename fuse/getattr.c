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
    SeafRepo *repo;
    SeafBranch *branch;
    SeafCommit *commit;
    GError *error = NULL;
    guint32 mode = 0;
    char *p, *id;

    /* the length of path should always greater than 36 */
    /* FIXME: filter invalid path firstly */
    if (strlen(path) < 36)
        return -ENOENT;

    /* Trim repo id */
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
    id = seaf_fs_manager_path_to_obj_id(seaf->fs_mgr, commit->root_id,
                                        path, &mode, &error);
    if (!id)
        return -ENOENT;

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

    return 0;
}
