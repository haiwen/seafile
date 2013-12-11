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

static char *replace_slash (const char *repo_name)
{
    char *ret = g_strdup(repo_name);
    char *p;

    for (p = ret; *p != 0; ++p)
        if (*p == '/')
            *p = '_';

    return ret;
}

int readdir_root(SeafileSession *seaf, const char *path, void *buf,
                 fuse_fill_dir_t filler, off_t offset,
                 struct fuse_file_info *info)
{
    GList *list = NULL, *p;
    GString *name;

    list = seaf_repo_manager_get_repo_list(seaf->repo_mgr, -1, -1);
    if (!list)
        return 0;

    for (p = list; p; p = p->next) {
        SeafRepo *repo = (SeafRepo *)p->data;

        char *clean_repo_name = replace_slash (repo->name);

        name = g_string_new ("");
        g_string_printf (name, "%s_%s", repo->id, clean_repo_name);
        filler(buf, name->str, NULL, 0);
        g_string_free (name, TRUE);
        g_free (clean_repo_name);
    }

    return 0;
}

int readdir_repo(SeafileSession *seaf, const char *path, void *buf,
                 fuse_fill_dir_t filler, off_t offset,
                 struct fuse_file_info *info)
{
    char *repo_id, *repo_path;
    SeafRepo *repo = NULL;
    SeafBranch *branch;
    SeafCommit *commit = NULL;
    SeafDir *dir = NULL;
    GList *l;
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

    dir = seaf_fs_manager_get_seafdir_by_path(seaf->fs_mgr, commit->root_id,
                                              repo_path, NULL);
    if (!dir) {
        seaf_warning ("Path %s doesn't exist in repo %s.\n", repo_path, repo_id);
        ret = -ENOENT;
        goto out;
    }

    for (l = dir->entries; l; l = l->next) {
        SeafDirent *seaf_dent = (SeafDirent *) l->data;
        /* FIXME: maybe we need to return stbuf */
        filler(buf, seaf_dent->name, NULL, 0);
    }

out:
    g_free (repo_id);
    g_free (repo_path);
    seaf_repo_unref (repo);
    seaf_commit_unref (commit);
    return ret;
}
