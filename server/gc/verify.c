#include "seafile-session.h"
#include "log.h"

typedef struct VerifyData {
    gint64 truncate_time;
    gboolean traversed_head;
} VerifyData;

static int
check_blocks (SeafFSManager *mgr, const char *file_id)
{
    Seafile *seafile;
    int i;

    seafile = seaf_fs_manager_get_seafile (mgr, file_id);
    if (!seafile) {
        seaf_warning ("Failed to find file %s.\n", file_id);
        return -1;
    }

    for (i = 0; i < seafile->n_blocks; ++i) {
        if (!seaf_block_manager_block_exists (seaf->block_mgr,
                                              seafile->blk_sha1s[i]))
            g_message ("Block %s is missing.\n", seafile->blk_sha1s[i]);
    }

    seafile_unref (seafile);

    return 0;
}

static gboolean
fs_callback (SeafFSManager *mgr,
             const char *obj_id,
             int type,
             void *user_data,
             gboolean *stop)
{
    if (type == SEAF_METADATA_TYPE_FILE && check_blocks (mgr, obj_id) < 0)
        return FALSE;

    return TRUE;
}

static gboolean
traverse_commit (SeafCommit *commit, void *vdata, gboolean *stop)
{
    VerifyData *data = vdata;
    int ret;

    if (data->truncate_time == 0)
    {
        *stop = TRUE;
        /* Stop after traversing the head commit. */
    }
    else if (data->truncate_time > 0 &&
             (gint64)(commit->ctime) < data->truncate_time &&
             data->traversed_head)
    {
        *stop = TRUE;
        return TRUE;
    }

    if (!data->traversed_head)
        data->traversed_head = TRUE;

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         commit->root_id,
                                         fs_callback,
                                         vdata);
    if (ret < 0)
        return FALSE;

    return TRUE;
}

static int
verify_repo (SeafRepo *repo)
{
    GList *branches, *ptr;
    SeafBranch *branch;
    int ret = 0;
    VerifyData data = {0};

    data.truncate_time = seaf_repo_manager_get_repo_truncate_time (repo->manager,
                                                                   repo->id);

    branches = seaf_branch_manager_get_branch_list (seaf->branch_mgr, repo->id);
    if (branches == NULL) {
        seaf_warning ("[GC] Failed to get branch list of repo %s.\n", repo->id);
        return -1;
    }

    for (ptr = branches; ptr != NULL; ptr = ptr->next) {
        branch = ptr->data;
        gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                                 branch->commit_id,
                                                                 traverse_commit,
                                                                 &data);
        seaf_branch_unref (branch);
        if (!res) {
            ret = -1;
            break;
        }
    }

    g_list_free (branches);

    return ret;
}

int
verify_repos ()
{
    GList *repos = NULL, *ptr;
    int ret = 0;

    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    for (ptr = repos; ptr != NULL; ptr = ptr->next) {
        ret = verify_repo ((SeafRepo *)ptr->data);
        seaf_repo_unref ((SeafRepo *)ptr->data);
        if (ret < 0)
            break;
    }

    return ret;
}
