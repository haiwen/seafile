#include "common.h"

#include <unistd.h>
#include <getopt.h>

#define FUSE_USE_VERSION  26
#include <fuse.h>
#include <fuse_opt.h>

#include <glib.h>
#include <glib-object.h>

#include <ccnet.h>
#include <seaf-db.h>

#include "log.h"
#include "utils.h"

#include "seafile-session.h"
#include "seaf-fuse.h"

CcnetClient *ccnet_client = NULL;
SeafileSession *seaf = NULL;

static int seaf_fuse_getattr(const char *path, struct stat *stbuf)
{
    memset(stbuf, 0, sizeof(struct stat));
    if (strcmp(path, "/") == 0) {
        return getattr_root(seaf, path, stbuf);
    } else {
        return getattr_repo(seaf, path+1, stbuf);
    }

    return 0;
}

static int seaf_fuse_readdir(const char *path, void *buf,
                             fuse_fill_dir_t filler, off_t offset,
                             struct fuse_file_info *info)
{
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);

    /* root dir: we display all libraries in root dir */
    if (strcmp(path, "/") == 0)
        return readdir_root(seaf, path, buf, filler, offset, info);
    else
        return readdir_repo(seaf, path+1, buf, filler, offset, info);

    return 0;
}

static int seaf_fuse_open(const char *path, struct fuse_file_info *info)
{
    SeafRepo *repo;
    SeafBranch *branch;
    SeafCommit *commit;
    GError *error = NULL;
    guint32 mode = 0;
    char *p;

    /* Now we only support read-only mode */
    if ((info->flags & 3) != O_RDONLY)
        return -EACCES;

    /* trim the first '/' */
    path++;
    p = strchr(path, '/');
    *p = '\0';

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, path);
    if (!repo)
        return -ENOENT;

    branch = repo->head;
    commit = seaf_commit_manager_get_commit(seaf->commit_mgr, branch->commit_id);
    if (!commit)
        return -ENOENT;

    path = ++p;
    if (!seaf_fs_manager_path_to_obj_id(seaf->fs_mgr, commit->root_id,
                                        path, &mode, &error))
        return -ENOENT;

    if (!S_ISREG(mode))
        return -EACCES;

    return 0;
}

static int seaf_fuse_read(const char *path, char *buf, size_t size,
                          off_t offset, struct fuse_file_info *info)
{
    SeafRepo *repo;
    SeafBranch *branch;
    SeafCommit *commit;
    Seafile *file;
    GError *error = NULL;
    char *p, *id;

    /* Now we only support read-only mode */
    if ((info->flags & 3) != O_RDONLY)
        return -EACCES;

    /* trim the first '/' */
    path++;
    p = strchr(path, '/');
    *p = '\0';

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, path);
    if (!repo)
        return -ENOENT;

    branch = repo->head;
    commit = seaf_commit_manager_get_commit(seaf->commit_mgr, branch->commit_id);
    if (!commit)
        return -ENOENT;

    path = ++p;
    id = seaf_fs_manager_get_seafile_id_by_path(seaf->fs_mgr, commit->root_id,
                                                path, &error);
    if (!id)
        return -ENOENT;

    file = seaf_fs_manager_get_seafile(seaf->fs_mgr, id);
    if (!file)
        return -ENOENT;

    return read_file(seaf, file, buf, size, offset, info);
}

struct options {
    char *config_dir;
    char *seafile_dir;
} options;

#define SEAF_FUSE_OPT_KEY(t, p, v) { t, offsetof(struct options, p), v }

enum {
    KEY_VERSION,
    KEY_HELP,
};

static struct fuse_opt seaf_fuse_opts[] = {
    SEAF_FUSE_OPT_KEY("-c %s", config_dir, 0),
    SEAF_FUSE_OPT_KEY("--config %s", config_dir, 0),
    SEAF_FUSE_OPT_KEY("-s %s", seafile_dir, 0),
    SEAF_FUSE_OPT_KEY("--seafdir %s", seafile_dir, 0),

    FUSE_OPT_KEY("-V", KEY_VERSION),
    FUSE_OPT_KEY("--version", KEY_VERSION),
    FUSE_OPT_KEY("-h", KEY_HELP),
    FUSE_OPT_KEY("--help", KEY_HELP),
    FUSE_OPT_END
};

static struct fuse_operations seaf_fuse_ops = {
    .getattr = seaf_fuse_getattr,
    .readdir = seaf_fuse_readdir,
    .open    = seaf_fuse_open,
    .read    = seaf_fuse_read,
};

int main(int argc, char *argv[])
{
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    const char *debug_str = NULL;
    char *config_dir = DEFAULT_CONFIG_DIR;
    char *seafile_dir = NULL;
    char *logfile = NULL;
    char *ccnet_debug_level_str = "info";
    char *seafile_debug_level_str = "debug";
    int ret;

    memset(&options, 0, sizeof(struct options));

    if (fuse_opt_parse(&args, &options, seaf_fuse_opts, NULL) == -1) {
        seaf_warning("Parse argument Failed\n");
        exit(1);
    }

    g_type_init();

    config_dir = options.config_dir ? : DEFAULT_CONFIG_DIR;

    if (!debug_str)
        debug_str = g_getenv("SEAFILE_DEBUG");
    seafile_debug_set_flags_string(debug_str);

    if (!options.seafile_dir)
        seafile_dir = g_build_filename(config_dir, "seafile", NULL);
    else
        seafile_dir = options.seafile_dir;
    if (!logfile)
        logfile = g_build_filename(seafile_dir, "seafile.log", NULL);

    if (seafile_log_init(logfile, ccnet_debug_level_str,
                         seafile_debug_level_str) < 0) {
        fprintf(stderr, "Failed to init log.\n");
        exit(1);
    }

    ccnet_client = ccnet_client_new();
    if ((ccnet_client_load_confdir(ccnet_client, config_dir)) < 0) {
        seaf_warning("Read config dir error\n");
        exit(1);
    }

    seaf = seafile_session_new(seafile_dir, ccnet_client);
    if (!seaf) {
        seaf_warning("Failed to create seafile session.\n");
        exit(1);
    }

    if (seafile_session_init(seaf) < 0) {
        seaf_warning("Failed to init seafile session.\n");
        exit(1);
    }

    seaf->client_pool = ccnet_client_pool_new(config_dir);
    if (!seaf->client_pool) {
        seaf_warning("Failed to creat client pool\n");
        exit(1);
    }

    ret = fuse_main(args.argc, args.argv, &seaf_fuse_ops, NULL);
    fuse_opt_free_args(&args);
    return ret;
}
