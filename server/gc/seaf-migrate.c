#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

#include <getopt.h>

#include <ccnet.h>

#include "seafile-session.h"

#include "utils.h"

static char *config_dir = NULL;
static char *seafile_dir = NULL;
static char *central_config_dir = NULL;

CcnetClient *ccnet_client;
SeafileSession *seaf;

static const char *short_opts = "hvc:d:VDiF:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "config-file", required_argument, NULL, 'c', },
    { "central-config-dir", required_argument, NULL, 'F' },
    { "seafdir", required_argument, NULL, 'd', },
};

static int
migrate_v0_repos_to_v1_layout ();

static void usage ()
{
    fprintf (stderr,
             "usage: seaf-migrate [-c config_dir] [-d seafile_dir]\n");
}

static void
load_history_config ()
{
    int keep_history_days;
    GError *error = NULL;

    seaf->keep_history_days = -1;

    keep_history_days = g_key_file_get_integer (seaf->config,
                                                "history", "keep_days",
                                                &error);
    if (error == NULL)
        seaf->keep_history_days = keep_history_days;
}

#ifdef WIN32
/* Get the commandline arguments in unicode, then convert them to utf8  */
static char **
get_argv_utf8 (int *argc)
{
    int i = 0;
    char **argv = NULL;
    const wchar_t *cmdline = NULL;
    wchar_t **argv_w = NULL;

    cmdline = GetCommandLineW();
    argv_w = CommandLineToArgvW (cmdline, argc);
    if (!argv_w) {
        printf("failed to CommandLineToArgvW(), GLE=%lu\n", GetLastError());
        return NULL;
    }

    argv = (char **)malloc (sizeof(char*) * (*argc));
    for (i = 0; i < *argc; i++) {
        argv[i] = wchar_to_utf8 (argv_w[i]);
    }

    return argv;
}
#endif

int
main(int argc, char *argv[])
{
    int c;

#ifdef WIN32
    argv = get_argv_utf8 (&argc);
#endif

    config_dir = DEFAULT_CONFIG_DIR;

    while ((c = getopt_long(argc, argv,
                short_opts, long_opts, NULL)) != EOF) {
        switch (c) {
        case 'h':
            usage();
            exit(0);
        case 'v':
            exit(-1);
            break;
        case 'c':
            config_dir = strdup(optarg);
            break;
        case 'd':
            seafile_dir = strdup(optarg);
            break;
        case 'F':
            central_config_dir = strdup(optarg);
            break;
        default:
            usage();
            exit(-1);
        }
    }

#if !GLIB_CHECK_VERSION(2, 35, 0)
    g_type_init();
#endif

    if (seafile_log_init ("-", "info", "debug") < 0) {
        seaf_warning ("Failed to init log.\n");
        exit (1);
    }

    ccnet_client = ccnet_client_new();
    if ((ccnet_client_load_confdir(ccnet_client, central_config_dir, config_dir)) < 0) {
        seaf_warning ("Read config dir error\n");
        return -1;
    }

    if (seafile_dir == NULL)
        seafile_dir = g_build_filename (config_dir, "seafile-data", NULL);
    
    seaf = seafile_session_new(central_config_dir, seafile_dir, ccnet_client, TRUE);
    if (!seaf) {
        seaf_warning ("Failed to create seafile session.\n");
        exit (1);
    }

    load_history_config ();

    migrate_v0_repos_to_v1_layout ();

    return 0;
}

typedef struct {
    SeafRepo *repo;
    GHashTable *visited;

    /* > 0: keep a period of history;
     * == 0: only keep data in head commit;
     * < 0: keep all history data.
     */
    gint64 truncate_time;
    gboolean traversed_head;
    gboolean stop_copy_blocks;
} MigrationData;

static int
migrate_file_blocks (SeafFSManager *mgr, MigrationData *data, const char *file_id)
{
    SeafRepo *repo = data->repo;
    Seafile *seafile;
    int i;
    char *block_id;

    seafile = seaf_fs_manager_get_seafile (mgr, repo->store_id, repo->version, file_id);
    if (!seafile) {
        seaf_warning ("Failed to find file %s.\n", file_id);
        return -1;
    }

    for (i = 0; i < seafile->n_blocks; ++i) {
        block_id = seafile->blk_sha1s[i];
        if (seaf_block_manager_copy_block (seaf->block_mgr,
                                           repo->store_id, repo->version,
                                           repo->store_id, 1,
                                           block_id) < 0) {
            seaf_warning ("Failed to copy block %s.\n", block_id);
            seafile_unref (seafile);
            return -1;
        }
    }

    seafile_unref (seafile);

    return 0;
}

static gboolean
fs_callback (SeafFSManager *mgr,
             const char *store_id,
             int version,
             const char *obj_id,
             int type,
             void *user_data,
             gboolean *stop)
{
    MigrationData *data = user_data;
    SeafRepo *repo = data->repo;

    if (data->visited != NULL) {
        if (g_hash_table_lookup (data->visited, obj_id) != NULL) {
            *stop = TRUE;
            return TRUE;
        }

        char *key = g_strdup(obj_id);
        g_hash_table_replace (data->visited, key, key);
    }

    if (seaf_obj_store_copy_obj (seaf->fs_mgr->obj_store,
                                 repo->store_id, repo->version,
                                 repo->store_id, 1,
                                 obj_id) < 0) {
        seaf_warning ("Failed to copy fs object %s.\n", obj_id);
        return FALSE;
    }

    if (data->stop_copy_blocks)
        return TRUE;

    if (type == SEAF_METADATA_TYPE_FILE &&
        migrate_file_blocks (mgr, data, obj_id) < 0)
        return FALSE;

    return TRUE;
}

static gboolean
traverse_commit (SeafCommit *commit, void *vdata, gboolean *stop)
{
    MigrationData *data = vdata;
    SeafRepo *repo = data->repo;
    int ret;

    if (data->truncate_time > 0 &&
        (gint64)(commit->ctime) < data->truncate_time &&
        data->traversed_head && !data->stop_copy_blocks) {
        data->stop_copy_blocks = TRUE;
    }

    if (!data->traversed_head)
        data->traversed_head = TRUE;

    if (seaf_obj_store_copy_obj (seaf->commit_mgr->obj_store,
                                 repo->id, repo->version,
                                 repo->id, 1,
                                 commit->commit_id) < 0) {
        seaf_warning ("Failed to copy commit %s.\n", commit->commit_id);
        return FALSE;
    }

    ret = seaf_fs_manager_traverse_tree (seaf->fs_mgr,
                                         data->repo->store_id, data->repo->version,
                                         commit->root_id,
                                         fs_callback,
                                         data, FALSE);
    if (ret < 0)
        return FALSE;

    if (data->truncate_time == 0 && !data->stop_copy_blocks) {
        data->stop_copy_blocks = TRUE;
        /* Stop after traversing the head commit. */
    }

    return TRUE;
}

static int
migrate_repo (SeafRepo *repo)
{
    MigrationData *data;
    int ret = 0;

    seaf_message ("Migrating data for repo %.8s.\n", repo->id);

    data = g_new0(MigrationData, 1);
    data->repo = repo;
    data->visited = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    gint64 truncate_time = seaf_repo_manager_get_repo_truncate_time (repo->manager,
                                                                     repo->id);
    data->truncate_time = truncate_time;

    gboolean res = seaf_commit_manager_traverse_commit_tree (seaf->commit_mgr,
                                                             repo->id,
                                                             repo->version,
                                                             repo->head->commit_id,
                                                             traverse_commit,
                                                             data,
                                                             FALSE);
    if (!res) {
        seaf_warning ("Migration of repo %s is not completed.\n", repo->id);
        ret = -1;
    }

    g_hash_table_destroy (data->visited);
    g_free (data);

    return ret;
}

static int
migrate_v0_repos_to_v1_layout ()
{
    GList *repos = NULL, *ptr;
    SeafRepo *repo;
    gboolean error = FALSE;

    repos = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1, &error);
    for (ptr = repos; ptr; ptr = ptr->next) {
        repo = ptr->data;
        if (!repo->is_corrupted && repo->version == 0)
            migrate_repo (repo);
        seaf_repo_unref (repo);
    }
    g_list_free (repos);

    return 0;
}
