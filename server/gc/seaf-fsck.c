#include "common.h"
#include "log.h"

#include <getopt.h>

#include <ccnet.h>

#include "seafile-session.h"
#include "fsck.h"

#include "utils.h"

static char *config_dir = NULL;
static char *seafile_dir = NULL;
static char *central_config_dir = NULL;

CcnetClient *ccnet_client;
SeafileSession *seaf;

static const char *short_opts = "hvc:d:rE:F:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "repair", no_argument, NULL, 'r', },
    { "export", required_argument, NULL, 'E', },
    { "config-file", required_argument, NULL, 'c', },
    { "central-config-dir", required_argument, NULL, 'F' },
    { "seafdir", required_argument, NULL, 'd', },
};

static void usage ()
{
    fprintf (stderr,
             "usage: seaf-fsck [-r] [-E exported_path] [-c config_dir] [-d seafile_dir] "
             "[repo_id_1 [repo_id_2 ...]]\n");
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

#ifdef __linux__

/* Compare the owner uid of the seafile-data dir with the current uid. */
static gboolean
check_user (const char *seafile_dir, uid_t *current_user, uid_t *seafile_user)
{
    struct stat st;
    uid_t euid;

    if (stat (seafile_dir, &st) < 0) {
        seaf_warning ("Failed to stat seafile data dir %s: %s\n",
                      seafile_dir, strerror(errno));
        return FALSE;
    }

    euid = geteuid();

    *current_user = euid;
    *seafile_user = st.st_uid;

    return (euid == st.st_uid);
}

#endif  /* __linux__ */

int
main(int argc, char *argv[])
{
    int c;
    gboolean repair = FALSE;
    char *export_path = NULL;

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
        case 'r':
            repair = TRUE;
            break;
        case 'E':
            export_path = strdup(optarg);
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

#ifdef __linux__
    uid_t current_user, seafile_user;
    if (!check_user (seafile_dir, &current_user, &seafile_user)) {
        seaf_message ("Current user (%u) is not the user for running "
                      "seafile server (%u). Unable to run fsck.\n",
                      current_user, seafile_user);
        exit(1);
    }
#endif

    seaf = seafile_session_new(central_config_dir, seafile_dir, ccnet_client,
                               export_path == NULL);
    if (!seaf) {
        seaf_warning ("Failed to create seafile session.\n");
        exit (1);
    }

    GList *repo_id_list = NULL;
    int i;
    for (i = optind; i < argc; i++)
        repo_id_list = g_list_append (repo_id_list, g_strdup(argv[i]));

    if (export_path) {
        export_file (repo_id_list, seafile_dir, export_path);
    } else {
        seaf_fsck (repo_id_list, repair);
    }

    return 0;
}
