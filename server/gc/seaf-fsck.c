#include "common.h"
#include "log.h"

#include <getopt.h>

#include <ccnet.h>

#include "seafile-session.h"
#include "fsck.h"

#include "utils.h"

static char *config_dir = NULL;
static char *seafile_dir = NULL;

CcnetClient *ccnet_client;
SeafileSession *seaf;

static const char *short_opts = "hvc:d:D";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "config-file", required_argument, NULL, 'c', },
    { "seafdir", required_argument, NULL, 'd', },
    { "dry-run", no_argument, NULL, 'D' },
};

static void usage ()
{
    fprintf (stderr,
             "usage: seaf-fsck [-c config_dir] [-d seafile_dir] "
             "[repo_id_1 [repo_id_2 ...]]\n"
             "Additional options:\n"
             "-D, --dry-run: check fs objects and blocks, but don't remove them.\n");
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
    int dry_run = 0;

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
        case 'D':
            dry_run = 1;
            break;
        default:
            usage();
            exit(-1);
        }
    }

    g_type_init();

    if (seafile_log_init ("-", "info", "debug") < 0) {
        seaf_warning ("Failed to init log.\n");
        exit (1);
    }

    ccnet_client = ccnet_client_new();
    if ((ccnet_client_load_confdir(ccnet_client, config_dir)) < 0) {
        seaf_warning ("Read config dir error\n");
        return -1;
    }

    if (seafile_dir == NULL)
        seafile_dir = g_build_filename (config_dir, "seafile-data", NULL);
    
    seaf = seafile_session_new(seafile_dir, ccnet_client);
    if (!seaf) {
        seaf_warning ("Failed to create seafile session.\n");
        exit (1);
    }

    GList *repo_id_list = NULL;
    int i;
    for (i = optind; i < argc; i++)
        repo_id_list = g_list_append (repo_id_list, g_strdup(argv[i]));

    seaf_fsck (repo_id_list, dry_run);

    return 0;
}
