#include "common.h"
#include "log.h"

#include <getopt.h>

#include <ccnet.h>

#include "seafile-session.h"
#include "gc-core.h"
#include "verify.h"

static char *config_dir = NULL;
static char *seafile_dir = NULL;

CcnetClient *ccnet_client;
SeafileSession *seaf;

static const char *short_opts = "hvc:d:VDi";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "config-file", required_argument, NULL, 'c', },
    { "seafdir", required_argument, NULL, 'd', },
    { "verify", no_argument, NULL, 'V' },
    { "dry-run", no_argument, NULL, 'D' },
    { "ignore-errors", no_argument, NULL, 'i' },
};

static void usage ()
{
    fprintf (stderr,
             "usage: seafserv-gc [-c config_dir] [-d seafile_dir]\n"
             "Additional options:\n"
             "-V, --verify: check for missing blocks\n");
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

int
main(int argc, char *argv[])
{
    int c;
    int verify = 0;
    int dry_run = 0;
    int ignore_errors = 0;

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
        case 'V':
            verify = 1;
            break;
        case 'D':
            dry_run = 1;
            break;
        case 'i':
            ignore_errors = 1;
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

    load_history_config ();

    if (verify) {
        verify_repos ();
        return 0;
    }

    gc_core_run (dry_run, ignore_errors);

    return 0;
}
