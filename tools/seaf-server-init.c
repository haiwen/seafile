#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "../common/seaf-db.h"

static int
save_config_file (GKeyFile *key_file, const char *path)
{
    GError *error = NULL;
    char *config = g_key_file_to_data (key_file, NULL, &error);
    if (error) {
        fprintf (stderr, "Failed to save config file to %s: %s\n",
                 path, error->message);
        return -1;
    }

    FILE *fp = g_fopen (path, "w");
    if (fp == NULL) {
        fprintf (stderr, "Failed to save config file: %s %s.\n",
                 path, strerror(errno));
        return -1;
    }

    fputs (config, fp);
    fclose (fp);

    return 0;
}

static const char *short_opts = "hvd:p:P:F:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "verbose", no_argument, NULL, 'v' },
    { "seafile-dir", required_argument, NULL, 'd' },
    { "central-config-dir", required_argument, NULL, 'F' },
    { "port", required_argument, NULL, 'p' },
    { "fileserver-port", required_argument, NULL, 'P' },
    { 0, 0, 0, 0 },
};

struct seaf_server_config {
    char *central_config_dir;
    char *seafile_dir;
    char *port;
    char *fileserver_port;
}; 

static struct seaf_server_config config = {
    NULL,
    NULL,
};

    
void usage(int code) {
    fprintf (stderr,
"\nUsage: seaf-server-init [OPTIONS]\n"
"Initialize your seafile server configuration\n\n"
"Required arguments are:\n\n" 
"  -h, --help                output help and quit\n"
"  -v, --verbose             output more information\n"
"  -d, --seafile-dir         specify a directory to put your seafile server config and data\n"
"  -F, --central-config-dir  specify a central config dir\n"
"  -p, --port                specify a port to to transmit data\n"
"  -P, --fileserver-port     specify the port to use by fileserver\n"
        );
    exit(code);
}

int main (int argc, char **argv)
{
    gboolean verbose = FALSE;

    if (argc == 1)
        usage(1);

    int c;
    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != EOF) {
        switch (c) {
        case 'h':
            usage(0);
            break;
        case 'v':
            verbose = TRUE;
            break;
        case 'F':
            config.central_config_dir = strdup(optarg);
            break;
        case 'd':
            config.seafile_dir = strdup(optarg);
            break;
        case 'p':
            config.port = strdup(optarg);
            break;
        case 'P':
            config.fileserver_port = strdup(optarg);
            break;
        default:
            usage(1);
        }
    }

    if (!config.seafile_dir && !config.central_config_dir) {
        fprintf (stderr, "You must specify seafile data dir\n");
        usage(1);
    }

    /* Generate config file. */
    GKeyFile *key_file = g_key_file_new ();

    if (config.port) {
        g_key_file_set_string (key_file, "network", "port", config.port);
    }

    if (config.fileserver_port) {
        g_key_file_set_string (key_file, "fileserver", "port", config.fileserver_port);
    } else {
        /* fileserver port defaults to 8082 */
        g_key_file_set_string (key_file, "fileserver", "port", "8082");
    }

    struct stat st;
    if (g_lstat (config.seafile_dir, &st) < 0) {
        if (g_mkdir (config.seafile_dir, 0700) < 0) {
            fprintf (stderr, "Directory %s cannot be created.\n", config.seafile_dir);
            return 1;
        }
    }

    if (config.central_config_dir && g_lstat (config.central_config_dir, &st) < 0) {
        if (g_mkdir (config.central_config_dir, 0700) < 0) {
            fprintf (stderr, "Directory %s cannot be created.\n", config.central_config_dir);
            return 1;
        }
    }

    const char *confdir = config.central_config_dir ? config.central_config_dir : config.seafile_dir;
    char *seafile_conf = g_build_filename (confdir, "seafile.conf", NULL);

    if (verbose)
        printf ("Generating config files:           %s\n", seafile_conf);

    if (save_config_file (key_file, seafile_conf) < 0)
        return 1;

    printf ("Done.\n");

    return 0;
}
