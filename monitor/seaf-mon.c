/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <glib.h>
#include <glib-object.h>

#include <ccnet.h>
#include <searpc-server.h>

#include "seafile-session.h"
#include "monitor-rpc.h"
#include <ccnet/rpcserver-proc.h>
#include "log.h"
#include "utils.h"

/* #include "processors/heartbeat-proc.h" */
/* #include "processors/repostat-proc.h" */

SeafileSession *seaf;

char *pidfile = NULL;

static const char *short_options = "hvc:d:l:fg:G:P:";
static struct option long_options[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "config-file", required_argument, NULL, 'c' },
    { "seafile-dir", required_argument, NULL, 'd' },
    { "log", required_argument, NULL, 'l' },
    { "foreground", no_argument, NULL, 'f' },
    { "ccnet-debug-level", required_argument, NULL, 'g' },
    { "monitor-debug-level", required_argument, NULL, 'G' },
    { "pidfile", required_argument, NULL, 'P' },
    { NULL, 0, NULL, 0, },
};

static void usage ()
{
    fprintf (stderr, "usage: seaf-mon -d seafile_dir [-c config_dir]\n");
}

static void register_processors (CcnetClient *client)
{

}

#include <searpc.h>
#include "searpc-signature.h"
#include "searpc-marshal.h"

static void start_rpc_service (CcnetClient *client)
{
    searpc_server_init (register_marshals);

    searpc_create_service ("monitor-rpcserver");
    ccnet_register_service (client, "monitor-rpcserver", "rpc-inner",
                            CCNET_TYPE_RPCSERVER_PROC, NULL);

    searpc_server_register_function ("monitor-rpcserver",
                                     monitor_compute_repo_size,
                                     "compute_repo_size",
                                     searpc_signature_int__string());
}

static void
set_signal_handlers (SeafileSession *session)
{
#ifndef WIN32
    signal (SIGPIPE, SIG_IGN);
#endif
}

static void
remove_pidfile (const char *pidfile)
{
    if (pidfile) {
        g_unlink (pidfile);
    }
}

static int
write_pidfile (const char *pidfile_path)
{
    if (!pidfile_path)
        return -1;

    pid_t pid = getpid();

    FILE *pidfile = fopen(pidfile_path, "w");
    if (!pidfile) {
        seaf_warning ("Failed to fopen() pidfile %s: %s\n",
                      pidfile_path, strerror(errno));
        return -1;
    }

    char buf[32];
    snprintf (buf, sizeof(buf), "%d\n", pid);
    if (fputs(buf, pidfile) < 0) {
        seaf_warning ("Failed to write pidfile %s: %s\n",
                      pidfile_path, strerror(errno));
        return -1;
    }

    fflush (pidfile);
    fclose (pidfile);
    return 0;
}

static void
on_seaf_mon_exit(void)
{
    if (pidfile)
        remove_pidfile (pidfile);
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
main (int argc, char **argv)
{
    int c;
    char *config_dir = DEFAULT_CONFIG_DIR;
    char *seafile_dir = NULL;
    char *logfile = NULL;
    int daemon_mode = 1;
    CcnetClient *client;
    char *ccnet_debug_level_str = "info";
    char *monitor_debug_level_str = "debug";

#ifdef WIN32
    argv = get_argv_utf8 (&argc);
#endif

    while ((c = getopt_long (argc, argv, short_options,
                             long_options, NULL)) != EOF)
    {
        switch (c) {
        case 'h':
            exit (1);
            break;
        case 'v':
            exit (1);
            break;
        case 'c':
            config_dir = optarg;
            break;
        case 'd':
            seafile_dir = g_strdup(optarg);
            break;
        case 'f':
            daemon_mode = 0;
            break;
        case 'l':
            logfile = g_strdup(optarg);
            break;
        case 'g':
            ccnet_debug_level_str = optarg;
            break;
        case 'G':
            monitor_debug_level_str = optarg;
            break;
        case 'P':
            pidfile = optarg;
            break;
        default:
            usage ();
            exit (1);
        }
    }

    argc -= optind;
    argv += optind;

#ifndef WIN32
    if (daemon_mode)
        daemon (1, 0);
#endif
    g_type_init ();

    client = ccnet_init (config_dir);
    if (!client)
        exit (1);

    register_processors (client);

    start_rpc_service (client);

    if (seafile_dir == NULL) {
        usage ();
        exit (1);
    }

    if (logfile == NULL)
        logfile = g_build_filename (seafile_dir, "monitor.log", NULL);

    seaf = seafile_session_new (seafile_dir, client);
    if (!seaf) {
        fprintf (stderr, "Failed to create seafile monitor.\n");
        exit (1);
    }

    if (seafile_session_init (seaf) < 0) {
        fprintf (stderr, "Failed to init seafile monitor.\n");
        exit (1);
    }

    if (seafile_log_init (logfile, ccnet_debug_level_str,
                          monitor_debug_level_str) < 0) {
        fprintf (stderr, "Failed to init log.\n");
        exit (1);
    }

    g_free (seafile_dir);
    g_free (logfile);

    set_signal_handlers (seaf);

    seafile_session_start (seaf);

    if (pidfile) {
        if (write_pidfile (pidfile) < 0) {
            ccnet_message ("Failed to write pidfile\n");
            return -1;
        }
    }
    atexit (on_seaf_mon_exit);

    ccnet_main (client);

    return 0;
}
