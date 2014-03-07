/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#ifdef WIN32
#include <windows.h>
#endif

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
#include <searpc-client.h>

#include "seafile-session.h"
#include "seafile-rpc.h"
#include <ccnet/rpcserver-proc.h>
#include "log.h"
#include "utils.h"
#include "vc-utils.h"
#include "seafile-config.h"

#include "processors/notifysync-slave-proc.h"
#include "processors/sync-repo-slave-proc.h"
#include "processors/check-tx-slave-proc.h"
#include "processors/putcommit-proc.h"
#include "processors/putfs-proc.h"

#include "cdc/cdc.h"

#ifndef SEAFILE_CLIENT_VERSION
#define SEAFILE_CLIENT_VERSION PACKAGE_VERSION
#endif


SeafileSession *seaf;
SearpcClient *ccnetrpc_client;
SearpcClient *appletrpc_client;
CcnetClient *bind_client;

static const char *short_options = "hvc:d:w:l:D:bg:G:R";
static struct option long_options[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "config-file", required_argument, NULL, 'c' },
    { "seafdir", required_argument, NULL, 'd' },
    { "daemon", no_argument, NULL, 'b' },
    { "debug", required_argument, NULL, 'D' },
    { "worktree", required_argument, NULL, 'w' },
    { "log", required_argument, NULL, 'l' },
    { "ccnet-debug-level", required_argument, NULL, 'g' },
    { "seafile-debug-level", required_argument, NULL, 'G' },
    { "log-rotate", no_argument, NULL, 'R' },
    { NULL, 0, NULL, 0, },
};

static void usage ()
{
    fprintf (stderr, "usage: seaf-daemon [-c config_dir] [-d seafile_dir] [-w worktree_dir] [--daemon]\n");
}

#include <searpc.h>
#include "searpc-signature.h"
#include "searpc-marshal.h"

static void
start_rpc_service (CcnetClient *client)
{
    searpc_server_init (register_marshals);

    searpc_create_service ("seafile-rpcserver");
    ccnet_register_service (client, "seafile-rpcserver", "rpc-inner",
                            CCNET_TYPE_RPCSERVER_PROC, NULL);

    /* searpc_create_service ("seafile-threaded-rpcserver"); */
    /* ccnet_register_service (client, "seafile-threaded-rpcserver", "rpc-inner", */
    /*                         CCNET_TYPE_THREADED_RPCSERVER_PROC, */
    /*                         seafile_register_service_cb); */

    /* seafile-rpcserver */
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_session_info,
                                     "seafile_get_session_info",
                                     searpc_signature_object__void());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_config,
                                     "seafile_get_config",
                                     searpc_signature_string__string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_set_config,
                                     "seafile_set_config",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_config_int,
                                     "seafile_get_config_int",
                                     searpc_signature_int__string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_set_config_int,
                                     "seafile_set_config_int",
                                     searpc_signature_int__string_int());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_set_upload_rate_limit,
                                     "seafile_set_upload_rate_limit",
                                     searpc_signature_int__int());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_set_download_rate_limit,
                                     "seafile_set_download_rate_limit",
                                     searpc_signature_int__int());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_unsync_repos_by_account,
                                     "seafile_unsync_repos_by_account",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_upload_rate,
                                     "seafile_get_upload_rate",
                                     searpc_signature_int__void());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_download_rate,
                                     "seafile_get_download_rate",
                                     searpc_signature_int__void());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_destroy_repo,
                                     "seafile_destroy_repo",
                                     searpc_signature_int__string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_set_repo_property,
                                     "seafile_set_repo_property",
                                     searpc_signature_int__string_string_string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_repo_property,
                                     "seafile_get_repo_property",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_repo_relay_address,
                                     "seafile_get_repo_relay_address",
                                     searpc_signature_string__string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_repo_relay_port,
                                     "seafile_get_repo_relay_port",
                                     searpc_signature_string__string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_update_repo_relay_info,
                                     "seafile_update_repo_relay_info",
                                     searpc_signature_int__string_string_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_disable_auto_sync,
                                     "seafile_disable_auto_sync",
                                     searpc_signature_int__void());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_enable_auto_sync,
                                     "seafile_enable_auto_sync",
                                     searpc_signature_int__void());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_is_auto_sync_enabled,
                                     "seafile_is_auto_sync_enabled",
                                     searpc_signature_int__void());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_branch_gets,
                                     "seafile_branch_gets",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_gen_default_worktree,
                                     "gen_default_worktree",
                                     searpc_signature_string__string_string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_check_path_for_clone,
                                     "seafile_check_path_for_clone",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_clone,
                                     "seafile_clone",
        searpc_signature_string__string_string_string_string_string_string_string_string_string_string_string_int());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_download,
                                     "seafile_download",
        searpc_signature_string__string_string_string_string_string_string_string_string_string_string_string_int());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_cancel_clone_task,
                                     "seafile_cancel_clone_task",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_remove_clone_task,
                                     "seafile_remove_clone_task",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_clone_tasks,
                                     "seafile_get_clone_tasks",
                                     searpc_signature_objlist__void());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_sync,
                                     "seafile_sync",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_repo_list,
                                     "seafile_get_repo_list",
                                     searpc_signature_objlist__int_int());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_repo,
                                     "seafile_get_repo",
                                     searpc_signature_object__string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_sync_task_list,
                                     "seafile_get_sync_task_list",
                                     searpc_signature_objlist__void());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_repo_sync_task,
                                     "seafile_get_repo_sync_task",
                                     searpc_signature_object__string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_repo_sync_info,
                                     "seafile_get_repo_sync_info",
                                     searpc_signature_object__string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_commit,
                                     "seafile_get_commit",
                                     searpc_signature_object__string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_commit_list,
                                     "seafile_get_commit_list",
                                     searpc_signature_objlist__string_int_int());


    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_find_transfer_task,
                                     "seafile_find_transfer_task",
                                     searpc_signature_object__string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_checkout_task,
                                     "seafile_get_checkout_task",
                                     searpc_signature_object__string());

}

static void
set_signal_handlers (SeafileSession *session)
{
#ifndef WIN32
    signal (SIGPIPE, SIG_IGN);
#endif
}

static void
create_sync_rpc_clients (const char *config_dir)
{
    CcnetClient *sync_client;

    /* sync client and rpc client */
    sync_client = ccnet_client_new ();
    if ( (ccnet_client_load_confdir(sync_client, config_dir)) < 0 ) {
        seaf_warning ("Read config dir error\n");
        exit(1);
    }

    if (ccnet_client_connect_daemon (sync_client, CCNET_CLIENT_SYNC) < 0)
    {
        seaf_warning ("Connect to server fail: %s\n", strerror(errno));
        exit(1);
    }

    ccnetrpc_client = ccnet_create_rpc_client (sync_client, NULL, "ccnet-rpcserver");
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

/*
 * Bind to an unused service to make sure only one instance of seaf-daemon
 * is running.
 */
static gboolean
bind_ccnet_service (const char *config_dir)
{
    gboolean ret = TRUE;

    bind_client = ccnet_client_new ();
    if ( (ccnet_client_load_confdir(bind_client, config_dir)) < 0 ) {
        seaf_warning ("Read config dir error\n");
        exit(1);
    }

    if (ccnet_client_connect_daemon (bind_client, CCNET_CLIENT_SYNC) < 0)
    {
        seaf_warning ("Connect to server fail: %s\n", strerror(errno));
        exit(1);
    }

    if (!ccnet_register_service_sync (bind_client,
                                      "seafile-dummy-service",
                                      "rpc-inner"))
        ret = FALSE;

    return ret;
}

int
main (int argc, char **argv)
{
    int c;
    char *config_dir = DEFAULT_CONFIG_DIR;
    char *seafile_dir = NULL;
    char *worktree_dir = NULL;
    char *logfile = NULL;
    const char *debug_str = NULL;
    int daemon_mode = 0;
    CcnetClient *client;
    char *ccnet_debug_level_str = "info";
    char *seafile_debug_level_str = "debug";

#ifdef WIN32
    LoadLibraryA ("exchndl.dll");

    argv = get_argv_utf8 (&argc);
#endif

    while ((c = getopt_long (argc, argv, short_options, 
                             long_options, NULL)) != EOF)
    {
        switch (c) {
        case 'h':
            usage();
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
        case 'b':
            daemon_mode = 1;
            break;
        case 'D':
            debug_str = optarg;
            break;
        case 'w':
            worktree_dir = g_strdup(optarg);
            break;
        case 'l':
            logfile = g_strdup(optarg);
            break;
        case 'g':
            ccnet_debug_level_str = optarg;
            break;
        case 'G':
            seafile_debug_level_str = optarg;
            break;
        case 'R':
            seafile_log_set_option(SEAFILE_LOG_ROTATE);
            break;
        default:
            usage ();
            exit (1);
        }
    }

    argc -= optind;
    argv += optind;

#ifndef WIN32

#ifndef __APPLE__
    if (daemon_mode)
        daemon (1, 0);
#endif

#endif

    cdc_init ();

#if !GLIB_CHECK_VERSION(2, 35, 0)
    g_type_init();
#endif
#if !GLIB_CHECK_VERSION(2, 31, 0)
    g_thread_init(NULL);
#endif

    if (!debug_str)
        debug_str = g_getenv("SEAFILE_DEBUG");
    seafile_debug_set_flags_string (debug_str);

    if (logfile == NULL)
        logfile = g_build_filename (config_dir, "logs", "seafile.log", NULL);
    if (seafile_log_init (logfile, ccnet_debug_level_str,
                          seafile_debug_level_str) < 0) {
        seaf_warning ("Failed to init log.\n");
        exit (1);
    }

    if (!bind_ccnet_service (config_dir)) {
        seaf_warning ("Failed to bind ccnet service\n");
        exit (1);
    }

    /* init ccnet */
    client = ccnet_init (config_dir);
    if (!client)
        exit (1);

    start_rpc_service (client);

    create_sync_rpc_clients (config_dir);
    appletrpc_client = ccnet_create_async_rpc_client (client, NULL, 
                                                      "applet-rpcserver");

    /* init seafile */
    if (seafile_dir == NULL)
        seafile_dir = g_build_filename (config_dir, "seafile-data", NULL);
    if (worktree_dir == NULL)
        worktree_dir = g_build_filename (g_get_home_dir(), "seafile", NULL);

    seaf = seafile_session_new (seafile_dir, worktree_dir, client);
    if (!seaf) {
        seaf_warning ("Failed to create seafile session.\n");
        exit (1);
    }
    seaf->ccnetrpc_client = ccnetrpc_client;
    seaf->appletrpc_client = appletrpc_client;

    seaf_message ("starting seafile client "SEAFILE_CLIENT_VERSION"\n");
#if defined(SEAFILE_SOURCE_COMMIT_ID)
    seaf_message ("seafile source code version "SEAFILE_SOURCE_COMMIT_ID"\n");
#endif

    g_free (seafile_dir);
    g_free (worktree_dir);
    g_free (logfile);

    set_signal_handlers (seaf);

    seafile_session_prepare (seaf);
    seafile_session_start (seaf);

    seafile_session_config_set_string (seaf, "wktree", seaf->worktree_dir);
    ccnet_main (client);

    return 0;
}
