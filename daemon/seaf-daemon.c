/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#ifdef WIN32
#include <windows.h>
#include <wincrypt.h>
#include <shellapi.h>
#endif

#ifndef WIN32
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <glib.h>
#include <glib-object.h>
#include <curl/curl.h>
#include <event2/thread.h>

#ifdef HAVE_BREAKPAD_SUPPORT
#include <c_bpwrapper.h>
#endif // HAVE_BREAKPAD_SUPPORT

#ifdef ENABLE_BREAKPAD
#include "c_bpwrapper.h"
#endif // ENABLE_BREAKPAD

#include <searpc.h>
#include <searpc-named-pipe-transport.h>

#include "seafile-session.h"
#include "seafile-rpc.h"
#include "log.h"
#include "utils.h"
#include "vc-utils.h"
#include "seafile-config.h"
#ifndef USE_GPL_CRYPTO
#include "curl-init.h"
#endif

#include "cdc/cdc.h"

#ifndef SEAFILE_CLIENT_VERSION
#define SEAFILE_CLIENT_VERSION PACKAGE_VERSION
#endif


SeafileSession *seaf;

static const char *short_options = "hvc:d:w:l:D:bg:G:";
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
    { NULL, 0, NULL, 0, },
};

static void usage ()
{
    fprintf (stderr, "usage: seaf-daemon [-c config_dir] [-d seafile_dir] [-w worktree_dir] [--daemon]\n");
}

#include <searpc.h>
#include "searpc-signature.h"
#include "searpc-marshal.h"

#define SEAFILE_SOCKET_NAME "seafile.sock"

static void
register_rpc_service ()
{
    searpc_server_init (register_marshals);

    searpc_create_service ("seafile-rpcserver");
    searpc_create_service ("seafile-threaded-rpcserver");

    /* seafile-rpcserver */
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_sync_error_id_to_str,
                                     "seafile_sync_error_id_to_str",
                                     searpc_signature_string__int());

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
                                     seafile_remove_repo_tokens_by_account,
                                     "seafile_remove_repo_tokens_by_account",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_set_repo_token,
                                     "seafile_set_repo_token",
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
                                     seafile_update_repos_server_host,
                                     "seafile_update_repos_server_host",
                                     searpc_signature_int__string_string());

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
                                     seafile_gen_default_worktree,
                                     "gen_default_worktree",
                                     searpc_signature_string__string_string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_check_path_for_clone,
                                     "seafile_check_path_for_clone",
                                     searpc_signature_int__string());

    /* clone means sync with existing folder, download means sync to a new folder. */
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_clone,
                                     "seafile_clone",
        searpc_signature_string__string_int_string_string_string_string_string_string_string_int_string());
    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_download,
                                     "seafile_download",
        searpc_signature_string__string_int_string_string_string_string_string_string_string_int_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_cancel_clone_task,
                                     "seafile_cancel_clone_task",
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
                                     seafile_get_repo_sync_task,
                                     "seafile_get_repo_sync_task",
                                     searpc_signature_object__string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_find_transfer_task,
                                     "seafile_find_transfer_task",
                                     searpc_signature_object__string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_path_sync_status,
                                     "seafile_get_path_sync_status",
                                     searpc_signature_string__string_string_int());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_mark_file_locked,
                                     "seafile_mark_file_locked",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_mark_file_unlocked,
                                     "seafile_mark_file_unlocked",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_generate_magic_and_random_key,
                                     "seafile_generate_magic_and_random_key",
                                     searpc_signature_object__int_string_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_server_property,
                                     "seafile_get_server_property",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_set_server_property,
                                     "seafile_set_server_property",
                                     searpc_signature_int__string_string_string());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_file_sync_errors,
                                     "seafile_get_file_sync_errors",
                                     searpc_signature_objlist__int_int());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_del_file_sync_error_by_id,
                                     "seafile_del_file_sync_error_by_id",
                                     searpc_signature_int__int());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_get_sync_notification,
                                     "seafile_get_sync_notification",
                                     searpc_signature_json__void());

    searpc_server_register_function ("seafile-rpcserver",
                                     seafile_shutdown,
                                     "seafile_shutdown",
                                     searpc_signature_int__void());

    /* Need to run in a thread since diff may take long. */
    searpc_server_register_function ("seafile-threaded-rpcserver",
                                     seafile_diff,
                                     "seafile_diff",
                                     searpc_signature_objlist__string_string_string_int());
}

#ifdef WIN32
char *b64encode(const char *input)
{
    char buf[32767] = {0};
    DWORD retlen = 32767;
    CryptBinaryToStringA((BYTE*) input, strlen(input), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buf, &retlen);
    return strdup(buf);
}
#endif

static int
start_searpc_server ()
{
    register_rpc_service ();

#ifdef WIN32
    char userNameBuf[32767];
    DWORD bufCharCount = sizeof(userNameBuf);
    if (GetUserNameA(userNameBuf, &bufCharCount) == 0) {
        seaf_warning ("Failed to get user name, GLE=%lu, required size is %lu\n",
                      GetLastError(), bufCharCount);
        return -1;
    }

    char *path = g_strdup_printf("\\\\.\\pipe\\seafile_%s", b64encode(userNameBuf));
#else
    char *path = g_build_filename (seaf->seaf_dir, SEAFILE_SOCKET_NAME, NULL);
#endif

    SearpcNamedPipeServer *server = searpc_create_named_pipe_server (path);
    if (!server) {
        seaf_warning ("Failed to create named pipe server.\n");
        g_free (path);
        return -1;
    }

    seaf->rpc_socket_path = path;

    return searpc_named_pipe_server_start (server);
}


#ifndef WIN32
static void
set_signal_handlers (SeafileSession *session)
{
    signal (SIGPIPE, SIG_IGN);
}
#endif

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
#if defined(HAVE_BREAKPAD_SUPPORT) || defined(ENABLE_BREAKPAD)
#ifdef WIN32
#define DUMPS_DIR "~/ccnet/logs/dumps/"
#else
#define DUMPS_DIR "~/.ccnet/logs/dumps/"
#endif
    const char *dump_dir = ccnet_expand_path(DUMPS_DIR);
    checkdir_with_mkdir(dump_dir);
    CBPWrapperExceptionHandler bp_exception_handler = newCBPWrapperExceptionHandler(dump_dir);
#endif

#ifdef WIN32
#define DEFAULT_CONFIG_DIR "~/ccnet"
#else
#define DEFAULT_CONFIG_DIR "~/.ccnet"
#endif

    int c;
    char *config_dir = DEFAULT_CONFIG_DIR;
    char *seafile_dir = NULL;
    char *worktree_dir = NULL;
    char *logfile = NULL;
    const char *debug_str = NULL;
    int daemon_mode = 0;
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
        default:
            usage ();
            exit (1);
        }
    }

    argc -= optind;
    argv += optind;

#ifndef WIN32
    if (daemon_mode) {
#ifndef __APPLE__
        daemon (1, 0);
#else   /* __APPLE */
        /* daemon is deprecated under APPLE
         * use fork() instead
         * */
        switch (fork ()) {
          case -1:
              seaf_warning ("Failed to daemonize");
              exit (-1);
              break;
          case 0:
              /* all good*/
              break;
          default:
              /* kill origin process */
              exit (0);
        }
#endif  /* __APPLE */
    }
#endif /* !WIN32 */

    cdc_init ();

    curl_global_init (CURL_GLOBAL_ALL);

#if !GLIB_CHECK_VERSION(2, 35, 0)
    g_type_init();
#endif
#if !GLIB_CHECK_VERSION(2, 31, 0)
    g_thread_init(NULL);
#endif

#ifndef WIN32
    /* init multithreading support for libevent.because struct event_base is not thread safe. */
    evthread_use_pthreads();
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

    /* init seafile */
    if (seafile_dir == NULL)
        seafile_dir = g_build_filename (config_dir, "seafile-data", NULL);
    if (worktree_dir == NULL)
        worktree_dir = g_build_filename (g_get_home_dir(), "seafile", NULL);

    seaf = seafile_session_new (seafile_dir, worktree_dir, config_dir);
    if (!seaf) {
        seaf_warning ("Failed to create seafile session.\n");
        exit (1);
    }

    seaf_message ("starting seafile client "SEAFILE_CLIENT_VERSION"\n");
#if defined(SEAFILE_SOURCE_COMMIT_ID)
    seaf_message ("seafile source code version "SEAFILE_SOURCE_COMMIT_ID"\n");
#endif

    g_free (seafile_dir);
    g_free (worktree_dir);
    g_free (logfile);

#ifndef WIN32
    set_signal_handlers (seaf);
#else
    WSADATA wsadata;
    WSAStartup (0x0101, &wsadata);
#endif

#ifndef USE_GPL_CRYPTO
    seafile_curl_init();
#endif
    seafile_session_prepare (seaf);
    seafile_session_start (seaf);

    if (start_searpc_server () < 0) {
        seaf_warning ("Failed to start searpc server.\n");
        exit (1);
    }

    seaf_message ("rpc server started.\n");


    seafile_session_config_set_string (seaf, "wktree", seaf->worktree_dir);

    event_base_loop (seaf->ev_base, 0);

#ifndef USE_GPL_CRYPTO
    seafile_curl_deinit();
#endif

    return 0;
}
