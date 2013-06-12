/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include <ccnet.h>
#include <glib.h>
#include "utils.h"

#include <getopt.h>

#include "log.h"
#include "seafile-controller.h"

#define CHECK_PROCESS_INTERVAL 10        /* every 10 seconds */

SeafileController *ctl;

static char *controller_pidfile = NULL;

static const char *short_opts = "hvftCc:d:l:g:G:P:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "foreground", no_argument, NULL, 'f', },
    { "test", no_argument, NULL, 't', },
    { "cloud-mode", no_argument, NULL, 'C', },
    { "config-dir", required_argument, NULL, 'c', },
    { "seafile-dir", required_argument, NULL, 'd', },
    { "logfile", required_argument, NULL, 'l', },
    { "ccnet-debug-level", required_argument, NULL, 'g' },
    { "seafile-debug-level", required_argument, NULL, 'G' },
    { "pidfile", required_argument, NULL, 'P' },
};

static void controller_exit (int code) __attribute__((noreturn));

static void
controller_exit (int code)
{
    if (code != 0) {
        seaf_warning ("seaf-controller exited with code %d\n", code);
    }
    exit(code);
}

//
// Utility functions Start
//

/* returns the pid of the newly created process */
static int
spawn_process (char *argv[])
{
    char **ptr = argv;
    GString *buf = g_string_new(argv[0]);
    while (*(++ptr)) {
        g_string_append_printf (buf, " %s", *ptr);
    }
    seaf_message ("spawn_process: %s\n", buf->str);
    g_string_free (buf, TRUE);

    pid_t pid = fork();

    if (pid == 0) {
        /* child process */
        execvp (argv[0], argv);
        seaf_warning ("failed to execvp %s\n", argv[0]);
        exit(-1);
    } else {
        /* controller */
        if (pid == -1)
            seaf_warning ("error when fork %s: %s\n", argv[0], strerror(errno));
        else
            seaf_message ("spawned %s, pid %d\n", argv[0], pid);

        return (int)pid;
    }
}

#define PID_ERROR_ENOENT 0
#define PID_ERROR_OTHER  -1

/**
 * @return
 * - pid if successfully opened and read the file
 * - PID_ERROR_ENOENT if file not exists,
 * - PID_ERROR_OTHER if other errors
 */
static int
read_pid_from_pidfile (const char *pidfile)
{
    FILE *pf = g_fopen (pidfile, "r");
    if (!pf) {
        if (errno == ENOENT) {
            return PID_ERROR_ENOENT;
        } else {
            return PID_ERROR_OTHER;
        }
    }

    int pid = PID_ERROR_OTHER;
    if (fscanf (pf, "%d", &pid) < 0) {
        seaf_warning ("bad pidfile format: %s\n", pidfile);
        fclose(pf);
        return PID_ERROR_OTHER;
    }

    fclose(pf);

    return pid;
}

static void
try_kill_process(int which)
{
    if (which < 0 || which >= N_PID)
        return;

    char *pidfile = ctl->pidfile[which];
    int pid = read_pid_from_pidfile(pidfile);
    if (pid > 0)
        kill((pid_t)pid, SIGTERM);
}


//
// Utility functions End
//

static int
start_ccnet_server ()
{
    if (!ctl->config_dir)
        return -1;

    seaf_message ("starting ccnet-server ...\n");

    char *argv[] = {
        "ccnet-server",
        "-c", ctl->config_dir,
        "-d",
        "-P", ctl->pidfile[PID_CCNET],
        NULL};

    int pid = spawn_process (argv);
    if (pid <= 0) {
        seaf_warning ("Failed to spawn ccnet-server\n");
        return -1;
    }

    return 0;
}

static int
start_seaf_server ()
{
    if (!ctl->config_dir || !ctl->seafile_dir)
        return -1;

    seaf_message ("starting seaf-server ...\n");

    char *argv[] = {
        "seaf-server",
        "-c", ctl->config_dir,
        "-d", ctl->seafile_dir,
        "-P", ctl->pidfile[PID_SERVER],
        "-C",
        NULL};

    if (!ctl->cloud_mode) {
        argv[7] = NULL;
    }

    int pid = spawn_process (argv);
    if (pid <= 0) {
        seaf_warning ("Failed to spawn seaf-server\n");
        return -1;
    }

    return 0;
}

static int
start_seaf_monitor ()
{
    if (!ctl->config_dir || !ctl->seafile_dir)
        return -1;

    seaf_message ("starting seaf-mon ...\n");

    char *argv[] = {
        "seaf-mon",
        "-c", ctl->config_dir,
        "-d", ctl->seafile_dir,
        "-P", ctl->pidfile[PID_MONITOR],
        NULL};

    int pid = spawn_process (argv);
    if (pid <= 0) {
        seaf_warning ("Failed to spawn seaf-mon\n");
        return -1;
    }

    return 0;
}

static int
start_httpserver() {
    char *argv[] = {
        "httpserver",
        "-c", ctl->config_dir,
        "-d", ctl->seafile_dir,
        "-P", ctl->pidfile[PID_HTTPSERVER],
        NULL
    };

    int pid = spawn_process (argv);
    if (pid <= 0) {
        seaf_warning ("Failed to spawn httpserver\n");
        return -1;
    }

    return 0;
}

static void
run_controller_loop ()
{
    GMainLoop *mainloop = g_main_loop_new (NULL, FALSE);

    g_main_loop_run (mainloop);
}

static gboolean
need_restart (int which)
{
    if (which < 0 || which >= N_PID)
        return FALSE;

    int pid = read_pid_from_pidfile (ctl->pidfile[which]);
    if (pid == PID_ERROR_ENOENT) {
        seaf_warning ("pid file %s does not exist\n", ctl->pidfile[which]);
        return TRUE;
    } else if (pid == PID_ERROR_OTHER) {
        seaf_warning ("failed to read pidfile %s: %s\n", ctl->pidfile[which], strerror(errno));
        return FALSE;
    } else {
        char buf[256];
        snprintf (buf, sizeof(buf), "/proc/%d", pid);
        if (g_file_test (buf, G_FILE_TEST_IS_DIR)) {
            return FALSE;
        } else {
            return TRUE;
        }
    }
}

static gboolean
check_process (void *data)
{
    if (need_restart(PID_SERVER)) {
        seaf_message ("seaf-server need restart...\n");
        start_seaf_server ();
    }

    if (need_restart(PID_MONITOR)) {
        seaf_message ("seaf-mon need restart...\n");
        start_seaf_monitor ();
    }

    if (need_restart(PID_HTTPSERVER)) {
        seaf_message ("httpserver need restart...\n");
        start_httpserver ();
    }

    return TRUE;
}

static void
start_process_monitor ()
{
    ctl->check_process_timer = g_timeout_add (
        CHECK_PROCESS_INTERVAL * 1000, check_process, NULL);
}

static void
stop_process_monitor ()
{
    if (ctl->check_process_timer != 0) {
        g_source_remove (ctl->check_process_timer);
        ctl->check_process_timer = 0;
    }
}

static void
disconnect_clients ()
{
    CcnetClient *client, *sync_client;
    client = ctl->client;
    sync_client = ctl->sync_client;

    if (client->connected) {
        ccnet_client_disconnect_daemon (client);
    }

    if (sync_client->connected) {
        ccnet_client_disconnect_daemon (sync_client);
    }
}

static void rm_client_fd_from_mainloop ();
static int seaf_controller_start ();

static void
on_ccnet_daemon_down ()
{
    stop_process_monitor ();
    disconnect_clients ();
    rm_client_fd_from_mainloop ();

    seaf_message ("restarting ccnet server ...\n");

    /* restart ccnet */
    if (seaf_controller_start () < 0) {
        seaf_warning ("Failed to restart ccnet server.\n");
        controller_exit (1);
    }
}

static gboolean
client_io_cb (GIOChannel *source, GIOCondition condition, gpointer data)
{
    if (condition & G_IO_IN) {
        if (ccnet_client_read_input (ctl->client) <= 0) {
            on_ccnet_daemon_down ();
            return FALSE;
        }
        return TRUE;
    } else {
        on_ccnet_daemon_down ();
        return FALSE;
    }
}

static void
add_client_fd_to_mainloop ()
{
    GIOChannel *channel;

    channel = g_io_channel_unix_new (ctl->client->connfd);
    ctl->client_io_id = g_io_add_watch (channel,
                                        G_IO_IN | G_IO_HUP | G_IO_ERR,
                                        client_io_cb, NULL);
}

static void
rm_client_fd_from_mainloop ()
{
    if (ctl->client_io_id != 0) {
        g_source_remove (ctl->client_io_id);
        ctl->client_io_id = 0;
    }
}

static void
on_ccnet_connected ()
{
    if (start_seaf_server () < 0)
        controller_exit(1);

    if (start_seaf_monitor () < 0)
        controller_exit(1);

    if (need_restart(PID_HTTPSERVER)) {
        /* Since httpserver doesn't die when ccnet server dies, when ccnet
         * server is restarted, we don't need to start httpserver */
        if (start_httpserver() < 0)
            controller_exit(1);
    }

    add_client_fd_to_mainloop ();

    start_process_monitor ();
}

static gboolean
do_connect_ccnet ()
{
    CcnetClient *client, *sync_client;
    client = ctl->client;
    sync_client = ctl->sync_client;

    if (!client->connected) {
        if (ccnet_client_connect_daemon (client, CCNET_CLIENT_ASYNC) < 0) {
            return TRUE;
        }
    }

    if (!sync_client->connected) {
        if (ccnet_client_connect_daemon (sync_client, CCNET_CLIENT_SYNC) < 0) {
            return TRUE;
        }
    }

    seaf_message ("ccnet daemon connected.\n");

    on_ccnet_connected ();

    return FALSE;
}

/* This would also stop seaf-server & seaf-mon  */
static void
stop_ccnet_server ()
{
    seaf_message ("shutting down ccnet-server ...\n");
    GError *error = NULL;
    ccnet_client_send_cmd (ctl->sync_client, "shutdown", &error);

    try_kill_process(PID_CCNET);
    try_kill_process(PID_SERVER);
    try_kill_process(PID_MONITOR);
    try_kill_process(PID_HTTPSERVER);
}

static void
init_pidfile_path (SeafileController *ctl)
{
    char *pid_dir = g_build_filename(ctl->seafile_dir, "pids", NULL);
    if (!g_file_test(pid_dir, G_FILE_TEST_EXISTS)) {
        if (g_mkdir(pid_dir, 0777) < 0) {
            seaf_warning("failed to create pid dir %s: %s", pid_dir, strerror(errno));
            controller_exit(1);
        }
    }

    ctl->pidfile[PID_CCNET] = g_build_filename(pid_dir, "ccnet.pid", NULL);
    ctl->pidfile[PID_SERVER] = g_build_filename(pid_dir, "seaf-server.pid", NULL);
    ctl->pidfile[PID_MONITOR] = g_build_filename(pid_dir, "seaf-mon.pid", NULL);
    ctl->pidfile[PID_HTTPSERVER] = g_build_filename(pid_dir, "httpserver.pid", NULL);
}

static int
seaf_controller_init (SeafileController *ctl,
                      char *config_dir,
                      char *seafile_dir,
                      gboolean cloud_mode)
{
    if (!g_file_test (config_dir, G_FILE_TEST_IS_DIR)) {
        seaf_warning ("invalid config_dir: %s\n", config_dir);
        return -1;
    }

    if (!g_file_test (seafile_dir, G_FILE_TEST_IS_DIR)) {
        seaf_warning ("invalid seafile_dir: %s\n", seafile_dir);
        return -1;
    }

    ctl->client = ccnet_client_new ();
    ctl->sync_client = ccnet_client_new ();

    if (ccnet_client_load_confdir (ctl->client, config_dir) < 0) {
        seaf_warning ("Failed to load ccnet confdir\n");
        return -1;
    }

    if (ccnet_client_load_confdir (ctl->sync_client, config_dir) < 0) {
        seaf_warning ("Failed to load ccnet confdir\n");
        return -1;
    }

    ctl->config_dir = config_dir;
    ctl->seafile_dir = seafile_dir;
    ctl->cloud_mode = cloud_mode;

    init_pidfile_path(ctl);

    return 0;
}

static int
seaf_controller_start ()
{
    if (start_ccnet_server () < 0) {
        seaf_warning ("Failed to start ccnet server\n");
        return -1;
    }

    g_timeout_add (1000 * 1, do_connect_ccnet, NULL);

    return 0;
}

static int
write_controller_pidfile ()
{
    if (!controller_pidfile)
        return -1;

    pid_t pid = getpid();

    FILE *pidfile = g_fopen(controller_pidfile, "w");
    if (!pidfile) {
        seaf_warning ("Failed to fopen() pidfile %s: %s\n",
                      controller_pidfile, strerror(errno));
        return -1;
    }

    char buf[32];
    snprintf (buf, sizeof(buf), "%d\n", pid);
    if (fputs(buf, pidfile) < 0) {
        seaf_warning ("Failed to write pidfile %s: %s\n",
                      controller_pidfile, strerror(errno));
        return -1;
    }

    fflush (pidfile);
    fclose (pidfile);
    return 0;
}

static void
remove_controller_pidfile ()
{
    if (controller_pidfile) {
        g_unlink (controller_pidfile);
    }
}

static void
sigint_handler (int signo)
{
    stop_ccnet_server ();

    remove_controller_pidfile();

    signal (signo, SIG_DFL);
    raise (signo);
}

static void
sigchld_handler (int signo)
{
    waitpid (-1, NULL, WNOHANG);
}

static void
set_signal_handlers ()
{
    signal (SIGINT, sigint_handler);
    signal (SIGTERM, sigint_handler);
    signal (SIGCHLD, sigchld_handler);
    signal (SIGPIPE, SIG_IGN);
}

static void
usage ()
{
    fprintf (stderr, "Usage: seafile-controller OPTIONS\n"
             "OPTIONS:\n"
             "  -b, --bin-dir           insert a directory in front of the PATH env\n"
             "  -c, --config-dir        ccnet config dir\n"
             "  -d, --seafile-dir       seafile dir\n"
        );
}

/* seafile-controller -t is used to test whether config file is valid */
static void
test_config (const char *ccnet_dir, const char *seafile_dir)
{
    char *ccnet_conf = g_build_filename (ccnet_dir, "ccnet.conf", NULL);
    char *seafile_conf = g_build_filename (seafile_dir, "seafile.conf", NULL);

    if (!g_file_test(ccnet_conf, G_FILE_TEST_IS_REGULAR)) {
        fprintf (stderr, "ccnet config file %s does not exist\n", ccnet_conf);
        exit(1);
    }

    if (!g_file_test(seafile_conf, G_FILE_TEST_IS_REGULAR)) {
        fprintf (stderr, "seafile config file %s does not exist\n", seafile_conf);
        exit(1);
    }

    GError *error = NULL;
    GKeyFile *keyfile = g_key_file_new ();
    if (!g_key_file_load_from_file (keyfile, ccnet_conf, 0, &error)) {
        fprintf (stderr, "Error in ccnet config file %s:\n%s\n",
                 ccnet_conf,
                 error->message);
        exit (1);
    }

    printf ("the syntax of ccnet config file %s is OK\n", ccnet_conf);

    if (!g_key_file_load_from_file (keyfile, seafile_conf, 0, &error)) {
        fprintf (stderr, "Error in seafile config file %s:\n%s\n",
                 seafile_conf,
                 error->message);
        exit (1);
    }

    printf ("the syntax of seafile config file %s is OK\n", seafile_conf);

    exit(0);
}

int main (int argc, char **argv)
{
    if (argc <= 1) {
        usage ();
        exit (1);
    }

    char *config_dir = DEFAULT_CONFIG_DIR;
    char *seafile_dir = NULL;
    char *logfile = NULL;
    char *ccnet_debug_level_str = "info";
    char *seafile_debug_level_str = "debug";
    int daemon_mode = 1;
    gboolean cloud_mode = FALSE;
    gboolean test_conf = FALSE;

    int c;
    while ((c = getopt_long (argc, argv, short_opts,
                             long_opts, NULL)) != EOF)
    {
        switch (c) {
        case 'h':
            usage ();
            exit(1);
            break;
        case 'v':
            fprintf (stderr, "seafile-controller version 1.0\n");
            break;
        case 't':
            test_conf = TRUE;
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
        case 'C':
            cloud_mode = TRUE;
            break;
        case 'g':
            ccnet_debug_level_str = optarg;
            break;
        case 'G':
            seafile_debug_level_str = optarg;
            break;
        case 'P':
            controller_pidfile = optarg;
            break;
        default:
            usage ();
            exit (1);
        }
    }

    g_type_init ();
#if !GLIB_CHECK_VERSION(2,32,0)
    g_thread_init (NULL);
#endif

    if (!seafile_dir) {
        fprintf (stderr, "<seafile_dir> must be specified with --seafile-dir\n");
        exit(1);
    }

    config_dir = ccnet_expand_path (config_dir);
    seafile_dir = ccnet_expand_path (seafile_dir);

    if (test_conf) {
        test_config (config_dir, seafile_dir);
    }

    ctl = g_new0 (SeafileController, 1);
    if (seaf_controller_init (ctl, config_dir, seafile_dir, cloud_mode) < 0) {
        controller_exit(1);
    }

    if (!logfile) {
        logfile = g_build_filename (seafile_dir, "controller.log", NULL);
    }

    if (seafile_log_init (logfile, ccnet_debug_level_str,
                          seafile_debug_level_str) < 0) {
        seaf_warning ("Failed to init log.\n");
        controller_exit (1);
    }

    set_signal_handlers ();

    if (seaf_controller_start (ctl) < 0)
        controller_exit (1);

    if (daemon_mode)
        daemon (1, 0);

    if (controller_pidfile == NULL) {
        controller_pidfile = g_strdup(g_getenv ("SEAFILE_PIDFILE"));
    }

    if (controller_pidfile != NULL) {
        if (write_controller_pidfile () < 0) {
            seaf_warning ("Failed to write pidfile %s\n", controller_pidfile);
            return -1;
        }
    }

    run_controller_loop ();

    return 0;
}
