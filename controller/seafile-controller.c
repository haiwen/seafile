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

#define CHECK_HEARTBEAT_INTERVAL 2        /* every 2 seconds */
#define MAX_HEARTBEAT_LIMIT 4

SeafileController *ctl;

static const char *short_opts = "hvfb:C:c:d:r:l:g:G:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "foreground", no_argument, NULL, 'f', },
    { "bin-dir", required_argument, NULL, 'b', },
    { "config-dir", required_argument, NULL, 'c', },
    { "seafile-dir", required_argument, NULL, 'd', },
    { "logfile", required_argument, NULL, 'l', },
    { "cloud-mode", no_argument, NULL, 'C', },
    { "ccnet-debug-level", required_argument, NULL, 'g' },
    { "seafile-debug-level", required_argument, NULL, 'G' },
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

/* If --bin-dir is specified, modify the <PATH> env before spawning any
 * process. */
static void
set_path_env (const char *bin_dir)
{
    if (!bin_dir)
        return;

    const char *path = g_getenv("PATH");

    if (!path) {
        g_setenv ("PATH", bin_dir, TRUE);
    } else {
        GString *buf = g_string_new (NULL);
        g_string_append_printf (buf, "%s:%s", bin_dir, path);
        g_setenv ("PATH", buf->str, TRUE);
        g_string_free (buf, TRUE);
    }
}

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

#define IS_APP_MSG(msg,topic) (strcmp((msg)->app, topic) == 0)

static void mq_cb (CcnetMessage *msg, void *data)
{
    time_t now = time (NULL);

    if (IS_APP_MSG(msg, "seaf_server.heartbeat")) {
        
        ctl->last_hb[HB_SEAFILE_SERVER] = now;
        
    } else if (IS_APP_MSG(msg, "seaf_mon.heartbeat")) {

        ctl->last_hb[HB_SEAFILE_MONITOR] = now;
    }
}

static int
start_mq_client ()
{
    seaf_message ("starting mq client ...\n");
    
    CcnetMqclientProc *mqclient_proc;

    mqclient_proc = (CcnetMqclientProc *)
        ccnet_proc_factory_create_master_processor
        (ctl->client->proc_factory, "mq-client");
    
    if (!mqclient_proc) {
        seaf_warning ("Failed to create mqclient proc.\n");
        return -1;
    }

    static char *topics[] = {
        "seaf_server.heartbeat",
        "seaf_mon.heartbeat",
    };

    ccnet_mqclient_proc_set_message_got_cb (mqclient_proc, mq_cb, NULL);

    /* Subscribe to messages. */
    if (ccnet_processor_start ((CcnetProcessor *)mqclient_proc,
                               G_N_ELEMENTS(topics), topics) < 0) {
        seaf_warning ("Failed to start mqclient proc\n");
        return -1;
    }

    ctl->mqclient_proc = mqclient_proc;

    return 0;
}

static void
stop_mq_client ()
{
    if (ctl->mqclient_proc) {
        seaf_message ("stopping mq client ...\n");
        ccnet_mqclient_proc_unsubscribe_apps (ctl->mqclient_proc);
        ctl->mqclient_proc = NULL;
    }
}

static void
run_controller_loop ()
{
    GMainLoop *mainloop = g_main_loop_new (NULL, FALSE);

    g_main_loop_run (mainloop);
}

static int
read_pid_from_pidfile (const char *pidfile)
{
    FILE *pf = fopen (pidfile, "r");
    if (!pf) {
        g_debug ("failed to open pidfile %s:%s\n",
                 pidfile, strerror(errno));
        return -1;
    }

    int pid = -1;
    if (fscanf (pf, "%d", &pid) < 0) {
        seaf_warning ("bad pidfile format: %s\n", pidfile);
        return -1;
    }

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

static gboolean
check_heartbeat (void *data)
{
    time_t now = time(NULL);
    int i;

    for (i = 0; i < N_HEARTBEAT; i++) {
        if (ctl->last_hb[i] == 0)
            ctl->last_hb[i] = now;
    }

    if (now - ctl->last_hb[HB_SEAFILE_SERVER] > MAX_HEARTBEAT_LIMIT) {

        try_kill_process(PID_SERVER);
        seaf_message ("seaf-server need restart...\n");
        start_seaf_server ();
        ctl->last_hb[HB_SEAFILE_SERVER] = time(NULL);

    }

    if (now - ctl->last_hb[HB_SEAFILE_MONITOR] > MAX_HEARTBEAT_LIMIT) {

        try_kill_process(PID_MONITOR);
        seaf_message ("seaf-mon need restart...\n");
        start_seaf_monitor ();
        ctl->last_hb[HB_SEAFILE_MONITOR] = time(NULL);
    }

    return TRUE;
}

static void
start_hearbeat_monitor ()
{
    ctl->hearbeat_timer = g_timeout_add (
        CHECK_HEARTBEAT_INTERVAL * 1000, check_heartbeat, NULL);
}

static void
stop_heartbeat_monitor ()
{
    if (ctl->hearbeat_timer != 0) {
        g_source_remove (ctl->hearbeat_timer);
        ctl->hearbeat_timer = 0;

        ctl->last_hb[HB_SEAFILE_SERVER] = 0;
        ctl->last_hb[HB_SEAFILE_MONITOR] = 0;
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
    stop_heartbeat_monitor ();
    stop_mq_client ();
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

    if (start_mq_client () < 0)
        controller_exit(1);

    add_client_fd_to_mainloop ();

    start_hearbeat_monitor ();
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
}

static void
init_pidfile_path (SeafileController *ctl)
{
    char tmp[] = "XXXXXX";
    char buf[SEAF_PATH_MAX];
    int pid = (int)getpid();

    if (!mktemp(tmp))
        return;
    /* use controller pid and mktemp to generate unique path */
    snprintf (buf, sizeof(buf), "/tmp/seafile-%d-%s.ccnet.pid", pid, tmp);
    ctl->pidfile[PID_CCNET] = g_strdup(buf);

    snprintf (buf, sizeof(buf), "/tmp/seafile-%d-%s.server.pid", pid, tmp);
    ctl->pidfile[PID_SERVER] = g_strdup(buf);

    snprintf (buf, sizeof(buf), "/tmp/seafile-%d-%s.monitor.pid", pid, tmp);
    ctl->pidfile[PID_MONITOR] = g_strdup(buf);
}

static int
seaf_controller_init (SeafileController *ctl, char *bin_dir,
                      char *config_dir, char *seafile_dir,
                      gboolean cloud_mode)
{
    if (bin_dir) {
        if (!g_file_test (bin_dir, G_FILE_TEST_IS_DIR)) {
            seaf_warning ("invalid config_dir: %s\n", config_dir);
            return -1;
        }
    }

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
    ctl->bin_dir = bin_dir;
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

static void
sigint_handler (int signo)
{
    stop_ccnet_server ();

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

int main (int argc, char **argv)
{
    if (argc <= 1) {
        usage ();
        exit (1);
    }
    
    char *bin_dir = NULL;
    char *config_dir = DEFAULT_CONFIG_DIR;
    char *seafile_dir = NULL;
    char *logfile = NULL;
    char *ccnet_debug_level_str = "info";
    char *seafile_debug_level_str = "debug";
    int daemon_mode = 1;
    gboolean cloud_mode = FALSE;

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
        case 'b':
            bin_dir = optarg;
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
        default:
            usage ();
            exit (1);
        }
    }

    if (daemon_mode)
        daemon (1, 0);

    g_type_init ();
#if !GLIB_CHECK_VERSION(2,32,0)
    g_thread_init (NULL);
#endif

    if (!seafile_dir) {
        seaf_warning ("<seafile_dir> must be specified with --seafile-dir\n");
        controller_exit(1);
    }

    if (bin_dir)
        bin_dir = ccnet_expand_path(bin_dir);

    config_dir = ccnet_expand_path (config_dir);
    seafile_dir = ccnet_expand_path(seafile_dir);

    ctl = g_new0 (SeafileController, 1);
    if (seaf_controller_init (ctl, bin_dir, config_dir, seafile_dir, cloud_mode) < 0) {
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

    if (ctl->bin_dir) 
        set_path_env (ctl->bin_dir);

    if (seaf_controller_start (ctl) < 0)
        controller_exit (1);

    run_controller_loop ();

    return 0;
}
