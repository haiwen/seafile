#include "config.h"

#include <glib/gi18n.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <getopt.h>
#include <time.h>

#include <ccnet.h>
#include "utils.h"
#include "net.h"

#include <evutil.h>

#include "ccnet-init.h"
#include "applet-log.h"
#include "applet-rpc-service.h"
#include "rpc-wrapper.h"
#include "applet-common.h"
#include "seafile-applet.h"
#include "translate-commit-desc.h"


#ifdef __APPLE__
#include "../mac/seafile/seafile/platform.h"
#endif

#define SEAFILE_OFFICIAL_ADDR "cloud.seafile.com.cn:10001"
#define SEAFILE_INI "seafile.ini"

#if !defined(SEAFILE_CLIENT_VERSION)
#define SEAFILE_CLIENT_VERSION PACKAGE_VERSION
#endif

static gboolean first_use = FALSE;

void 
applet_exit(int code)
{
    on_quit();
    exit(code);
}

static void
save_seafile_dir()
{
    FILE *fp;
    char *path;

    char *config_dir = applet->config_dir;
    char *seafile_dir = applet->seafile_dir;

    path = g_build_filename(config_dir, SEAFILE_INI, NULL);
    fp = (FILE *)(long)g_fopen(path, "wb");

    if (fp) {
        fprintf(fp, "%s\n", seafile_dir);
        fclose(fp);
    } else {
        applet_warning ("Failed to open %s: %s\n", path, strerror(errno));
    }

    g_free (path);
}

static char *
get_seafile_dir(const char *config_dir)
{
    FILE *fp = NULL;
    char buf[4096];

    char *fname = g_build_filename (config_dir, SEAFILE_INI, NULL);
    fp = (FILE *)(long)g_fopen (fname, "rb");
    g_free (fname);
    
    if (fp) {
        if (fgets(buf, sizeof(buf), fp)) {
            char *p = buf + strlen(buf) -1;

            while (*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t' || *p == '/' || *p == '\\')
                *p-- = '\0';
            fclose(fp);
            return g_strdup(buf);
        }
    }
    return NULL;
}

static void
init_ccnet ()
{
    char *config_dir = applet->config_dir;
    char *config_file;
    
    config_file = g_build_filename (config_dir,
                                    SESSION_CONFIG_FILENAME, NULL);
    
    if (!g_file_test(config_dir, G_FILE_TEST_IS_DIR)
        || !g_file_test(config_file, G_FILE_TEST_IS_REGULAR)) {
        
        if (create_new() < 0) {
            applet_exit(-1);
        }
    }

    applet_log_init(config_dir);
    
    applet_message ("Load config dir %s success\n", config_dir);
    applet_message ("starting seafile-applet "SEAFILE_CLIENT_VERSION"\n");
    g_setenv("CCNET_CONF_DIR", config_dir, 1);
    
    g_free (config_file);
}

#ifdef WIN32
extern void copy_user_manual();
#endif    

static void
init_seafile ()
{
    applet->seafile_dir = get_seafile_dir(applet->config_dir);
    
    if (!applet->seafile_dir
        || !g_file_test(applet->seafile_dir, G_FILE_TEST_EXISTS)) {
        
        first_use = TRUE;
        if (show_init_seafile_window() < 0)
            applet_exit (1);
        else 
            save_seafile_dir();
    }

#ifdef WIN32
    copy_user_manual();
#endif    

#ifndef __APPLE__
    char *parent_dir = g_path_get_dirname (applet->seafile_dir);
    char *parent_name = g_path_get_basename (parent_dir);

    if (parent_name && (strcmp(parent_name, "Seafile") == 0)) {
        /* For seafile version >= 0.9.4 in windows
              applet->seafile_dir:       C:/Seafile/seafile-data
              applet->seafile_worktree:  C:/Seafile
         */
        applet->seafile_worktree = g_strdup(parent_dir);
    } else {
        /* For seafile version < 0.9.4 in windows and all versions in linux
              applet->seafile_dir:       /data/seafile-data
              applet->seafile_worktree:  /data/seafile
         */
        applet->seafile_worktree = g_build_filename (parent_dir, "seafile", NULL);
    }
    g_free (parent_dir);
    g_free (parent_name);
#else
    if (!applet->seafile_worktree) {
        applet->seafile_worktree = g_path_get_dirname (applet->seafile_dir);
    }
#endif
    g_setenv("SEAFILE_WORKTREE", applet->seafile_worktree, 1);
}

static void
collect_transfer_info (GString *msg, const char *info, char *repo_name)
{
    char *p;
    if (! (p = strchr (info, '\t')))
        return;
    *p = '\0';

    int rate = atoi(p + 1) / 1024;
    
    gboolean is_upload = (strcmp(info, "upload") == 0);
    char buf[4096];
    snprintf (buf, sizeof(buf) , "%s %s, %s %d KB/s\n",
              is_upload ? _("Uploading") : _("Downloading"),
              repo_name, _("Speed"), rate);
    g_string_append (msg, buf);
}

static void
handle_seafile_notification (char *type, char *content)
{
    char buf[1024];

    if (strcmp(type, "transfer") == 0) {
        if (applet->auto_sync_disabled) {
            /* When auto sync is disabled but there is clone task running,
             * applet can still get "transfer" notification, but we don't
             * rotate the icon */
            return;
        }
        trayicon_rotate (TRUE);

        if (content == NULL) {
            applet_debug ("handle empty notification\n");
            return;
        }
        GString *str = g_string_new (NULL);
        parse_key_value_pairs (content,
                               (KeyValueFunc)collect_transfer_info, str);
        trayicon_set_tip (str->str);
        g_string_free (str, TRUE);

        return;
        
    } else if (strcmp(type, "repo.deleted_on_relay") == 0) {
        snprintf (buf, sizeof(buf), "\"%s\" %s", content, _("is unsynced. \nReason: Deleted on server"));
        trayicon_notify ("Seafile", buf);
        
    } else if (strcmp(type, "sync.done") == 0) {
        /* format: repo_name \t repo_id \t description */
        char *p, *repo_name, *repo_id, *desc;
        repo_name = content;
        p = strchr(content, '\t');
        if (!p) {
            return;
        }
        *p = '\0';
        repo_id = p + 1;

        p = strchr(p + 1, '\t');
        if (!p) {
            return;
        }
        *p = '\0';
        desc = p + 1;
#ifdef __APPLE__
        char *translated_desc = g_strdup(desc);
#else
        char *translated_desc = translate_commit_desc(desc);
#endif

        memcpy (applet->last_synced_repo, repo_id, strlen(repo_id) + 1);
        snprintf (buf, sizeof(buf), "\"%s\" %s", repo_name, _("is synchronized"));
        trayicon_notify (buf, translated_desc);

        g_free (translated_desc);
        
    } else if (strcmp(type, "sync.access_denied") == 0) {
        /* format: <repo_name\trepo_id> */
        char *p = strchr(content, '\t');
        if (!p) {
            return;
        }
        *p = '\0';
        char *repo_name = content;
        char *repo_id = p + 1;

        memcpy (applet->last_synced_repo, repo_id, strlen(repo_id) + 1);
        snprintf (buf, sizeof(buf), "\"%s\" %s", repo_name, _("failed to sync. \nAccess denied to service"));
        trayicon_notify ("Seafile", buf);
    } else if (strcmp(type, "sync.quota_full") == 0) {
        /* format: <repo_name\trepo_id> */
        char *p = strchr(content, '\t');
        if (!p) {
            return;
        }
        *p = '\0';
        char *repo_name = content;
        char *repo_id = p + 1;

        memcpy (applet->last_synced_repo, repo_id, strlen(repo_id) + 1);
        snprintf (buf, sizeof(buf), "\"%s\" %s", repo_name, _("failed to sync.\nThe library owner's storage space is used up."));
        trayicon_notify ("Seafile", buf);
    }
#ifdef __APPLE__
    else if (strcmp(type, "repo.setwktree") == 0) {
        seafile_set_repofolder_icns (content);
    } else if  (strcmp(type, "repo.unsetwktree") == 0) {
        seafile_unset_repofolder_icns (content);
    }
#endif
}

static int
parse_seafile_notification (char *msg, char **type, char **body)
{
    if (!msg)
        return -1;

    char *ptr = strchr (msg, '\n');
    if (!ptr)
        return -1;

    *ptr = '\0';

    *type = msg;
    *body = ptr + 1;

    return 0;
}

#define IS_APP_MSG(msg,topic) (strcmp((msg)->app, (topic)) == 0)

static void mq_cb (CcnetMessage *msg, void *data)
{
    char *type = NULL;
    char *content = NULL;

    if (IS_APP_MSG(msg, "seafile.heartbeat")) {
        applet->last_heartbeat = time(NULL);
    } else if (IS_APP_MSG(msg, "seafile.notification")) {
        if (parse_seafile_notification (msg->body, &type, &content) < 0)
            return;

        handle_seafile_notification (type, content);
    }
}

static void
start_mq_client ()
{
    CcnetMqclientProc *mqclient_proc;
    
    mqclient_proc = (CcnetMqclientProc *)
        ccnet_proc_factory_create_master_processor
        (applet->client->proc_factory, "mq-client");

    if (!mqclient_proc) {
        applet_warning ("Failed to create mq-client!\n");
        applet_exit(1);
    }

    ccnet_mqclient_proc_set_message_got_cb (mqclient_proc, mq_cb, NULL);
    
    static char *topics[] = {
        "seafile.heartbeat",
        "seafile.notification",
    };
    
    /* Subscribe to messages. */
    if (ccnet_processor_start ((CcnetProcessor *)mqclient_proc,
                               G_N_ELEMENTS(topics), topics) < 0) {
        
        applet_warning ("Failed to start mq-client!\n");
        applet_exit(1);
    }

    applet->mqclient_proc = mqclient_proc;
}

static void
stop_mq_client ()
{
    if (applet->mqclient_proc) {
        ccnet_mqclient_proc_unsubscribe_apps (applet->mqclient_proc);
        applet->mqclient_proc = NULL;
    }
}

void
send_command (const char *command)
{
    GError *error = NULL;
    ccnet_client_send_cmd (applet->sync_client, command, &error);
    if (error) {
        applet_warning ("Failed to send command %s: %s\n",
                        command, error->message);
    }
}

gboolean
test_web_server (void)
{
    applet_message ("[web] testing web server ... \n");

    evutil_socket_t test_sockfd = socket (AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in servaddr;

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(13420);
    inet_pton(AF_INET, "127.0.0.1", &servaddr.sin_addr);

    int ret = connect (test_sockfd, (struct sockaddr *)&servaddr,
                       sizeof(servaddr));
    evutil_closesocket(test_sockfd) ;

    if (ret == 0) {
        applet_message ("web server now ready\n");
    }
    return (ret == 0) ;
}

int
connect_to_daemon (void)
{
    applet_message ("connecting ccnet ...\n");

    CcnetClient *client = applet->client;
    CcnetClient *sync_client = applet->sync_client;
    
    if (client->connected && sync_client->connected) {
        return 0;
    }

    if (!client->connected) {
        if (ccnet_client_connect_daemon (client, CCNET_CLIENT_ASYNC) < 0) {
            applet_warning("connect to ccnet daemon fail: %s\n", strerror(errno));
            trayicon_set_ccnet_state (CCNET_STATE_DOWN);
            return -1;
        }
    }

    if (!sync_client->connected) {
        if (ccnet_client_connect_daemon (sync_client, CCNET_CLIENT_SYNC) < 0) {
            applet_warning ("sync_client: connect to ccnet daemon failed: %s\n",
                            strerror(errno));
            applet_exit(1);
        }
    }

    trayicon_set_ccnet_state (CCNET_STATE_UP);
    
    add_client_fd_to_mainloop ();

    applet_init_ccnet_rpc (sync_client);
    applet_init_seafile_rpc (client);

    applet_start_rpc_service(client);
    start_mq_client ();

    return 0;
}

/* Ask ccnet daemon to quit, and disconnect client from daemon. */
void
stop_ccnet (void)
{
    CcnetClient *client = applet->client;
    CcnetClient *sync_client = applet->sync_client;
    
    if (!client)
        return;

    if (client->connected) {
        stop_mq_client ();
        
        send_command ("shutdown");
        ccnet_client_disconnect_daemon (client);
        if (sync_client && sync_client->connected)
            ccnet_client_disconnect_daemon (sync_client);

        trayicon_rotate (FALSE);

        rm_client_fd_from_mainloop ();
    }

    if (applet->heartbeat_monitor_on)
        stop_heartbeat_monitor ();

    trayicon_set_ccnet_state (CCNET_STATE_DOWN);
}

static void
start_ccnet ()
{
    applet_message ("Starting ccnet ...\n");

    if ((ccnet_client_load_confdir(applet->client, applet->config_dir)) < 0 ) {
        applet_warning("Read config dir error\n");
        applet_exit (1);
    }

    if ((ccnet_client_load_confdir(applet->sync_client, applet->config_dir)) < 0 ) {
        applet_warning("Read config dir error\n");
        applet_exit (1);
    }

    if (spawn_ccnet_daemon () < 0) {
        applet_warning ("Failed to start ccnet\n");;
        applet_exit (1);
    }

    applet_message ("ccnet daemon started\n");
}

/* Kill ccnet/seaf/web, and restart them. */
void restart_all (void)
{
    trayicon_set_tip ("Seafile");
    
    applet_message ("Restarting ccnet ...\n");
    stop_open_browser_timer();
    stop_web_server();
    
    if (applet->client->connected) {
        stop_ccnet();
    }
    
    spawn_ccnet_daemon();
    
    start_conn_daemon_timer (1000, NULL);
}

void 
on_ccnet_daemon_down (void)
{
    applet_warning ("Connection to daemon is down.\n");
    trayicon_rotate (FALSE);
    trayicon_set_ccnet_state (CCNET_STATE_DOWN);
    
    if (applet->client->connected) {
        ccnet_client_disconnect_daemon (applet->client);
        if (applet->sync_client->connected)
            ccnet_client_disconnect_daemon (applet->sync_client);
    }
}

gboolean
on_open_browser_timeout(void)
{
    /* only start the browser after we can successfully connect the
     web server port
     */
    if (test_web_server ()) {
        applet_message ("[web] web server ready, now start browser \n");
        applet->web_status = WEB_READY;

        if (first_use) {
            open_web_browser(SEAF_HTTP_ADDR);
        }

        return FALSE;
    } else {
        //applet_message ("[web] web server not ready, wait for a moment\n");
        return TRUE;
    }
}

#define HEARTBEAT_INTERVAL 2

gboolean heartbeat_monitor (void *data)
{
    if (!applet->heartbeat_monitor_on)
        return FALSE;

    time_t now = time(NULL);

    if (applet->last_heartbeat == 0) {
        applet->last_heartbeat = now;
        return TRUE;
     } else if (now - applet->last_heartbeat > 3 * HEARTBEAT_INTERVAL) {
        /* heartbeat not received */

        if (is_seafile_daemon_running()) {
            return TRUE;
        } else {
            applet_message ("[heartbeat mon] seaf-daemon is down, "
                            "now bring it up..\n");
            applet->auto_sync_disabled = FALSE;
            start_seafile_daemon();
            applet->last_heartbeat = time(NULL);
        }
     }
    return TRUE;
}

void start_heartbeat_monitor (void)
{
    applet_message ("[hearbeat mon] started.\n");
    applet->heartbeat_monitor_on = TRUE;
    start_heartbeat_monitor_timer (2000, NULL);
}

void stop_heartbeat_monitor (void)
{
    applet_message ("[hearbeat mon] stopped.\n");
    applet->heartbeat_monitor_on = FALSE;
}

gboolean
connect_to_server (gpointer data)
{
    if (connect_to_daemon() < 0) {
        return TRUE;
    }

    applet_message ("Connected to ccnet.\n");

    start_seafile_daemon ();
    applet->auto_sync_disabled = FALSE;
    start_heartbeat_monitor();
    start_web_server();

    start_open_browser_timer (1000, NULL);

    return FALSE;
}

int
seafile_applet_start (int argc, char **argv)
{
    int c;
    char *temp_confdir;
    const char *env;

    env = g_getenv("CCNET_CONF_DIR");
    if (env)
        temp_confdir = g_strdup(env);
    else
        temp_confdir = g_strdup(DEFAULT_CONFIG_DIR);

    static const char *short_options = "hvc:";
    static const struct option long_options[] = {
        { "help", no_argument, NULL, 'h' }, 
        { "version", no_argument, NULL, 'v' }, 
        { "config-dir", required_argument, NULL, 'c' },
        { NULL, 0, NULL, 0, },
    };

    while ((c = getopt_long (argc, argv, short_options, 
                             long_options, NULL)) != EOF) {
        switch (c) {
        case 'h':
            applet_exit (1);
            break;
        case 'v':
            applet_exit (1);
            break;
        case 'c':
            if (temp_confdir)
                g_free(temp_confdir);
            temp_confdir = g_strdup(optarg);
            break;
        default:
            applet_exit (1);
        }
    }

    applet->config_dir = ccnet_expand_path (temp_confdir);
    g_free (temp_confdir);

    /* Check and create config dirs. Also start logging. */
    init_ccnet ();
    init_seafile ();

    /* start ccnet daemon and periodically check. */
    start_ccnet ();
    start_conn_daemon_timer (1000, NULL);

    return 0;
}

int is_repo_path_allowed(const char *path) {
    char buf[4096];
    char buf2[4096];
    size_t len = strlen(path);
    if (path[len-1] == '/')
        snprintf(buf, 4095, "%s", path);
    else
        snprintf(buf, 4095, "%s/", path);

    len = strlen(applet->seafile_dir);
    snprintf(buf2, 4095, "%s/", applet->seafile_dir);

    if (strncmp(buf2, buf, strlen(buf)) == 0)
        return 0;

    return 1;
}

extern void set_auto_sync_cb (void *result, void *data, GError *error);

void seafile_disable_auto_sync (void)
{
    SetAutoSyncData *sdata = g_new0 (SetAutoSyncData, 1);
    sdata->disable = TRUE;
    call_seafile_disable_auto_sync (set_auto_sync_cb, sdata);
}

void seafile_enable_auto_sync (void)
{
    SetAutoSyncData *sdata = g_new0 (SetAutoSyncData, 1);
    sdata->disable = FALSE;
    call_seafile_enable_auto_sync (set_auto_sync_cb, sdata);
}
