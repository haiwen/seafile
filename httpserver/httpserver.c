/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include "log.h"

#include <getopt.h>

#include <event.h>
#include <evhtp.h>

#include <ccnet.h>

#include "seafile-session.h"
#include "httpserver.h"
#include "access-file.h"
#include "upload-file.h"

static char *config_dir = NULL;
static char *seafile_dir = NULL;
static char *bind_addr = "0.0.0.0";
static uint16_t bind_port = 8082;
static int num_threads = 10;
static char *root_dir = NULL;

CcnetClient *ccnet_client;
SeafileSession *seaf;

static const char *short_opts = "hvfc:d:p:b:t:r:l:g:G:D:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "foreground", no_argument, NULL, 'f', },
    { "config-file", required_argument, NULL, 'c', },
    { "seafdir", required_argument, NULL, 'd', },
    { "port", required_argument, NULL, 'p', },
    { "bindaddr", required_argument, NULL, 'b', },
    { "threads", required_argument, NULL, 't', },
    { "root", required_argument, NULL, 'r', },
    { "log", required_argument, NULL, 'l' },
    { "ccnet-debug-level", required_argument, NULL, 'g' },
    { "http-debug-level", required_argument, NULL, 'G' },
    { "debug", required_argument, NULL, 'D' },
};

static void usage ()
{
    fprintf (stderr, "usage: httpserver [-c config_dir] [-d seafile_dir] -r http_root_dir\n");
}

static void
default_cb(evhtp_request_t *req, void *arg)
{
    /* Return empty page. */
    evhtp_send_reply (req, EVHTP_RES_OK);
}

int
main(int argc, char *argv[])
{
    evbase_t *evbase = NULL;
    evhtp_t *htp = NULL;
    int daemon_mode = 1;
    int c;
    char *logfile = NULL;
    char *ccnet_debug_level_str = "info";
    char *http_debug_level_str = "debug";
    const char *debug_str = NULL;

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
        case 'p':
            bind_port = atoi(optarg);
            break;
        case 'b':
            bind_addr = strdup(optarg);
            break;
        case 't':
            num_threads = atoi(optarg);
            break;
        case 'r':
            root_dir = strdup(optarg);
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
            http_debug_level_str = optarg;
            break;
        case 'D':
            debug_str = optarg;
            break;
        default:
            usage();
            exit(-1);
        }
    }

    if (!root_dir) {
        usage();
        exit (-1);
    }

#ifndef WIN32    
    if (daemon_mode)
        daemon(1, 0);
#endif    

    g_type_init();

    ccnet_client = ccnet_client_new();
    if ((ccnet_client_load_confdir(ccnet_client, config_dir)) < 0) {
        g_warning ("Read config dir error\n");
        return -1;
    }

    if (seafile_dir == NULL)
        seafile_dir = g_build_filename (config_dir, "seafile-data", NULL);
    if (logfile == NULL)
        logfile = g_build_filename (seafile_dir, "http.log", NULL);
    
    seaf = seafile_session_new(seafile_dir, ccnet_client);
    if (!seaf) {
        g_warning ("Failed to create seafile session.\n");
        exit (1);
    }
    seafile_session_init(seaf);

    seaf->client_pool = ccnet_client_pool_new (config_dir);

    if (!debug_str)
        debug_str = g_getenv("SEAFILE_DEBUG");
    seafile_debug_set_flags_string (debug_str);

    if (seafile_log_init (logfile, ccnet_debug_level_str,
                          http_debug_level_str) < 0) {
        g_warning ("Failed to init log.\n");
        exit (1);
    }

    evbase = event_base_new();
    htp = evhtp_new(evbase, NULL);

    if (access_file_init (htp, root_dir) < 0)
        exit (1);

    if (upload_file_init (htp) < 0)
        exit (1);
    
    evhtp_set_gencb(htp, default_cb, NULL);

    evhtp_use_threads(htp, NULL, num_threads, NULL);

    if (evhtp_bind_socket(htp, bind_addr, bind_port, 128) < 0) {
        g_warning ("Could not bind socket: %s\n", strerror(errno));
        exit(-1);
    }

    event_base_loop(evbase, 0);

    return 0;
}
