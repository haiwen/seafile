/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>
#include <errno.h>
#include <string.h>

#include <searpc-client.h>

#include <seafile-object.h>

#include <ccnet.h>
#include <seafile.h>

struct cmd {
    char *name;
    int (*handler) (int argc, char **argv);
};

static int add_server   (int, char **);
static int del_server   (int, char **);
static int list_servers (int, char **);
static int set_monitor  (int, char **);
static int get_monitor  (int, char **);
static int put_file     (int, char **);
static int set_user_quota (int, char **);
static int set_org_quota (int, char **);
static int set_org_user_quota (int, char **);

static struct cmd cmdtab[] =  {
    { "add-server",     add_server  },
    { "del-server",     del_server  },
    { "list-servers",   list_servers  },
    { "set-monitor",    set_monitor },
    { "get-monitor",    get_monitor },
    { "put-file",       put_file },
    { "set-user-quota", set_user_quota },
    { "set-org-quota",  set_org_quota },
    { "set-org-user-quota",  set_org_user_quota },
    { 0 },
};

CcnetClient *client;
SearpcClient *rpc_client;
SearpcClient *threaded_rpc_client;

struct cmd *
getcmd (char *name)
{
    char *p, *q;
    struct cmd *c, *found;
    int nmatches, longest;

    longest = 0;
    nmatches = 0;
    found = 0;
    for (c = cmdtab; (p = c->name); c++) {
        for (q = name; *q == *p++; q++)
            if (*q == 0)		/* exact match? */
                return c;
        if (!*q) {	/* the name was a prefix */
            if (q - name > longest) {
                longest = q - name;
                nmatches = 1;
                found = c;
            } else if (q - name == longest)
                nmatches++;
        }
    }
  
    if (nmatches > 1)
        return (struct cmd *)-1;
    return found;
}


void usage()
{
    fputs (
"Usage: seafserv-tool [--version ] [-c CONF_DIR] COMMAND [ARGS]\n"
"\n"
"Available commands are:\n"
"  add-server       Add a chunk server\n"
"  del-server       Delete a chunk server\n"
"  list-servers     List current chunk servers\n"
"  get-monitor          Get monitor id\n"
"  set-monitor          Set monitor id\n"
    ,stderr);
}

void show_version()
{
    fputs ("seafile version: 0.1\n", stderr);
}


static gboolean print_version = FALSE;
static char *config_dir = NULL;

static GOptionEntry entries[] = 
{
    { "version", 0, 0, G_OPTION_ARG_NONE, &print_version, "show version", NULL },
    { "config-file", 'c', 0, G_OPTION_ARG_STRING, &config_dir, 
      "ccnet configuration directory", NULL },
    { NULL },
};

int main (int argc, char *argv[])
{
	struct cmd *c;

    g_type_init ();
	config_dir = DEFAULT_CONFIG_DIR;

    if (argc == 1) {
        usage();
        exit(1);
    }

    GError *error = NULL;
    GOptionContext *context;

    context = g_option_context_new (NULL);
    g_option_context_add_main_entries (context, entries, "seafile");
    if (!g_option_context_parse (context, &argc, &argv, &error))
    {
        g_print ("option parsing failed: %s\n", error->message);
        exit (1);
    }

    if (print_version) {
        show_version();
        exit(1);
    }

    if (argc <= 1) {
        usage();
        exit(1);
    }

    c = getcmd (argv[1]);
    if (c == NULL) {
        usage();
        exit(1);
    }

    client = ccnet_client_new ();
    if ( (ccnet_client_load_confdir(client, config_dir)) < 0 ) {
        fprintf (stderr, "Read config dir error\n");
        exit(1);
    }

	if (ccnet_client_connect_daemon(client, CCNET_CLIENT_SYNC) < 0)
    {
        fprintf(stderr, "Connect to server fail: %s\n", strerror(errno));
        exit(1);
    }

    rpc_client = ccnet_create_rpc_client (client, NULL, "seafserv-rpcserver");
    threaded_rpc_client = ccnet_create_rpc_client (client, NULL,
                                                   "seafserv-threaded-rpcserver");

    argc -= 2;
    argv += 2;
    c->handler (argc, argv);
	
	ccnet_client_disconnect_daemon (client);

	return 0;
}

static int add_server (int argc, char **argv)
{
    char *server_id;
    GError *error = NULL;

    if (argc != 1) {
        fprintf (stderr, "seafserv-tool add-server <peer id>\n");
        return -1;
    }

    server_id = argv[0];

    if (seafile_add_chunk_server (rpc_client, server_id, &error) < 0) {
        fprintf (stderr, "Failed to add chunk server %s.\n", server_id);
        return -1;
    }

    printf ("Added chunk server %s.\n", server_id);

    return 0;
}

static int del_server (int argc, char **argv)
{
    char *server_id;
    GError *error = NULL;

    if (argc != 1) {
        fprintf (stderr, "seafserv-tool del-server <peer id>\n");
        return -1;
    }

    server_id = argv[0];

    if (seafile_del_chunk_server (rpc_client, server_id, &error) < 0) {
        fprintf (stderr, "Failed to delete chunk server %s.\n", server_id);
        return -1;
    }

    printf ("Deleted chunk server %s.\n", server_id);

    return 0;
}

static int list_servers (int argc, char **argv)
{
    GError *error = NULL;
    char *list = NULL;

    list = seafile_list_chunk_servers (rpc_client, &error);
    if (!list) {
        fprintf (stderr, "%s\n", error->message);
        return -1;
    }

    printf ("%s", list);

    return 0;
}

static int set_monitor (int argc, char **argv)
{
    char *monitor_id;
    GError *error = NULL;

    if (argc != 1) {
        fprintf (stderr, "seafserv-tool set-monitor <peer id>\n");
        return -1;
    }

    monitor_id = argv[0];

    if (seafile_set_monitor (rpc_client, monitor_id, &error) < 0) {
        fprintf (stderr, "Failed to set monitor to %s.\n", monitor_id);
        return -1;
    }

    printf ("Set monitor to %s.\n", monitor_id);

    return 0;
}

static int get_monitor (int argc, char **argv)
{
    char *monitor_id;
    GError *error = NULL;

    monitor_id = seafile_get_monitor (rpc_client, &error);
    if (!monitor_id) {
        printf ("Monitor is not set.\n");
        return 0;
    }

    printf ("Monitor is %s.\n", monitor_id);
    return 0;
}

static int put_file (int argc, char **argv)
{
    GError *error = NULL;
    const char *repo_id;
    const char *file_path;
    const char *parent_dir;
    const char *file_name;
    const char *user;
    int ret;

    if (argc != 5) {
        fprintf (stderr, "[usage] seafserv-tool put-file <repo id> <file>"
                 " <parent dir> <file name> <user> \n");
        return -1;
    }

    repo_id = argv[0];
    file_path = argv[1];
    parent_dir = argv[2];
    file_name = argv[3];
    user = argv[4];

    ret = seafile_put_file(threaded_rpc_client, repo_id, file_path,
                           parent_dir, file_name, user, NULL, &error);
    if (ret < 0) {
        fprintf (stderr, "Failed to put a file into server (filepath %s)\n",
                 file_path);
        if (error && error->message)
            fprintf (stderr, "Error: %s\n", error->message);
        return -1;
    }

    printf ("Success to put a file into server\n");
    return 0;
}

static int set_user_quota (int argc, char **argv)
{
    GError *error = NULL;
    const char *user;
    gint64 quota;

    if (argc != 2) {
        fprintf (stderr, "[usage] seafserv-tool set-user-quota <user> <quota>\n");
        return -1;
    }
    user = argv[0];
    quota = strtoll (argv[1], NULL, 10);

    if (seafile_set_user_quota (threaded_rpc_client, user, quota, &error) < 0) {
        fprintf (stderr, "Failed to set user %s quota to %"G_GINT64_FORMAT"\n", user, quota);
        return -1;
    }

    printf ("Successfully set quota for %s to %"G_GINT64_FORMAT".\n", user, quota);
    return 0;
}

static int set_org_quota (int argc, char **argv)
{
    GError *error = NULL;
    int org_id;
    gint64 quota;

    if (argc != 2) {
        fprintf (stderr, "[usage] seafserv-tool set-org-quota <org-id> <quota>\n");
        return -1;
    }
    org_id = atoi (argv[0]);
    quota = strtoll (argv[1], NULL, 10);

    if (seafile_set_org_quota (threaded_rpc_client, org_id, quota, &error) < 0) {
        fprintf (stderr, "Failed to set org %d quota to %"G_GINT64_FORMAT"\n", org_id, quota);
        return -1;
    }

    printf ("Successfully set quota for %d to %"G_GINT64_FORMAT".\n", org_id, quota);
    return 0;
}

static int set_org_user_quota (int argc, char **argv)
{
    GError *error = NULL;
    int org_id;
    const char *user;
    gint64 quota;

    if (argc != 3) {
        fprintf (stderr, "[usage] seafserv-tool set-org-user-quota <org-id> <user> <quota>\n");
        return -1;
    }
    org_id = atoi (argv[0]);
    user = argv[1];
    quota = strtoll (argv[2], NULL, 10);

    if (seafile_set_org_user_quota (threaded_rpc_client, 
                                    org_id, user, quota, &error) < 0) {
        fprintf (stderr, "Failed to set user %s quota to %"G_GINT64_FORMAT"\n", user, quota);
        return -1;
    }

    printf ("Successfully set quota for %s to %"G_GINT64_FORMAT".\n", user, quota);
    return 0;
}
