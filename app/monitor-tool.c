/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <getopt.h>
#include <errno.h>
#include <string.h>

#include <searpc-client.h>

#include <ccnet.h>
#include <searpc-transport.h>

struct cmd {
    char *name;
    int (*handler) (int argc, char **argv);
};

static int add_server   (int, char **);
static int del_server   (int, char **);
static int list_servers (int, char **);

static struct cmd cmdtab[] =  {
    { "add-server",     add_server  },
    { "del-server",     del_server  },
    { "list-servers",   list_servers  },
    { 0 },
};

CcnetClient *client;
SearpcClient *rpc_client;
SearpcUserPriv priv;

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
"Usage: seaf-server [--version ] [-c CONF_DIR] COMMAND [ARGS]\n"
"\n"
"Available commands are:\n"
"  add-server       Add a chunk server\n"
"  del-server       Delete a chunk server\n"
"  list-servers     List current chunk servers\n"
    ,stderr);
}

void show_version()
{
    fputs ("seafile version: 0.1\n", stderr);
}

SEARPC_CLIENT_DEFUN_INT__STRING(monitor_add_chunk_server)
SEARPC_CLIENT_DEFUN_INT__STRING(monitor_del_chunk_server)
SEARPC_CLIENT_DEFUN_STRING__VOID(monitor_list_chunk_servers)

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

    priv.session = client;
    priv.peer_id = NULL;
    priv.service = "monitor";

    rpc_client = searpc_client_new ();
    rpc_client->transport = searpc_transport_send;
    rpc_client->arg = &priv;

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
        fprintf (stderr, "monitor-tool add-server <peer id | peer name>\n");
        return -1;
    }

    server_id = argv[0];

    if (monitor_add_chunk_server (rpc_client, server_id, &error) < 0) {
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
        fprintf (stderr, "monitor-tool del-server <peer id | peer name>\n");
        return -1;
    }

    server_id = argv[0];

    if (monitor_del_chunk_server (rpc_client, server_id, &error) < 0) {
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

    list = monitor_list_chunk_servers (rpc_client, &error);
    if (!list) {
        fprintf (stderr, "%s\n", error->message);
        return -1;
    }

    printf ("%s", list);

    return 0;
}
