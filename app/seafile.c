/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <getopt.h>
#include <errno.h>
#include <string.h>

#include <glib.h>
#include <glib-object.h>
#include <searpc-client.h>

#include <ccnet.h>
#include <utils.h>
#include <seafile.h>
#include <seafile-object.h>

#define DEFAULT_LOG_LEVEL G_LOG_LEVEL_INFO

static int display_log_level = DEFAULT_LOG_LEVEL;

#define PARSE_OPTIONS                                               \
    do {                                                            \
        context = g_option_context_new (NULL);                      \
        g_option_context_add_main_entries (context, cmd_entries, NULL); \
        if (!g_option_context_parse (context, &argc, &argv, &error)) {  \
            g_print ("option parsing failed: %s\n", error->message);    \
            exit (1);                                                   \
        }                                                               \
    } while (0)

CcnetClient *client;
SearpcClient *rpc_client, *threaded_rpc_client;

static void 
seafile_log (const gchar *log_domain, GLogLevelFlags log_level,
             const gchar *message,    gpointer user_data)
{
    /* time_t t; */
    /* struct tm *tm; */
    /* char buf[256]; */
    int len;
    FILE *logfp = stderr;

    if (log_level > display_log_level)
        return;

    fputs ("seafile: ", logfp);
    fputs (message, logfp);
    len = strlen(message);
    if (message[len-1] != '\n')
        fputs ("\n", logfp);
    fflush (logfp);
}

struct cmd
{
    char *name;
    int (*handler) (int argc, char **argv);
};

static int create       (int, char **);
static int repo_remove  (int, char **);
static int set_token    (int, char **);
static int get_token    (int, char **);
static int set_auto     (int, char **);
static int set_manual   (int, char **);
static int list_repos   (int, char **);
static int list_worktrees (int , char **);

static struct cmd cmdtab[] =  {
    { "create",         create  },
    { "repo-rm",        repo_remove },
    { "set-token",      set_token },
    { "get-token",      get_token },
    { "set-auto",       set_auto },
    { "set-manual",     set_manual },
    { "list-repos",     list_repos },
    { "list-worktrees", list_worktrees},
    { 0 },
};

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
  
    if (nmatches > 1) {
        fprintf (stderr, "ambiguous command : %s\n", name);
        return NULL;
    }
    return found;
}


void usage()
{
    fputs (
"Usage: seafile [--version ] [-c CONF_DIR] COMMAND [ARGS]\n"
"\n"
"Available commands are:\n"
"  create               Create an empty repository\n"
"  repo-rm              Remove a repository\n"
"  get-token            Get token for a repo\n"
"  set-token            Set token for a repo\n"
"  set-passwd           Set passwd after fetching an encrypted repo\n"
"  set-auto             Turn on auto sync\n"
"  set-manual           Turn off auto sync\n"
"  diff                 Diff two branches\n"
"  list-repos           List all repositories\n"
"  list-worktrees       list all worktrees\n"
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

#if !GLIB_CHECK_VERSION(2, 35, 0)
    g_type_init();
#endif
    config_dir = DEFAULT_CONFIG_DIR;

    if (argc == 1) {
        usage();
        exit(1);
    }

    int i = 0;

    /* first convert command line args to utf8 */
    for (i = 1; i < argc; i++) {
        argv[i] = ccnet_locale_to_utf8 (argv[i]);
        if (!argv[i])
            return -1;
    }

    GError *error = NULL;
    GOptionContext *context;

    context = g_option_context_new (NULL);
    g_option_context_add_main_entries (context, entries, "seafile");
    /* pass remaining options to handlers   */
    g_option_context_set_ignore_unknown_options (context, TRUE);
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

    g_log_set_default_handler (seafile_log, NULL);

    client = ccnet_client_new ();
    if ( (ccnet_client_load_confdir(client, config_dir)) < 0 ) {
        fprintf (stderr, "Read config dir error\n");
        exit(1);
    }

    if (ccnet_client_connect_daemon (client, CCNET_CLIENT_SYNC) < 0)
    {
        fprintf(stderr, "Connect to server fail: %s\n", strerror(errno));
        exit(1);
    }


    rpc_client = ccnet_create_rpc_client (client, NULL, "seafile-rpcserver");
    threaded_rpc_client = ccnet_create_rpc_client (client, NULL,
                                                   "seafile-threaded-rpcserver");

    argc -= 1;
    argv += 1;
    int ret = c->handler (argc, argv);

    ccnet_client_disconnect_daemon (client);

	return ret ;
}

/* get the passwd from user when creating an encrypted repo */
static char * ask_repo_passwd ()
{
    char *passwd;
    char input1[100];
    char input2[100];
    int retry = 0;
    
    while (retry++ < 3) {
        fputs ("Your passwd (5 ~ 20 chars): ", stdout);
        if (!fgets (input1, 20, stdin))
            continue;
        g_strstrip (input1);
    
        fputs ("Your passwd again: ", stdout);
        if (!fgets (input2, 20, stdin))
            continue;
        g_strstrip (input2);

      
        if (strcmp(input1, input2) == 0) {
            if (strlen(input1) < 5)
                fputs ("Warning: a too short passwd!\n", stdout);
            break;
        }
        
        fputs ("The two passwd you entered are not the same!\n", stdout);

    }
    
    if (retry > 3) {
        return NULL;
    }
         
    passwd = g_strdup (input1);

    return passwd;

}

static int create (int argc, char **argv)
{
    char *passwd = NULL;
    gboolean encrypt = FALSE;
    char *relay_id = NULL;

    GOptionContext *context;
    GError *error = NULL;
    GOptionEntry cmd_entries[] = {
        { .long_name            = "encrypt",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_NONE,
          .arg_data             = &encrypt, 
          .description          = "create an encrypted repo",
          .arg_description      = NULL },
        { .long_name            = "passwd",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &passwd, 
          .description          = "password",
          .arg_description      = NULL },
        { .long_name            = "relay",
          .short_name           = 0,
          .flags                = 0,
          .arg                  = G_OPTION_ARG_STRING,
          .arg_data             = &relay_id,
          .description          = "relay_id",
          .arg_description      = NULL },
        { NULL },
    };
    
    PARSE_OPTIONS;

    argc -= 1;
    argv += 1;

    char *name, *desc, *repo_id, *base = NULL;
    if (argc != 2 && argc != 3) {
        fprintf (stderr, "seafile create [--encrypt] [--passwd=<passwd>] "
                 "[--relay=<relay>] <repo name> <repo description> [worktree]\n");
        return -1;
    }

    if (encrypt && passwd == NULL) {
        if ((passwd = ask_repo_passwd()) == NULL) {
            fputs ("Invalid passwd, aborting. \n", stdout);
            return -1;
        }
    }

    name = argv[0];
    desc = argv[1];
    if (argc == 3)
        base = ccnet_expand_path(argv[2]);

    char *key = "max_repo_base_size";
    char *maxsize_str = seafile_get_config (rpc_client, key, &error);
    if (error) {
        fprintf (stderr, "Failed to query max allowed repo base size config: %s\n", error->message);
        return -1;
    }
#define DEFAULT_MAX_REPO_BASE_SIZE 1024 /* in MB */
    guint max_repo_base_size = DEFAULT_MAX_REPO_BASE_SIZE;

    /* In case there is no config key about this */
    if (maxsize_str)
        max_repo_base_size = (guint)atoi(maxsize_str);

    guint repo_base_size = (guint)seafile_calc_dir_size (rpc_client, base, &error);
    if (error) {
        fprintf (stderr, "Failed to calcuate work tree size: %s\n", error->message);
        return -1;
    }

    if (repo_base_size > max_repo_base_size) {
        fprintf (stderr, "repo base too large! %u MB: (max allowed %u MB)\n",
                 repo_base_size, max_repo_base_size);
        return -1;
    }

    repo_id = seafile_create_repo (rpc_client, name, desc, base,
                                   passwd, relay_id, FALSE, &error);
    if (!repo_id) {
        fprintf (stderr, "Failed to create repository %s: %s\n",
                 ccnet_locale_from_utf8(name),
                 error->message);
        return -1;
    }

    printf ("Repository %s created. ID is %s.\n",
            ccnet_locale_from_utf8(name),
            repo_id);
    return 0;
}

static int repo_remove (int argc, char **argv)
{
    argc -= 1;
    argv += 1;

    char *repo_id;
    GError *error = NULL;

    if (argc != 1) {
        fprintf (stderr, "seafile repo-rm <repo id>\n");
        return -1;
    }

    repo_id = argv[0];

    if (seafile_destroy_repo (threaded_rpc_client, repo_id, &error) < 0) {
        fprintf (stderr, "Failed to remove repository %s: %s\n",
                 repo_id, error->message);
        return -1;
    }

    printf ("Repository %s destroied\n", repo_id);
    return 0;
}


static int set_token (int argc, char **argv)
{
    argc -= 1;
    argv += 1;

    char *repo_id, *token;
    GError *error = NULL;

    if (argc < 2) {
        fprintf (stderr, "seafile set-token <repo id> <token>\n");
        return -1;
    }

    repo_id = argv[0];
    token = argv[1];

    if (seafile_set_repo_token (rpc_client, repo_id, token, &error) < 0) {
        fprintf (stderr, "Failed to set token for repo %s\n", repo_id);
        return -1;
    }

    printf ("Success\n");
    return 0;
}

static int get_token (int argc, char **argv)
{
    argc -= 1;
    argv += 1;

    char *repo_id, *token;
    GError *error = NULL;

    if (argc < 1) {
        fprintf (stderr, "seafile get-token <repo id>\n");
        return -1;
    }

    repo_id = argv[0];

    token = seafile_get_repo_token (rpc_client, repo_id, &error);
    if (!token) {
        fprintf (stderr, "Failed to get token for repo %s\n", repo_id);
        return -1;
    }

    printf ("Token is %s\n", token);
    return 0;
}



static int list_repos (int argc, char **argv)
{
    argc -= 1;
    argv += 1;

    GError *error = NULL;
    GList *repos, *ptr;

    repos = seafile_get_repo_list (rpc_client, -1, -1, &error);
    printf ("ID\tName\tDescription\n");
    printf ("-------\n");
    for (ptr = repos; ptr; ptr = ptr->next) {
        SeafileRepo *repo = ptr->data;
        printf ("%s\t%s\t%s\n", repo->_id, repo->_name, repo->_desc);
    }

    for (ptr = repos; ptr; ptr = ptr->next)
        g_object_unref (ptr->data);
    g_list_free (repos);

    return 0;
}

static int set_auto (int argc, char **argv)
{
    argc -= 1;
    argv += 1;

    GError *error = NULL;
    char *repo_id;

    if (argc != 1) {
        fprintf (stderr, "seafile set-auto <repo id>\n");
        return -1;
    }
    repo_id = argv[0];

    int res = seafile_set_repo_property (rpc_client, repo_id, "auto-sync", "true", &error);
    if (res != 0) {
        fprintf (stderr, "Failed to turn on auto fetch.\n");
        return -1;
    }

    printf ("Successfully trun on auto mode.\n");
    return 0;
}

static int set_manual (int argc, char **argv)
{
    argc -= 1;
    argv += 1;

    GError *error = NULL;
    char *repo_id;

    if (argc != 1) {
        fprintf (stderr, "seafile set-manual <repo id>\n");
        return -1;
    }
    repo_id = argv[0];

    int res = seafile_set_repo_property (rpc_client, repo_id, "auto-sync", "false", &error);
    if (res != 0) {
        fprintf (stderr, "Failed to turn off auto fetch.\n");
        if (error && error->message)
            fprintf (stderr, "Error: %s.\n", error->message);
        return -1;
    }

    printf ("Successfully trun off auto mode.\n");
    return 0;
}

static int list_worktrees (int argc, char **argv)
{
    argc -= 1;
    argv += 1;

    if (argc != 0) {
        fprintf (stderr, "[usage] seafile list-worktrees \n");
        return -1;
    }

    GError *error = NULL;
    GList *repos, *ptr;

    repos = seafile_get_repo_list (rpc_client, -1, -1, &error);

    if (!repos) {
        /* Could be either a rpc error, or no repo at all */
        if (error && error->message) {
            fprintf (stderr, "Failed to get repo info : %s\n", error->message); 
            return -1;
        }

        /* no repo */
        return 0;
    }

    for (ptr = repos; ptr; ptr = ptr->next) {
        SeafileRepo *repo = ptr->data;
        const char *wt;

        wt = seafile_repo_get_worktree(repo);

        if (wt)
            fprintf (stdout, "%s\t%s\n", repo->_id, ccnet_locale_from_utf8(wt));
        else
            fprintf (stderr, "worktree is NULL for repo %s\n", repo->_id);
    }

    for (ptr = repos; ptr; ptr = ptr->next)
        g_object_unref (ptr->data);
    g_list_free (repos);

    return 0;
}
