#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "../common/seaf-db.h"

static int
save_config_file (GKeyFile *key_file, const char *path)
{
    GError *error = NULL;
    char *config = g_key_file_to_data (key_file, NULL, &error);
    if (error) {
        fprintf (stderr, "Failed to save config file to %s: %s\n",
                 path, error->message);
        return -1;
    }

    FILE *fp = g_fopen (path, "w");
    if (fp == NULL) {
        fprintf (stderr, "Failed to save config file: %s %s.\n",
                 path, strerror(errno));
        return -1;
    }

    fputs (config, fp);
    fclose (fp);

    return 0;
}

static const char *short_opts = "hgmvs:t:r:d:p:P:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "verbose", no_argument, NULL, 'v' },
    { "mysql", no_argument, NULL, 'm' },
    { "pgsql", no_argument, NULL, 'g' },
    { "host", required_argument, NULL, 's' },
    { "socket", required_argument, NULL, 't' },
    { "root-passwd", required_argument, NULL, 'r' },
    { "seafile-dir", required_argument, NULL, 'd' },
    { "port", required_argument, NULL, 'p' },
    { "httpserver-port", required_argument, NULL, 'P' },
    { 0, 0, 0, 0 },
};

struct seaf_server_config {
    char *db_host;
    char *db_root_passwd;
    char *db_name;
    char *seahub_db_name;
    char *seafile_dir;
    char *db_socket;
    char *port;
    char *httpserver_port;
}; 

static struct seaf_server_config config = {
    "localhost",
    NULL,
    "seafile-meta",
    "seahub-meta",
    NULL,
    NULL,
    "12001",
};

    
void usage(int code) {
    fprintf (stderr,
"\nUsage: seaf-server-init [OPTIONS]\n"
"Initialize your seafile server configuration\n\n"
"Required arguments are:\n\n" 
"  -h, --help             output help and quit\n"
"  -v, --verbose          output more information\n"
"  -d, --seafile-dir      specify a diretory to put your seafile server config and data\n" 
"  -p, --port             specify a port to to transmit data\n" 
"  -P, --httpserver-port  specify the port to use by httpserver\n" 
"  -m, --mysql            use mysql database. Default is to use sqlite3\n"
"  -g, --pgsql            use postgresql database. Default is to use sqlite3\n"
"\n"
"When using mysql or postgresql database, you need to specify these arguments:\n\n"
"       -r, --root-passwd      your mysql root passwd, needed to create seafile server database\n"
"       -s, --host             Optional. Your mysql server host name, default is localhost\n"
"       -t, --socket           Optional. Your mysql server socket path.\n"
"\n"
        );
    exit(code);
}

int main (int argc, char **argv)
{

    char sql[256];
    gboolean verbose = FALSE;
    gboolean use_mysql = FALSE;
    gboolean use_pgsql = FALSE;
    int ret;

    if (argc == 1)
        usage(1);

    int c;
    while ((c = getopt_long(argc, argv, short_opts, long_opts, NULL)) != EOF) {
        switch (c) {
        case 'h':
            usage(0);
            break;
        case 'v':
            verbose = TRUE;
            break;
        case 'g':
            use_pgsql = TRUE;
            break;
        case 'm':
            use_mysql = TRUE;
            break;
        case 's':
            config.db_host = strdup(optarg);
            break;
        case 't':
            config.db_socket = strdup(optarg);
            break;
        case 'r':
            config.db_root_passwd = strdup(optarg);
            break;
        case 'd':
            config.seafile_dir = strdup(optarg);
            break;
        case 'p':
            config.port = strdup(optarg);
            break;
        case 'P':
            config.httpserver_port = strdup(optarg);
            break;
        default:
            usage(1);
        }
    }

    if ((use_mysql || use_pgsql) && !config.db_root_passwd) {
        fprintf (stderr, "You choose to use mysql database. "
                 "Mysql Root Password must be specified.\n");
        exit(1);
    }

    if (!config.seafile_dir) {
        fprintf (stderr, "You must specify seafile data dir\n");
        usage(1);
    }

    /* Create database for mysql/pgsql */
    if (use_mysql || use_pgsql) {
        SeafDB *db_root;
            
        if (use_mysql)
            db_root = seaf_db_new_mysql (config.db_host, "root",
                                         config.db_root_passwd,
                                         NULL, config.db_socket);
        else
            db_root = seaf_db_new_pgsql (config.db_host, "root",
                                         config.db_root_passwd,
                                         NULL, config.db_socket);

        if (!db_root) {
        fprintf (stderr, "Out of memory!\n");
        return 1;
        }

        /* Create database for Seafile server. */
        snprintf (sql, sizeof(sql), "CREATE DATABASE IF NOT EXISTS `%s`",
              config.db_name);
        ret = seaf_db_query (db_root, sql);
        if (ret < 0) {
            fprintf (stderr, "Failed to create database %s.\n", config.db_name);
        return 1;
        }
        
        if (verbose)
            printf ("Successfully created database:     %s\n",
                    config.db_name);
        
        /* Create database for Seahub. */
        snprintf (sql, sizeof(sql), "CREATE DATABASE IF NOT EXISTS `%s` character set utf8",
                  config.seahub_db_name);
        ret = seaf_db_query (db_root, sql);
        if (ret < 0) {
            fprintf (stderr, "Failed to create database %s.\n",
                     config.seahub_db_name);
            return 1;
        }

        if (verbose)
            printf ("Successfully created database:     %s\n",
                    config.seahub_db_name);
    }
        
    /* Generate config file. */
    GKeyFile *key_file = g_key_file_new ();

    if (use_mysql)
        g_key_file_set_string (key_file, "database", "type", "mysql");
    else if (use_pgsql)
        g_key_file_set_string (key_file, "database", "type", "pgsql");
    else
        g_key_file_set_string (key_file, "database", "type", "sqlite");

    if (use_mysql) {
        g_key_file_set_string (key_file, "database", "host", config.db_host);
        g_key_file_set_string (key_file, "database", "user", "root");
        g_key_file_set_string (key_file, "database", "password", config.db_root_passwd);
        g_key_file_set_string (key_file, "database", "db_name", config.db_name);
        if (config.db_socket)
            g_key_file_set_string (key_file, "database", "unix_socket", config.db_socket);
    }

    g_key_file_set_string (key_file, "network", "port", config.port);
    if (config.httpserver_port) {
        g_key_file_set_string (key_file, "httpserver", "port", config.httpserver_port);
    } else {
        /* httpserver port defaults to 8082 */
        g_key_file_set_string (key_file, "httpserver", "port", "8082");
    }

    struct stat st;
    if (g_lstat (config.seafile_dir, &st) < 0) {
        if (g_mkdir (config.seafile_dir, 0777) < 0) {
            fprintf (stderr, "Directory %s cannot be created.\n", config.seafile_dir);
            return 1;
        }
    }

    char *seafile_conf = g_build_filename (config.seafile_dir, "seafile.conf", NULL);

    if (verbose)
        printf ("Generating config files:           %s\n", seafile_conf);

    if (save_config_file (key_file, seafile_conf) < 0)
        return 1;

    printf ("Done.\n");

    return 0;
}
