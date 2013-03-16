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

    FILE *fp = fopen (path, "w");
    if (fp == NULL) {
        fprintf (stderr, "Failed to save config file: %s %s.\n",
                 path, strerror(errno));
        return -1;
    }

    fputs (config, fp);
    fclose (fp);

    return 0;
}

static const char *short_opts = "hmvs:t:r:d:p:P:";
static const struct option long_opts[] = {
    { "help", no_argument, NULL, 'h' },
    { "verbose", no_argument, NULL, 'v' },
    { "mysql", no_argument, NULL, 'm' },
    { "host", required_argument, NULL, 's' },
    { "socket", required_argument, NULL, 't' },
    { "root-passwd", required_argument, NULL, 'r' },
    { "seafile-dir", required_argument, NULL, 'd' },
    { "port", required_argument, NULL, 'p' },
    { "httpserver-port", required_argument, NULL, 'P' },
    { 0, 0, 0, 0 },
};

struct seaf_server_config {
    char *mysql_host;
    char *mysql_root_passwd;
    char *mysql_db_name;
    char *mysql_seahub_db_name;
    char *seafile_dir;
    char *mysql_socket;
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
"\n"
"When using mysql database, you need to specify these arguments:\n\n"
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
        case 'm':
            use_mysql = TRUE;
            break;
        case 's':
            config.mysql_host = strdup(optarg);
            break;
        case 't':
            config.mysql_socket = strdup(optarg);
            break;
        case 'r':
            config.mysql_root_passwd = strdup(optarg);
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

    if (use_mysql && !config.mysql_root_passwd) {
        fprintf (stderr, "You choose to use mysql database. "
                 "Mysql Root Password must be specified.\n");
        exit(1);
    }

    if (!config.seafile_dir) {
        fprintf (stderr, "You must specify seafile data dir\n");
        usage(1);
    }

    /* Create database for mysql */
    if (use_mysql) {
        SeafDB *db_root = seaf_db_new_mysql (config.mysql_host, "root",
                                             config.mysql_root_passwd,
                                             NULL, config.mysql_socket);
        if (!db_root) {
        fprintf (stderr, "Out of memory!\n");
        return 1;
        }

        /* Create database for Seafile server. */
        snprintf (sql, sizeof(sql), "CREATE DATABASE IF NOT EXISTS `%s`",
              config.mysql_db_name);
        ret = seaf_db_query (db_root, sql);
        if (ret < 0) {
            fprintf (stderr, "Failed to create database %s.\n", config.mysql_db_name);
        return 1;
        }
        
        if (verbose)
            printf ("Successfully created database:     %s\n",
                    config.mysql_db_name);
        
        /* Create database for Seahub. */
        snprintf (sql, sizeof(sql), "CREATE DATABASE IF NOT EXISTS `%s` character set utf8",
                  config.mysql_seahub_db_name);
        ret = seaf_db_query (db_root, sql);
        if (ret < 0) {
            fprintf (stderr, "Failed to create database %s.\n",
                     config.mysql_seahub_db_name);
            return 1;
        }

        if (verbose)
            printf ("Successfully created database:     %s\n",
                    config.mysql_seahub_db_name);
    }
        
    /* Generate config file. */
    GKeyFile *key_file = g_key_file_new ();

    g_key_file_set_string (key_file, "database", "type",
                           use_mysql ? "mysql" : "sqlite");
    if (use_mysql) {
        g_key_file_set_string (key_file, "database", "host", config.mysql_host);
        g_key_file_set_string (key_file, "database", "user", "root");
        g_key_file_set_string (key_file, "database", "password", config.mysql_root_passwd);
        g_key_file_set_string (key_file, "database", "db_name", config.mysql_db_name);
        if (config.mysql_socket)
            g_key_file_set_string (key_file, "database", "unix_socket", config.mysql_socket);
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
