#include "common.h"

#include "seafile-session.h"
#include "seaf-utils.h"
#include "seaf-db.h"

#include <stdlib.h>
#include <string.h>

char *
seafile_session_get_tmp_file_path (SeafileSession *session,
                                   const char *basename,
                                   char path[])
{
    int path_len;

    path_len = strlen (session->tmp_file_dir);
    memcpy (path, session->tmp_file_dir, path_len + 1);
    path[path_len] = '/';
    strcpy (path + path_len + 1, basename);

    return path;
}

#ifdef SEAFILE_SERVER

#define SQLITE_DB_NAME "seafile.db"

static int
sqlite_db_start (SeafileSession *session)
{
    char *db_path;

    db_path = g_build_filename (session->seaf_dir, SQLITE_DB_NAME, NULL);
    session->db = seaf_db_new_sqlite (db_path);
    if (!session->db) {
        g_warning ("Failed to start sqlite db.\n");
        return -1;
    }

    return 0;
}

static int
mysql_db_start (SeafileSession *session)
{
    char *host, *user, *passwd, *db, *unix_socket;
    GError *error = NULL;

    host = g_key_file_get_string (session->config, "database", "host", &error);
    if (!host) {
        g_warning ("DB host not set in config.\n");
        return -1;
    }

    user = g_key_file_get_string (session->config, "database", "user", &error);
    if (!user) {
        g_warning ("DB user not set in config.\n");
        return -1;
    }

    passwd = g_key_file_get_string (session->config, "database", "password", &error);
    if (!passwd) {
        g_warning ("DB passwd not set in config.\n");
        return -1;
    }

    db = g_key_file_get_string (session->config, "database", "db_name", &error);
    if (!db) {
        g_warning ("DB name not set in config.\n");
        return -1;
    }

    unix_socket = g_key_file_get_string (session->config, 
                                         "database", "unix_socket", &error);

    session->db = seaf_db_new_mysql (host, user, passwd, db, unix_socket);
    if (!session->db) {
        g_warning ("Failed to start mysql db.\n");
        return -1;
    }

    g_free (host);
    g_free (user);
    g_free (passwd);
    g_free (db);
    g_free (unix_socket);

    return 0;
}

static int
pgsql_db_start (SeafileSession *session)
{
    char *host, *user, *passwd, *db, *unix_socket;
    GError *error = NULL;

    host = g_key_file_get_string (session->config, "database", "host", &error);
    if (!host) {
        g_warning ("DB host not set in config.\n");
        return -1;
    }

    user = g_key_file_get_string (session->config, "database", "user", &error);
    if (!user) {
        g_warning ("DB user not set in config.\n");
        return -1;
    }

    passwd = g_key_file_get_string (session->config, "database", "password", &error);
    if (!passwd) {
        g_warning ("DB passwd not set in config.\n");
        return -1;
    }

    db = g_key_file_get_string (session->config, "database", "db_name", &error);
    if (!db) {
        g_warning ("DB name not set in config.\n");
        return -1;
    }

    unix_socket = g_key_file_get_string (session->config,
                                         "database", "unix_socket", &error);

    session->db = seaf_db_new_pgsql (host, user, passwd, db, unix_socket);
    if (!session->db) {
        g_warning ("Failed to start pgsql db.\n");
        return -1;
    }

    g_free (host);
    g_free (user);
    g_free (passwd);
    g_free (db);
    g_free (unix_socket);

    return 0;
}

int
load_database_config (SeafileSession *session)
{
    char *type;
    GError *error = NULL;

    type = g_key_file_get_string (session->config, "database", "type", &error);
    /* Default to use sqlite if not set. */
    if (!type)
        type = "sqlite";

    if (strcasecmp (type, "sqlite") == 0) {
        return sqlite_db_start (session);
    } else if (strcasecmp (type, "mysql") == 0) {
        return mysql_db_start (session);
    } else if (strcasecmp (type, "pgsql") == 0) {
        return pgsql_db_start (session);
    } else {
        g_warning ("Unsupported db type %s.\n", type);
        return -1;
    }

    return 0;
}

#endif
