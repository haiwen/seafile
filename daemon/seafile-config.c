/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include "db.h"

#include "seafile-config.h"

static gboolean
get_value (sqlite3_stmt *stmt, void *data)
{
    char **p_value = data;

    *p_value = g_strdup((char *) sqlite3_column_text (stmt, 0));
    /* Only one result. */
    return FALSE;
}

static char *
config_get_string (sqlite3 *config_db, const char *key)
{
    char sql[256];
    char *value = NULL;

    snprintf (sql, sizeof(sql),
              "SELECT value FROM Config WHERE key='%s';",
              key);
    if (sqlite_foreach_selected_row (config_db, sql,
                                     get_value, &value) < 0)
        return NULL;

    return value;
}

char *
seafile_session_config_get_string (SeafileSession *session,
                                   const char *key)
{
    return (config_get_string (session->config_db, key));
}

int
seafile_session_config_get_int (SeafileSession *session,
                                const char *key,
                                gboolean *exists)
{
    char *value;
    int ret;

    value = config_get_string (session->config_db, key);
    if (!value) {
        if (exists)
            *exists = FALSE;
        return -1;
    }

    if (exists)
        *exists = TRUE;
    ret = atoi (value);
    g_free (value);
    return ret;
}

int
seafile_session_config_set_string (SeafileSession *session,
                                   const char *key,
                                   const char *value)
{
    char sql[256];

    sqlite3_snprintf (sizeof(sql), sql,
                      "REPLACE INTO Config VALUES ('%q', '%q');",
                      key, value);
    if (sqlite_query_exec (session->config_db, sql) < 0)
        return -1;

    return 0;
}

int
seafile_session_config_set_int (SeafileSession *session,
                                const char *key,
                                int value)
{
    char sql[256];

    sqlite3_snprintf (sizeof(sql), sql,
                      "REPLACE INTO Config VALUES ('%q', %d);",
                      key, value);
    if (sqlite_query_exec (session->config_db, sql) < 0)
        return -1;

    return 0;
}

sqlite3 *
seafile_session_config_open_db (const char *db_path)
{
    sqlite3 *db;

    if (sqlite_open_db (db_path, &db) < 0)
        return NULL;

    /*
     * Values are stored in text. You should convert it
     * back to integer if needed when you read it from
     * db.
     */
    char *sql = "CREATE TABLE IF NOT EXISTS Config ("
        "key TEXT PRIMARY KEY, "
        "value TEXT);";
    sqlite_query_exec (db, sql);

    return db;
}

int
seafile_session_config_set_allow_invalid_worktree(SeafileSession *session, gboolean val)
{
    return seafile_session_config_set_string(session, KEY_ALLOW_INVALID_WORKTREE,
                                             val ? "true" : "false");
}

gboolean
seafile_session_config_get_allow_invalid_worktree(SeafileSession *session)
{
    return g_strcmp0(seafile_session_config_get_string(session, \
                        KEY_ALLOW_INVALID_WORKTREE), "true") == 0;
}
