
#include <glib.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include "db.h"

int
sqlite_open_db (const char *db_path, sqlite3 **db)
{
    int result;
    const char *errmsg;

    result = sqlite3_open (db_path, db);
    if (result) {
        errmsg = sqlite3_errmsg (*db);
                                
        g_warning ("Couldn't open database:'%s', %s\n", 
                   db_path, errmsg ? errmsg : "no error given");

        sqlite3_close (*db);
        return -1;
    }

    return 0;
}

int sqlite_close_db (sqlite3 *db)
{
    return sqlite3_close (db);
}

sqlite3_stmt *
sqlite_query_prepare (sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt;
    int result;

    result = sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL);

    if (result != SQLITE_OK) {
        const gchar *str = sqlite3_errmsg (db);

        g_warning ("Couldn't prepare query, error:%d->'%s'\n\t%s\n", 
                   result, str ? str : "no error given", sql);

        return NULL;
    }

    return stmt;
}

int
sqlite_query_exec (sqlite3 *db, const char *sql)
{
    char *errmsg = NULL;
    int result;

    result = sqlite3_exec (db, sql, NULL, NULL, &errmsg);

    if (result != SQLITE_OK) {
        if (errmsg != NULL) {
            g_warning ("SQL error: %d - %s\n:\t%s\n", result, errmsg, sql);
            sqlite3_free (errmsg);
        }
        return -1;
    }

    return 0;
}

int
sqlite_begin_transaction (sqlite3 *db)
{
    char *sql = "BEGIN TRANSACTION;";
    return sqlite_query_exec (db, sql);
}

int
sqlite_end_transaction (sqlite3 *db)
{
    char *sql = "END TRANSACTION;";
    return sqlite_query_exec (db, sql);
}


gboolean
sqlite_check_for_existence (sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt;
    int result;

    stmt = sqlite_query_prepare (db, sql);
    if (!stmt)
        return FALSE;

    result = sqlite3_step (stmt);
    if (result == SQLITE_ERROR) {
        const gchar *str = sqlite3_errmsg (db);

        g_warning ("Couldn't execute query, error: %d->'%s'\n", 
                   result, str ? str : "no error given");
        sqlite3_finalize (stmt);
        return FALSE;
    }
    sqlite3_finalize (stmt);

    if (result == SQLITE_ROW)
        return TRUE;
    return FALSE;
}

int
sqlite_foreach_selected_row (sqlite3 *db, const char *sql, 
                             SqliteRowFunc callback, void *data)
{
    sqlite3_stmt *stmt;
    int result;
    int n_rows = 0;

    stmt = sqlite_query_prepare (db, sql);
    if (!stmt) {
        return -1;
    }

    while (1) {
        result = sqlite3_step (stmt);
        if (result != SQLITE_ROW)
            break;
        n_rows++;
        if (!callback (stmt, data))
            break;
    }

    if (result == SQLITE_ERROR) {
        const gchar *s = sqlite3_errmsg (db);

        g_warning ("Couldn't execute query, error: %d->'%s'\n",
                   result, s ? s : "no error given");
        sqlite3_finalize (stmt);
        return -1;
    }

    sqlite3_finalize (stmt);
    return n_rows;
}

int sqlite_get_int (sqlite3 *db, const char *sql)
{
    int ret = -1;
    int result;
    sqlite3_stmt *stmt;

    if ( !(stmt = sqlite_query_prepare(db, sql)) )
        return 0;

    result = sqlite3_step (stmt);
    if (result == SQLITE_ROW) {
        ret = sqlite3_column_int (stmt, 0);
        sqlite3_finalize (stmt);
        return ret;
    }

    if (result == SQLITE_ERROR) {
        const gchar *str = sqlite3_errmsg (db);
        g_warning ("Couldn't execute query, error: %d->'%s'\n",
                   result, str ? str : "no error given");
        sqlite3_finalize (stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return ret;
}

gint64 sqlite_get_int64 (sqlite3 *db, const char *sql)
{
    gint64 ret = -1;
    int result;
    sqlite3_stmt *stmt;

    if ( !(stmt = sqlite_query_prepare(db, sql)) )
        return 0;

    result = sqlite3_step (stmt);
    if (result == SQLITE_ROW) {
        ret = sqlite3_column_int64 (stmt, 0);
        sqlite3_finalize (stmt);
        return ret;
    }

    if (result == SQLITE_ERROR) {
        const gchar *str = sqlite3_errmsg (db);
        g_warning ("Couldn't execute query, error: %d->'%s'\n",
                   result, str ? str : "no error given");
        sqlite3_finalize (stmt);
        return -1;
    }

    sqlite3_finalize(stmt);
    return ret;
}

char *sqlite_get_string (sqlite3 *db, const char *sql)
{
    const char *res = NULL;
    int result;
    sqlite3_stmt *stmt;
    char *ret;

    if ( !(stmt = sqlite_query_prepare(db, sql)) )
        return NULL;

    result = sqlite3_step (stmt);
    if (result == SQLITE_ROW) {
        res = (const char *)sqlite3_column_text (stmt, 0);
        ret = g_strdup(res);
        sqlite3_finalize (stmt);
        return ret;
    }

    if (result == SQLITE_ERROR) {
        const gchar *str = sqlite3_errmsg (db);
        g_warning ("Couldn't execute query, error: %d->'%s'\n",
                   result, str ? str : "no error given");
        sqlite3_finalize (stmt);
        return NULL;
    }

    sqlite3_finalize(stmt);
    return NULL;
}
