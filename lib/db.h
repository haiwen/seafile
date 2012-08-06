/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef DB_UTILS_H
#define DB_UTILS_H

#include <sqlite3.h>

int sqlite_open_db (const char *db_path, sqlite3 **db);

int sqlite_close_db (sqlite3 *db);

sqlite3_stmt *sqlite_query_prepare (sqlite3 *db, const char *sql);

int sqlite_query_exec (sqlite3 *db, const char *sql);
int sqlite_begin_transaction (sqlite3 *db);
int sqlite_end_transaction (sqlite3 *db);

gboolean sqlite_check_for_existence (sqlite3 *db, const char *sql);

typedef gboolean (*SqliteRowFunc) (sqlite3_stmt *stmt, void *data);

int
sqlite_foreach_selected_row (sqlite3 *db, const char *sql, 
                             SqliteRowFunc callback, void *data);

int sqlite_get_int (sqlite3 *db, const char *sql);

gint64 sqlite_get_int64 (sqlite3 *db, const char *sql);

char *sqlite_get_string (sqlite3 *db, const char *sql);


#endif
