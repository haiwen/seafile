#ifndef SEAF_DB_H
#define SEAF_DB_H

enum {
    SEAF_DB_TYPE_SQLITE,
    SEAF_DB_TYPE_MYSQL,
    SEAF_DB_TYPE_PGSQL,
};

typedef struct SeafDB SeafDB;
typedef struct SeafDBRow SeafDBRow;
typedef struct SeafDBTrans SeafDBTrans;

typedef gboolean (*SeafDBRowFunc) (SeafDBRow *, void *);

SeafDB *
seaf_db_new_mysql (const char *host,
                   const char *port,
                   const char *user, 
                   const char *passwd,
                   const char *db,
                   const char *unix_socket,
                   gboolean use_ssl,
                   const char *charset,
                   int max_connections);

SeafDB *
seaf_db_new_pgsql (const char *host,
                   const char *user,
                   const char *passwd,
                   const char *db_name,
                   const char *unix_socket);

SeafDB *
seaf_db_new_sqlite (const char *db_path, int max_connections);

void
seaf_db_free (SeafDB *db);

int
seaf_db_type (SeafDB *db);

int
seaf_db_query (SeafDB *db, const char *sql);

gboolean
seaf_db_check_for_existence (SeafDB *db, const char *sql, gboolean *db_err);

int
seaf_db_foreach_selected_row (SeafDB *db, const char *sql, 
                              SeafDBRowFunc callback, void *data);

const char *
seaf_db_row_get_column_text (SeafDBRow *row, guint32 idx);

int
seaf_db_row_get_column_int (SeafDBRow *row, guint32 idx);

gint64
seaf_db_row_get_column_int64 (SeafDBRow *row, guint32 idx);

int
seaf_db_get_int (SeafDB *db, const char *sql);

gint64
seaf_db_get_int64 (SeafDB *db, const char *sql);

char *
seaf_db_get_string (SeafDB *db, const char *sql);

/* Transaction related */

SeafDBTrans *
seaf_db_begin_transaction (SeafDB *db);

void
seaf_db_trans_close (SeafDBTrans *trans);

int
seaf_db_commit (SeafDBTrans *trans);

int
seaf_db_rollback (SeafDBTrans *trans);

int
seaf_db_trans_query (SeafDBTrans *trans, const char *sql, int n, ...);

gboolean
seaf_db_trans_check_for_existence (SeafDBTrans *trans,
                                   const char *sql,
                                   gboolean *db_err,
                                   int n, ...);

int
seaf_db_trans_foreach_selected_row (SeafDBTrans *trans, const char *sql,
                                    SeafDBRowFunc callback, void *data,
                                    int n, ...);

/* Escape a string contant by doubling '\" characters.
 */
char *
seaf_db_escape_string (SeafDB *db, const char *from);

gboolean
pgsql_index_exists (SeafDB *db, const char *index_name);

/* Prepared Statements */

int
seaf_db_statement_query (SeafDB *db, const char *sql, int n, ...);

gboolean
seaf_db_statement_exists (SeafDB *db, const char *sql, gboolean *db_err, int n, ...);

int
seaf_db_statement_foreach_row (SeafDB *db, const char *sql,
                                SeafDBRowFunc callback, void *data,
                                int n, ...);

int
seaf_db_statement_get_int (SeafDB *db, const char *sql, int n, ...);

gint64
seaf_db_statement_get_int64 (SeafDB *db, const char *sql, int n, ...);

char *
seaf_db_statement_get_string (SeafDB *db, const char *sql, int n, ...);

#endif
