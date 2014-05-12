
#include "common.h"

#include <zdb.h>
#include "seaf-db.h"

#ifdef WIN32
#include <windows.h>
#define sleep(n) Sleep(1000 * (n))
#endif

#define MAX_GET_CONNECTION_RETRIES 3

struct SeafDB {
    int type;
    ConnectionPool_T pool;
};

struct SeafDBRow {
    ResultSet_T res;
};

struct SeafDBTrans {
    Connection_T conn;
};

SeafDB *
seaf_db_new_mysql (const char *host,
                   const char *port,
                   const char *user, 
                   const char *passwd,
                   const char *db_name,
                   const char *unix_socket,
                   gboolean use_ssl,
                   const char *charset,
                   int max_connections)
{
    SeafDB *db;
    GString *url;
    URL_T zdb_url;
    gboolean has_param = FALSE;

    db = g_new0 (SeafDB, 1);
    if (!db) {
        g_warning ("Failed to alloc db structure.\n");
        return NULL;
    }

    char *passwd_esc = g_uri_escape_string (passwd, NULL, FALSE);

    url = g_string_new ("");
    g_string_append_printf (url, "mysql://%s:%s@%s:%s/", user, passwd_esc, host, port);
    if (db_name)
        g_string_append (url, db_name);
    if (unix_socket) {
        g_string_append_printf (url, "?unix-socket=%s", unix_socket);
        has_param = TRUE;
    }
    if (use_ssl) {
        g_string_append_printf (url, "%suse-ssl=true", has_param?"&":"?");
        has_param = TRUE;
    }
    if (charset) {
        g_string_append_printf (url, "%scharset=%s", has_param?"&":"?", charset);
        has_param = TRUE;
    }

    g_free (passwd_esc);

    zdb_url = URL_new (url->str);
    db->pool = ConnectionPool_new (zdb_url);
    if (!db->pool) {
        g_warning ("Failed to create db connection pool.\n");
        g_string_free (url, TRUE);
        g_free (db);
        return NULL;
    }

    ConnectionPool_setMaxConnections (db->pool, max_connections);
    ConnectionPool_start (db->pool);
    db->type = SEAF_DB_TYPE_MYSQL;

    return db;
}

SeafDB *
seaf_db_new_pgsql (const char *host,
                   const char *user,
                   const char *passwd,
                   const char *db_name,
                   const char *unix_socket)
{
    SeafDB *db;
    GString *url;
    URL_T zdb_url;

    db = g_new0(SeafDB, 1);
    if (!db) {
        g_warning ("Failed to alloc db structre.\n");
        return NULL;
    }

    url = g_string_new ("");
    g_string_append_printf (url, "postgresql://%s:%s@%s/", user, passwd, host);
    if (db_name)
        g_string_append (url, db_name);
    if (unix_socket)
        g_string_append_printf (url, "?unix-socket=%s", unix_socket);

    zdb_url = URL_new (url->str);
    db->pool = ConnectionPool_new (zdb_url);
    if (!db->pool) {
        g_warning ("Failed to create db connection pool.\n");
        g_string_free(url, TRUE);
        g_free (db);
        return NULL;
    }

    ConnectionPool_start (db->pool);
    db->type = SEAF_DB_TYPE_PGSQL;

    return db;
}

SeafDB *
seaf_db_new_sqlite (const char *db_path, int max_connections)
{
    SeafDB *db;
    GString *url;
    URL_T zdb_url;

    db = g_new0 (SeafDB, 1);
    if (!db) {
        g_warning ("Failed to alloc db structure.\n");
        return NULL;
    }

    url = g_string_new ("");
    g_string_append_printf (url, "sqlite://%s", db_path);

    zdb_url = URL_new (url->str);
    db->pool = ConnectionPool_new (zdb_url);
    if (!db->pool) {
        g_warning ("Failed to create db connection pool.\n");
        g_string_free (url, TRUE);
        g_free (db);
        return NULL;
    }

    ConnectionPool_setMaxConnections (db->pool, max_connections);
    ConnectionPool_start (db->pool);
    db->type = SEAF_DB_TYPE_SQLITE;

    return db;
}

void
seaf_db_free (SeafDB *db)
{
    ConnectionPool_stop (db->pool);
    ConnectionPool_free (&db->pool);
    g_free (db);
}

int
seaf_db_type (SeafDB *db)
{
    return db->type;
}

static Connection_T
get_db_connection (SeafDB *db)
{
    Connection_T conn;
    int n_retries = 0;

    /* Wait for at most 30 seconds before getting a connection from pool. */
    do {
        conn = ConnectionPool_getConnection (db->pool);
        if (!conn)
            g_usleep (100000);
    } while (!conn && ++n_retries < 300);

    if (!conn)
        g_warning ("Failed to get database connection.\n");

    return conn;
}

int
seaf_db_query (SeafDB *db, const char *sql)
{
    Connection_T conn = get_db_connection (db);
    if (!conn)
        return -1;

    /* Handle zdb "exception"s. */
    TRY
        Connection_execute (conn, "%s", sql);
        Connection_close (conn);
        RETURN (0);
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        return -1;
    END_TRY;

    /* Should not be reached. */
    return 0;
}

gboolean
seaf_db_check_for_existence (SeafDB *db, const char *sql, gboolean *db_err)
{
    Connection_T conn;
    ResultSet_T result;
    gboolean ret = TRUE;

    *db_err = FALSE;

    conn = get_db_connection (db);
    if (!conn) {
        *db_err = TRUE;
        return FALSE;
    }

    TRY
        result = Connection_executeQuery (conn, "%s", sql);
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        *db_err = TRUE;
        return FALSE;
    END_TRY;

    TRY
        if (!ResultSet_next (result))
            ret = FALSE;
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        *db_err = TRUE;
        return FALSE;
    END_TRY;

    Connection_close (conn);

    return ret;
}

int
seaf_db_foreach_selected_row (SeafDB *db, const char *sql, 
                              SeafDBRowFunc callback, void *data)
{
    Connection_T conn;
    ResultSet_T result;
    SeafDBRow seaf_row;
    int n_rows = 0;

    conn = get_db_connection (db);
    if (!conn)
        return -1;

    TRY
        result = Connection_executeQuery (conn, "%s", sql);
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        return -1;
    END_TRY;

    seaf_row.res = result;
    TRY
        while (ResultSet_next (result)) {
            n_rows++;
            if (!callback (&seaf_row, data))
                break;
        }
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        return -1;
    END_TRY;

    Connection_close (conn);
    return n_rows;
}

const char *
seaf_db_row_get_column_text (SeafDBRow *row, guint32 idx)
{
    g_return_val_if_fail (idx < ResultSet_getColumnCount(row->res), NULL);

    return ResultSet_getString (row->res, idx+1);
}

int
seaf_db_row_get_column_int (SeafDBRow *row, guint32 idx)
{
    g_return_val_if_fail (idx < ResultSet_getColumnCount(row->res), -1);

    return ResultSet_getInt (row->res, idx+1);
}

gint64
seaf_db_row_get_column_int64 (SeafDBRow *row, guint32 idx)
{
    g_return_val_if_fail (idx < ResultSet_getColumnCount(row->res), -1);

    return ResultSet_getLLong (row->res, idx+1);
}

int
seaf_db_get_int (SeafDB *db, const char *sql)
{
    int ret = -1;
    Connection_T conn;
    ResultSet_T result;
    SeafDBRow seaf_row;

    conn = get_db_connection (db);
    if (!conn)
        return -1;

    TRY
        result = Connection_executeQuery (conn, "%s", sql);
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        return -1;
    END_TRY;

    seaf_row.res = result;

    TRY
        if (ResultSet_next (result))
            ret = seaf_db_row_get_column_int (&seaf_row, 0);
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        return -1;
    END_TRY;

    Connection_close (conn);
    return ret;
}

gint64
seaf_db_get_int64 (SeafDB *db, const char *sql)
{
    gint64 ret = -1;
    Connection_T conn;
    ResultSet_T result;
    SeafDBRow seaf_row;

    conn = get_db_connection (db);
    if (!conn)
        return -1;

    TRY
        result = Connection_executeQuery (conn, "%s", sql);
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        return -1;
    END_TRY;

    seaf_row.res = result;

    TRY
        if (ResultSet_next (result))
            ret = seaf_db_row_get_column_int64 (&seaf_row, 0);
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        return -1;
    END_TRY;

    Connection_close (conn);
    return ret;
}

char *
seaf_db_get_string (SeafDB *db, const char *sql)
{
    char *ret = NULL;
    const char *s;
    Connection_T conn;
    ResultSet_T result;
    SeafDBRow seaf_row;

    conn = get_db_connection (db);
    if (!conn)
        return NULL;

    TRY
        result = Connection_executeQuery (conn, "%s", sql);
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        return NULL;
    END_TRY;

    seaf_row.res = result;
    
    TRY
        if (ResultSet_next (result)) {
            s = seaf_db_row_get_column_text (&seaf_row, 0);
            ret = g_strdup(s);
        }
    CATCH (SQLException)
        g_warning ("Error exec query %s: %s.\n", sql, Exception_frame.message);
        Connection_close (conn);
        return NULL;
    END_TRY;

    Connection_close (conn);
    return ret;
}

char *
seaf_db_escape_string (SeafDB *db, const char *from)
{
    const char *p = from;
    char *to, *q;

    to = g_malloc0 (2*strlen(from)+1);
    q = to;

    while (*p != '\0') {
        if (*p == '\'' || *p == '\\' || *p == '"') {
            *q = *p;
            *(++q) = *p;
        } else
            *q = *p;
        ++p;
        ++q;
    }

    return to;
}

gboolean
pgsql_index_exists (SeafDB *db, const char *index_name)
{
    char sql[256];
    gboolean db_err = FALSE;

    snprintf (sql, sizeof(sql),
              "SELECT 1 FROM pg_class WHERE relname='%s'",
              index_name);
    return seaf_db_check_for_existence (db, sql, &db_err);
}

/* Prepared Statements */

struct SeafDBStatement {
    PreparedStatement_T p;
    Connection_T conn;
};
typedef struct SeafDBStatement SeafDBStatement;

SeafDBStatement *
seaf_db_prepare_statement (SeafDB *db, const char *sql)
{
    PreparedStatement_T p;
    SeafDBStatement *ret = g_new0 (SeafDBStatement, 1);

    Connection_T conn = get_db_connection (db);
    if (!conn) {
        g_free (ret);
        return NULL;
    }

    TRY
        p = Connection_prepareStatement (conn, "%s", sql);
        ret->p = p;
        ret->conn = conn;
        RETURN (ret);
    CATCH (SQLException)
        g_warning ("Error prepare statement %s: %s.\n", sql, Exception_frame.message);
        g_free (ret);
        Connection_close (conn);
        return NULL;
    END_TRY;

    /* Should not be reached. */
    return NULL;
}

void
seaf_db_statement_free (SeafDBStatement *p)
{
    Connection_close (p->conn);
    g_free (p);
}

int
seaf_db_statement_set_int (PreparedStatement_T p, int idx, int x)
{
    TRY
        PreparedStatement_setInt (p, idx, x);
        RETURN (0);
    CATCH (SQLException)
        g_warning ("Error set int in prep stmt: %s.\n", Exception_frame.message);
        return -1;
    END_TRY;

    return -1;
}

int
seaf_db_statement_set_string (PreparedStatement_T p,
                              int idx, const char *s)
{
    TRY
        PreparedStatement_setString (p, idx, s);
        RETURN (0);
    CATCH (SQLException)
        g_warning ("Error set string in prep stmt: %s.\n", Exception_frame.message);
        return -1;
    END_TRY;

    return -1;
}

int
seaf_db_statement_set_int64 (PreparedStatement_T p,
                             int idx, gint64 x)
{
    TRY
        PreparedStatement_setLLong (p, idx, (long long)x);
        RETURN (0);
    CATCH (SQLException)
        g_warning ("Error set int64 in prep stmt: %s.\n", Exception_frame.message);
        return -1;
    END_TRY;

    return -1;
}

static int
set_parameters_va (PreparedStatement_T p, int n, va_list args)
{
    int i;
    const char *type;

    for (i = 0; i < n; ++i) {
        type = va_arg (args, const char *);
        if (strcmp(type, "int") == 0) {
            int x = va_arg (args, int);
            if (seaf_db_statement_set_int (p, i+1, x) < 0)
                return -1;
        } else if (strcmp (type, "int64") == 0) {
            gint64 x = va_arg (args, gint64);
            if (seaf_db_statement_set_int64 (p, i+1, x) < 0)
                return -1;
        } else if (strcmp (type, "string") == 0) {
            const char *s = va_arg (args, const char *);
            if (seaf_db_statement_set_string (p, i+1, s) < 0)
                return -1;
        } else {
            g_warning ("BUG: invalid prep stmt parameter type %s.\n", type);
            g_return_val_if_reached (-1);
        }
    }

    return 0;
}

int
seaf_db_statement_query (SeafDB *db, const char *sql, int n, ...)
{
    SeafDBStatement *p;
    volatile int ret = 0;

    p = seaf_db_prepare_statement (db, sql);
    if (!p)
        return -1;

    va_list args;
    va_start (args, n);
    if (set_parameters_va (p->p, n, args) < 0) {
        seaf_db_statement_free (p);
        va_end (args);
        return -1;
    }
    va_end (args);

    TRY
        PreparedStatement_execute (p->p);
    CATCH (SQLException)
        g_warning ("Error execute prep stmt: %s.\n", Exception_frame.message);
        ret = -1;
    END_TRY;

    seaf_db_statement_free (p);
    return ret;
}

gboolean
seaf_db_statement_exists (SeafDB *db, const char *sql, gboolean *db_err, int n, ...)
{
    SeafDBStatement *p;
    ResultSet_T result;
    volatile gboolean ret = TRUE;

    *db_err = FALSE;

    p = seaf_db_prepare_statement (db, sql);
    if (!p)
        return FALSE;

    va_list args;
    va_start (args, n);
    if (set_parameters_va (p->p, n, args) < 0) {
        seaf_db_statement_free (p);
        va_end (args);
        return FALSE;
    }
    va_end (args);

    TRY
        result = PreparedStatement_executeQuery (p->p);
    CATCH (SQLException)
        g_warning ("Error exec prep stmt: %s.\n", Exception_frame.message);
        seaf_db_statement_free (p);
        *db_err = TRUE;
        return FALSE;
    END_TRY;

    TRY
        if (!ResultSet_next (result))
            ret = FALSE;
    CATCH (SQLException)
        g_warning ("Error get next result from prep stmt: %s.\n",
                   Exception_frame.message);
        *db_err = TRUE;
        ret = FALSE;
    END_TRY;

    seaf_db_statement_free (p);

    return ret;
}

int
seaf_db_statement_foreach_row (SeafDB *db,
                                const char *sql,
                                SeafDBRowFunc callback, void *data,
                                int n, ...)
{
    SeafDBStatement *p;
    ResultSet_T result;
    SeafDBRow seaf_row;
    volatile int n_rows = 0;

    p = seaf_db_prepare_statement (db, sql);
    if (!p)
        return -1;

    va_list args;
    va_start (args, n);
    if (set_parameters_va (p->p, n, args) < 0) {
        seaf_db_statement_free (p);
        va_end (args);
        return -1;
    }
    va_end (args);

    TRY
        result = PreparedStatement_executeQuery (p->p);
    CATCH (SQLException)
        g_warning ("Error exec prep stmt: %s.\n", Exception_frame.message);
        seaf_db_statement_free (p);
        return -1;
    END_TRY;

    seaf_row.res = result;
    TRY
        while (ResultSet_next (result)) {
            n_rows++;
            if (!callback (&seaf_row, data))
                break;
        }
    CATCH (SQLException)
        g_warning ("Error get next result for prep stmt: %s.\n",
                   Exception_frame.message);
        seaf_db_statement_free (p);
        return -1;
    END_TRY;

    seaf_db_statement_free (p);
    return n_rows;
}

int
seaf_db_statement_get_int (SeafDB *db, const char *sql, int n, ...)
{
    SeafDBStatement *p;
    volatile int ret = -1;
    ResultSet_T result;
    SeafDBRow seaf_row;

    p = seaf_db_prepare_statement (db, sql);
    if (!p)
        return -1;

    va_list args;
    va_start (args, n);
    if (set_parameters_va (p->p, n, args) < 0) {
        seaf_db_statement_free (p);
        va_end (args);
        return -1;
    }
    va_end (args);

    TRY
        result = PreparedStatement_executeQuery (p->p);
    CATCH (SQLException)
        g_warning ("Error exec prep stmt: %s.\n", Exception_frame.message);
        seaf_db_statement_free (p);
        return -1;
    END_TRY;

    seaf_row.res = result;

    TRY
        if (ResultSet_next (result))
            ret = seaf_db_row_get_column_int (&seaf_row, 0);
    CATCH (SQLException)
        g_warning ("Error get next result for prep stmt: %s.\n",
                   Exception_frame.message);
        seaf_db_statement_free (p);
        return -1;
    END_TRY;

    seaf_db_statement_free (p);
    return ret;
}

gint64
seaf_db_statement_get_int64 (SeafDB *db, const char *sql, int n, ...)
{
    SeafDBStatement *p;
    volatile gint64 ret = -1;
    ResultSet_T result;
    SeafDBRow seaf_row;

    p = seaf_db_prepare_statement (db, sql);
    if (!p)
        return -1;

    va_list args;
    va_start (args, n);
    if (set_parameters_va (p->p, n, args) < 0) {
        seaf_db_statement_free (p);
        va_end (args);
        return -1;
    }
    va_end (args);

    TRY
        result = PreparedStatement_executeQuery (p->p);
    CATCH (SQLException)
        g_warning ("Error exec prep stmt: %s.\n", Exception_frame.message);
        seaf_db_statement_free (p);
        return -1;
    END_TRY;

    seaf_row.res = result;

    TRY
        if (ResultSet_next (result))
            ret = seaf_db_row_get_column_int64 (&seaf_row, 0);
    CATCH (SQLException)
        g_warning ("Error get next result for prep stmt: %s.\n",
                   Exception_frame.message);
        seaf_db_statement_free (p);
        return -1;
    END_TRY;

    seaf_db_statement_free (p);
    return ret;
}

char *
seaf_db_statement_get_string (SeafDB *db, const char *sql, int n, ...)
{
    SeafDBStatement *p;
    char *ret = NULL;
    const char *s;
    ResultSet_T result;
    SeafDBRow seaf_row;

    p = seaf_db_prepare_statement (db, sql);
    if (!p)
        return NULL;

    va_list args;
    va_start (args, n);
    if (set_parameters_va (p->p, n, args) < 0) {
        seaf_db_statement_free (p);
        va_end (args);
        return NULL;
    }
    va_end (args);

    TRY
        result = PreparedStatement_executeQuery (p->p);
    CATCH (SQLException)
        g_warning ("Error exec prep stmt: %s.\n", Exception_frame.message);
        seaf_db_statement_free (p);
        return NULL;
    END_TRY;

    seaf_row.res = result;
    
    TRY
        if (ResultSet_next (result)) {
            s = seaf_db_row_get_column_text (&seaf_row, 0);
            ret = g_strdup(s);
        }
    CATCH (SQLException)
        g_warning ("Error get next result for prep stmt: %s.\n",
                   Exception_frame.message);
        seaf_db_statement_free (p);
        return NULL;
    END_TRY;

    seaf_db_statement_free (p);
    return ret;
}

/* Transaction */

SeafDBTrans *
seaf_db_begin_transaction (SeafDB *db)
{
    Connection_T conn;
    SeafDBTrans *trans;

    trans = g_new0 (SeafDBTrans, 1);
    if (!trans)
        return NULL;

    conn = get_db_connection (db);
    if (!conn) {
        g_free (trans);
        return NULL;
    }

    trans->conn = conn;
    TRY
        Connection_beginTransaction (trans->conn);
    CATCH (SQLException)
        g_warning ("Start transaction failed: %s.\n", Exception_frame.message);
        Connection_close (trans->conn);
        g_free (trans);
        return NULL;
    END_TRY;

    return trans;
}

void
seaf_db_trans_close (SeafDBTrans *trans)
{
    Connection_close (trans->conn);
    g_free (trans);
}

int
seaf_db_commit (SeafDBTrans *trans)
{
    Connection_T conn = trans->conn;

    TRY
        Connection_commit (conn);
    CATCH (SQLException)
        g_warning ("Commit failed: %s.\n", Exception_frame.message);
        return -1;
    END_TRY;

    return 0;
}

int
seaf_db_rollback (SeafDBTrans *trans)
{
    Connection_T conn = trans->conn;

    TRY
        Connection_rollback (conn);
    CATCH (SQLException)
        g_warning ("Rollback failed: %s.\n", Exception_frame.message);
        return -1;
    END_TRY;

    return 0;
}

static PreparedStatement_T
trans_prepare_statement (Connection_T conn, const char *sql)
{
    PreparedStatement_T p;

    TRY
        p = Connection_prepareStatement (conn, "%s", sql);
        RETURN (p);
    CATCH (SQLException)
        g_warning ("Error prepare statement %s: %s.\n", sql, Exception_frame.message);
        return NULL;
    END_TRY;

    /* Should not be reached. */
    return NULL;
}

int
seaf_db_trans_query (SeafDBTrans *trans, const char *sql, int n, ...)
{
    PreparedStatement_T p;

    p = trans_prepare_statement (trans->conn, sql);
    if (!p)
        return -1;

    va_list args;
    va_start (args, n);
    if (set_parameters_va (p, n, args) < 0) {
        va_end (args);
        return -1;
    }
    va_end (args);

    /* Handle zdb "exception"s. */
    TRY
        PreparedStatement_execute (p);
        RETURN (0);
    CATCH (SQLException)
        g_warning ("Error exec prep stmt: %s.\n", Exception_frame.message);
        return -1;
    END_TRY;

    /* Should not be reached. */
    return 0;
}

gboolean
seaf_db_trans_check_for_existence (SeafDBTrans *trans,
                                   const char *sql,
                                   gboolean *db_err,
                                   int n, ...)
{
    ResultSet_T result;
    gboolean ret = TRUE;

    *db_err = FALSE;

    PreparedStatement_T p;

    p = trans_prepare_statement (trans->conn, sql);
    if (!p)
        return FALSE;

    va_list args;
    va_start (args, n);
    if (set_parameters_va (p, n, args) < 0) {
        va_end (args);
        return -1;
    }
    va_end (args);

    TRY
        result = PreparedStatement_executeQuery (p);
    CATCH (SQLException)
        g_warning ("Error exec prep stmt: %s.\n", Exception_frame.message);
        *db_err = TRUE;
        return FALSE;
    END_TRY;

    TRY
        if (!ResultSet_next (result))
            ret = FALSE;
    CATCH (SQLException)
        g_warning ("Error get next result for prep stmt: %s.\n",
                   Exception_frame.message);
        *db_err = TRUE;
        return FALSE;
    END_TRY;

    return ret;
}

int
seaf_db_trans_foreach_selected_row (SeafDBTrans *trans, const char *sql, 
                                    SeafDBRowFunc callback, void *data,
                                    int n, ...)
{
    ResultSet_T result;
    SeafDBRow seaf_row;
    int n_rows = 0;

    PreparedStatement_T p;

    p = trans_prepare_statement (trans->conn, sql);
    if (!p)
        return FALSE;

    va_list args;
    va_start (args, n);
    if (set_parameters_va (p, n, args) < 0) {
        va_end (args);
        return -1;
    }
    va_end (args);

    TRY
        result = PreparedStatement_executeQuery (p);
    CATCH (SQLException)
        g_warning ("Error exec prep stmt: %s.\n", Exception_frame.message);
        return -1;
    END_TRY;

    seaf_row.res = result;
    TRY
    while (ResultSet_next (result)) {
        n_rows++;
        if (!callback (&seaf_row, data))
            break;
    }
    CATCH (SQLException)
        g_warning ("Error get next result for prep stmt: %s.\n",
                   Exception_frame.message);
        return -1;
    END_TRY;

    return n_rows;
}
