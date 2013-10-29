/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <string.h>

#include <ccnet.h>
#include "seafile-session.h"
#include "chunkserv-mgr.h"
#include "processors/putcs-proc.h"

#define CHUNKSERVER_DB "chunkserver.db"

SeafCSManager *
seaf_cs_manager_new (SeafileSession *seaf)
{
    SeafCSManager *mgr = g_new0 (SeafCSManager, 1);

    /* char *db_path = g_build_filename (seaf->seaf_dir, CHUNKSERVER_DB, NULL); */
    /* if (sqlite_open_db (db_path, &mgr->db) < 0) { */
    /*     g_critical ("Failed to open chunk server db\n"); */
    /*     g_free (db_path); */
    /*     g_free (mgr); */
    /*     return NULL; */
    /* } */

    mgr->seaf = seaf;
    mgr->chunk_servers = g_hash_table_new_full (g_str_hash, g_str_equal,
                                                g_free, NULL);

    return mgr;
}

static int
load_chunk_servers (SeafCSManager *mgr)
{
    /* char             sql[256]; */
    /* sqlite3_stmt    *stmt; */
    /* int              result; */
    /* char            *cs_id; */

    /* snprintf (sql, 256, "SELECT cs_id FROM chunkservers;"); */

    /* stmt = sqlite_query_prepare (mgr->db, sql); */
    /* if (!stmt) */
    /*     return -1; */

    /* while ((result = sqlite3_step (stmt)) == SQLITE_ROW) { */
    /*     cs_id = (char *) sqlite3_column_text (stmt, 0); */
    /*     g_hash_table_insert (mgr->chunk_servers, g_strdup(cs_id), NULL); */
    /* } */

    /* if (result == SQLITE_ERROR) { */
    /*     const gchar *str = sqlite3_errmsg (mgr->db); */

    /*     g_warning ("Couldn't execute query, error: %d->'%s'\n",  */
    /*                result, str ? str : "no error given"); */
    /*     sqlite3_finalize (stmt); */

    /*     return -1; */
    /* } */
    /* sqlite3_finalize (stmt); */

    /* Add myself as chunk server by default. */
    g_hash_table_insert (mgr->chunk_servers, 
                         g_strdup(mgr->seaf->session->base.id),
                         NULL);

    return 0;
}

static void
register_processors (SeafCSManager *mgr)
{
    CcnetClient *client = mgr->seaf->session;

    ccnet_register_service (client, "seafile-putcs", "basic",
                            SEAFILE_TYPE_PUTCS_PROC, NULL);
}

int
seaf_cs_manager_start (SeafCSManager *mgr)
{
    /* const char *sql; */

    register_processors (mgr);

    /* sql = "CREATE TABLE IF NOT EXISTS chunkservers " */
    /*     "(id INTEGER PRIMARY KEY, cs_id TEXT);"; */
    /* if (sqlite_query_exec (mgr->db, sql) < 0) */
    /*     return -1; */

    return (load_chunk_servers (mgr));
}

int
seaf_cs_manager_add_chunk_server (SeafCSManager *mgr, const char *cs_id)
{
    char sql[256];

    snprintf (sql, 256, "INSERT INTO chunkservers VALUES (NULL, '%s');", cs_id);
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    g_hash_table_insert (mgr->chunk_servers, g_strdup(cs_id), NULL);

    return 0;
}

int
seaf_cs_manager_del_chunk_server (SeafCSManager *mgr, const char *cs_id)
{
    char sql[256];

    snprintf (sql, 256, "DELETE FROM chunkservers WHERE cs_id = '%s';", cs_id);
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    g_hash_table_remove (mgr->chunk_servers, cs_id);

    return 0;
}

GList*
seaf_cs_manager_get_chunk_servers (SeafCSManager *mgr)
{
    return (g_hash_table_get_keys(mgr->chunk_servers));
}
