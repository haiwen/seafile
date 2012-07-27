/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <ccnet.h>

#include "db.h"
#include "seafile-session.h"
#include "permission-mgr.h"

#define PERM_DB "perm.db"

struct _SeafPermManagerPriv {
    sqlite3    *db;
};

static int load_db (SeafPermManager *mgr);

SeafPermManager *
seaf_perm_manager_new (SeafileSession *seaf)
{
    SeafPermManager *mgr = g_new0 (SeafPermManager, 1);
    mgr->priv = g_new0 (SeafPermManagerPriv, 1);
    mgr->seaf = seaf;
    return mgr;
}

int
seaf_perm_manager_init (SeafPermManager *mgr)
{
    return load_db (mgr);
}

static int
load_db (SeafPermManager *mgr)
{
    char *db_path = g_build_filename (mgr->seaf->seaf_dir, PERM_DB, NULL);
    if (sqlite_open_db (db_path, &mgr->priv->db) < 0) {
        g_critical ("[Permission mgr] Failed to open permission db\n");
        g_free (db_path);
        g_free (mgr);
        return -1;
    }
    g_free (db_path);

    const char *sql;

    return 0;
}

