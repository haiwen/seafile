/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "seafile-session.h"
#include "seaf-db.h"
#include "quota-mgr.h"

static gint64
get_default_quota (GKeyFile *config)
{
    gint quota_gb;

    /* Get default quota configuration in GB. */
    quota_gb = g_key_file_get_integer (config, "quota", "default", NULL);
    if (quota_gb <= 0)
        return INFINITE_QUOTA;

    return quota_gb * ((gint64)1 << 30);
}

SeafQuotaManager *
seaf_quota_manager_new (struct _SeafileSession *session)
{
    SeafQuotaManager *mgr = g_new0 (SeafQuotaManager, 1);
    if (!mgr)
        return NULL;
    mgr->session = session;

    mgr->default_quota = get_default_quota (session->config);

    return mgr;
}

int
seaf_quota_manager_init (SeafQuotaManager *mgr)
{
    SeafDB *db = mgr->session->db;
    const char *sql;

    sql = "CREATE TABLE IF NOT EXISTS UserQuota (user VARCHAR(255) PRIMARY KEY,"
        "quota BIGINT)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS OrgQuota (org_id INTEGER PRIMARY KEY,"
        "quota BIGINT)";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    sql = "CREATE TABLE IF NOT EXISTS OrgUserQuota (org_id INTEGER,"
        "user VARCHAR(255), quota BIGINT, PRIMARY KEY (org_id, user))";
    if (seaf_db_query (db, sql) < 0)
        return -1;

    return 0;
}

int
seaf_quota_manager_set_user_quota (SeafQuotaManager *mgr,
                                   const char *user,
                                   gint64 quota)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "REPLACE INTO UserQuota VALUES ('%s', %"G_GINT64_FORMAT")",
              user, quota);
    return seaf_db_query (mgr->session->db, sql);
}

gint64
seaf_quota_manager_get_user_quota (SeafQuotaManager *mgr,
                                   const char *user)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "SELECT quota FROM UserQuota WHERE user='%s'",
              user);
    return seaf_db_get_int64 (mgr->session->db, sql);
}

int
seaf_quota_manager_set_org_quota (SeafQuotaManager *mgr,
                                  int org_id,
                                  gint64 quota)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "REPLACE INTO OrgQuota VALUES ('%d', %"G_GINT64_FORMAT")",
              org_id, quota);
    return seaf_db_query (mgr->session->db, sql);
}

gint64
seaf_quota_manager_get_org_quota (SeafQuotaManager *mgr,
                                  int org_id)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "SELECT quota FROM OrgQuota WHERE org_id='%d'",
              org_id);
    return seaf_db_get_int64 (mgr->session->db, sql);
}

int
seaf_quota_manager_set_org_user_quota (SeafQuotaManager *mgr,
                                       int org_id,
                                       const char *user,
                                       gint64 quota)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "REPLACE INTO OrgUserQuota VALUES ('%d', '%s', %"G_GINT64_FORMAT")",
              org_id, user, quota);
    return seaf_db_query (mgr->session->db, sql);
}

gint64
seaf_quota_manager_get_org_user_quota (SeafQuotaManager *mgr,
                                       int org_id,
                                       const char *user)
{
    char sql[512];

    snprintf (sql, sizeof(sql),
              "SELECT quota FROM OrgUserQuota WHERE org_id='%d' AND user='%s'",
              org_id, user);
    return seaf_db_get_int64 (mgr->session->db, sql);
}
