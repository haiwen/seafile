/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef QUOTA_MGR_H
#define QUOTA_MGR_H

#define INFINITE_QUOTA (gint64)-2

struct _SeafQuotaManager {
    struct _SeafileSession *session;

    gint64 default_quota;
    gboolean calc_share_usage;
};
typedef struct _SeafQuotaManager SeafQuotaManager;

SeafQuotaManager *
seaf_quota_manager_new (struct _SeafileSession *session);

int
seaf_quota_manager_init (SeafQuotaManager *mgr);

/* Set/get quota for a personal account. */
int
seaf_quota_manager_set_user_quota (SeafQuotaManager *mgr,
                                   const char *user,
                                   gint64 quota);

gint64
seaf_quota_manager_get_user_quota (SeafQuotaManager *mgr,
                                   const char *user);

/* Set/get quota for a business acount. */
int
seaf_quota_manager_set_org_quota (SeafQuotaManager *mgr,
                                  int org_id,
                                  gint64 quota);

gint64
seaf_quota_manager_get_org_quota (SeafQuotaManager *mgr,
                                  int org_id);

gint64
seaf_quota_manager_get_user_share_usage (SeafQuotaManager *mgr,
                                         const char *user);

/* Set/get quota for a user in a business account.
 * The caller should make sure the user is a member of the organization.
 */
int
seaf_quota_manager_set_org_user_quota (SeafQuotaManager *mgr,
                                       int org_id,
                                       const char *user,
                                       gint64 quota);

gint64
seaf_quota_manager_get_org_user_quota (SeafQuotaManager *mgr,
                                       int org_id,
                                       const char *user);

/*
 * Check if @repo_id still has free space for upload.
 */
int
seaf_quota_manager_check_quota (SeafQuotaManager *mgr,
                                const char *repo_id);

gint64
seaf_quota_manager_get_user_usage (SeafQuotaManager *mgr, const char *user);

gint64
seaf_quota_manager_get_org_usage (SeafQuotaManager *mgr, int org_id);

gint64
seaf_quota_manager_get_org_user_usage (SeafQuotaManager *mgr,
                                       int org_id,
                                       const char *user);

#endif
