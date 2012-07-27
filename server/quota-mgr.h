/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef QUOTA_MGR_H
#define QUOTA_MGR_H

struct _SeafQuotaManager {
    struct _SeafileSession *session;
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

#endif
