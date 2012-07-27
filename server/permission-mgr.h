/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_PERM_MGR_H
#define SEAF_PERM_MGR_H

#include <glib.h>

struct _SeafileSession;

typedef struct _SeafPermManager SeafPermManager;
typedef struct _SeafPermManagerPriv SeafPermManagerPriv;

struct _SeafPermManager {
    struct _SeafileSession *seaf;

    SeafPermManagerPriv *priv;
};

SeafPermManager*
seaf_perm_manager_new (struct _SeafileSession *seaf);

int
seaf_perm_manager_init (SeafPermManager *mgr);

int
seaf_perm_manager_set_repo_owner (SeafPermManager *mgr,
                                  const char *repo_id,
                                  const char *user_id);

char *
seaf_perm_manager_get_repo_owner (SeafPermManager *mgr,
                                  const char *repo_id);

/* TODO: add start and limit. */
/* Get repos owned by this user.
 */
GList *
seaf_perm_manager_get_repos_by_owner (SeafPermManager *mgr,
                                      const char *user_id);

#endif
