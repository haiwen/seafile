/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_CHANGE_SET_H
#define SEAF_CHANGE_SET_H

#include <glib.h>
#include "utils.h"

struct _ChangeSetDir;

struct _ChangeSet {
    char repo_id[37];
    /* List of diff entries, used to generate commit description. */
    GList *diff;
    /* A partial tree for all changed directories. */
    struct _ChangeSetDir *tree_root;
};
typedef struct _ChangeSet ChangeSet;

ChangeSet *
changeset_new (const char *repo_id);

void
changeset_free (ChangeSet *changeset);

void
add_to_changeset (ChangeSet *changeset,
                  char status,
                  unsigned char *sha1,
                  SeafStat *st,
                  const char *modifier,
                  const char *path,
                  const char *new_path,
                  gboolean add_to_diff);

char *
commit_tree_from_changeset (ChangeSet *changeset);

#endif
