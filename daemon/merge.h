/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef MERGE_H
#define MERGE_H

#include "repo-mgr.h"
#include "commit-mgr.h"
#include "branch-mgr.h"
#include "fs-mgr.h"

int
merge_branches (SeafRepo *repo, SeafBranch *remote_branch, char **error,
                gboolean *real_merge);

int
merge_get_new_block_list (SeafRepo *repo, SeafCommit *remote, BlockList **bl);

#endif
