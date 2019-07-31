#ifndef SEAFILE_ERROR_IMPL_H
#define SEAFILE_ERROR_IMPL_H

#include "seafile-error.h"

enum {
    SYNC_ERROR_LEVEL_REPO,
    SYNC_ERROR_LEVEL_FILE,
};

const char *
sync_error_id_to_str (int error);

int
sync_error_level (int error);

#endif
