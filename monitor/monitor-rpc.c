#include <ccnet.h>

#include "seafile-session.h"
#include "seafile-error.h"

#define SEAFILE_DOMAIN g_quark_from_string("MONITOR")

int
monitor_compute_repo_size (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    schedule_repo_size_computation (seaf->scheduler, repo_id);

    return 0;
}
