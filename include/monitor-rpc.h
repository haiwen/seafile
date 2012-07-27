#ifndef MONITOR_RPC_H
#define MONITOR_RPC_H

/**
 * monitor_compute_repo_size:
 * @repo_id: repo id
 *
 * Returns 0 if successfully scheduled computation.
 */
int
monitor_compute_repo_size (const char *repo_id, GError **error);

#endif
