#ifndef MONITOR_RPC_WRAPPERS_H
#define MONITOR_RPC_WRAPPERS_H

#include <searpc-client.h>
#include <ccnet.h>

#if 0
gint64
monitor_get_repos_size_wrapper (const char *monitor_id,
                                const char *repo_list, 
                                GError **error);

void
monitor_get_repos_size_async_wrapper (const char *monitor_id,
                                      const char *repo_list,
                                      AsyncCallback callback,
                                      void *user_data);
#endif


void
monitor_compute_repo_size_async_wrapper (const char *peer_id,
                                         const char *repo_id,
                                         AsyncCallback callback,
                                         void *user_data);

#endif
