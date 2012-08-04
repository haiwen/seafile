#ifndef RPC_WRAPPER_H
#define RPC_WRAPPER_H 
#include <ccnet.h>

void applet_init_ccnet_rpc (CcnetClient *sync_client);
void applet_init_seafile_rpc (CcnetClient *client);


/* ----------------------------------------
 * Functions making using of RPCS 
 * ----------------------------------------
 */

gboolean need_set_relay (void);

gboolean need_login_relay (void);

void
do_login_relay (const char *username, const char *passwd);

/* 1: login in progress
   0: login success
   -1: login failed
*/
int get_login_status (void);

/* 1: connect in progress
   0: connect established
   -1: connect failed
*/
int get_conn_relay_status (void);

void
set_ccnet_config (char *key, char *value);

char *
get_ccnet_config (char *key);

int
call_seafile_create_repo (const char *name, const char *desc,
                          const char *path, const char *relay_id,
                          const char *passwd, int keep_local_history,
                          AsyncCallback callback, void *data);

int
call_seafile_get_config (char *key, AsyncCallback callback, void *data);

int
call_seafile_set_config (char *key, char *value,
                         AsyncCallback callback, void *data);

GList *get_relay_list (void);

char *relay_name_to_id (GList *relays, const char *name);

void free_relay_list (GList *relays);

#endif
