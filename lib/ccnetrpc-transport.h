#ifndef CCNETRPC_TRANPORT_H
#define CCNETRPC_TRANPORT_H

#include <ccnet.h>

typedef struct {
    CcnetClient *session;
    char  *peer_id;       /* NULL if local */
    char  *service;
} CcnetrpcTransportParam;        /* this structure will be parsed to
                                  * ccnet_transport_send ()
                                  */

typedef struct {
    CcnetClient *session;
    char  *peer_id;              /* NULL if local */
    char  *service;
} CcnetrpcAsyncTransportParam;   /* this structure will be parsed to
                                  * ccnet_async_transport_send ()
                                  */

char *ccnetrpc_transport_send (void *arg,
        const gchar *fcall_str, size_t fcall_len, size_t *ret_len);

int ccnetrpc_async_transport_send (void *arg, gchar *fcall_str,
                                 size_t fcall_len, void *rpc_priv);

#endif /* SEARPC_TRANPORT_H */
