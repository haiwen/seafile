#ifndef SEAF_LISTEN_MANAGER_H
#define SEAF_LISTEN_MANAGER_H

/**
 * We always listen on the same tcp port for block tx.
 *
 * This module listens on the port, and when a new connection comes in, tries
 * to read a 37-bit uuid(called a `token'), and deliveres the new socket to
 * the corresponding block tx processor by calling the callback it provides
 * when the token is registered.
 */

typedef struct _SeafListenManager       SeafListenManager;
typedef struct _SeafListenManagerPriv   SeafListenManagerPriv;

struct _SeafListenManager {
    int port;
    SeafListenManagerPriv *priv;
};

struct _SeafListenManager *
seaf_listen_manager_new (struct _SeafileSession *session);

int
seaf_listen_manager_start (SeafListenManager *mgr);

typedef void (*ConnAcceptedCB) (evutil_socket_t, void *);

int
seaf_listen_manager_register_token (SeafListenManager *mgr,
                                    const char *token,
                                    ConnAcceptedCB cb,
                                    void *cb_arg);

void
seaf_listen_manager_unregister_token (SeafListenManager *mgr,
                                      const char *token);
char *
seaf_listen_manager_generate_token (SeafListenManager *mgr);

#endif
