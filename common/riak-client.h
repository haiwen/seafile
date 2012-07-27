#ifndef SEAF_RIAK_CLIENT_H
#define SEAF_RIAK_CLIENT_H

#include <glib.h>

#define RIAK_QUORUM -1
#define RIAK_ALL -2

struct SeafRiakClient;
typedef struct SeafRiakClient SeafRiakClient;

SeafRiakClient *
seaf_riak_client_new (const char *host, const char *port);

void
seaf_riak_client_free (SeafRiakClient *client);

int
seaf_riak_client_get (SeafRiakClient *client,
                      const char *bucket,
                      const char *key,
                      void **value,
                      int *size);

int
seaf_riak_client_put (SeafRiakClient *client,
                      const char *bucket,
                      const char *key,
                      void *value,
                      int size,
                      int n_w);

gboolean
seaf_riak_client_query (SeafRiakClient *client,
                        const char *bucket,
                        const char *key);

int
seaf_riak_client_delete (SeafRiakClient *client,
                         const char *bucket,
                         const char *key,
                         int n_w);

#endif
