/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#ifndef USE_GPL_CRYPTO

#include <curl/curl.h>
#include <openssl/crypto.h>
#include <pthread.h>

#include "curl-init.h"

pthread_mutex_t* curl_locks = NULL;

void seafile_curl_locking_callback(int mode, int n, const char* file, int line)
{
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock (&curl_locks[n]);
    } else {
        pthread_mutex_unlock (&curl_locks[n]);
    }
}

void seafile_curl_init()
{
    int i;
    curl_locks = malloc (sizeof(pthread_mutex_t) * CRYPTO_num_locks());
    for (i = 0; i < CRYPTO_num_locks(); ++i) {
        pthread_mutex_init (&curl_locks[i], NULL);
    }

#ifndef WIN32
    /* On Windows it's better to use the default id_function.
     * As per http://linux.die.net/man/3/crypto_set_id_callback,
     * the default id_functioin uses system's default thread
     * identifying API.
     */
    CRYPTO_set_id_callback (pthread_self);
#endif
    CRYPTO_set_locking_callback (seafile_curl_locking_callback);
}

void seafile_curl_deinit()
{
    int i;
    CRYPTO_set_id_callback (0);
    CRYPTO_set_locking_callback (0);

    for (i = 0; i < CRYPTO_num_locks(); ++i) {
        pthread_mutex_destroy (&curl_locks[i]);
    }
    free (curl_locks);
}

#endif
