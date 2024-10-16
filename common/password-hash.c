/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <string.h>
#include <glib.h>
#include <argon2.h>
#include "password-hash.h"
#include "seafile-crypt.h"
#include <openssl/rand.h>

#include "utils.h"
#include "log.h"

// pbkdf2
typedef struct Pbkdf2Params {
    int iteration;
} Pbkdf2Params;

static Pbkdf2Params *
parse_pbkdf2_sha256_params (const char *params_str)
{
    Pbkdf2Params *params = NULL;
    if (!params_str) {
        params = g_new0 (Pbkdf2Params, 1);
        params->iteration = 1000;
        return params;
    }
    int iteration;
    iteration = atoi (params_str);
    if (iteration <= 0) {
        iteration = 1000;
    }

    params = g_new0 (Pbkdf2Params, 1);
    params->iteration = iteration;
    return params;
}

static int
pbkdf2_sha256_derive_key (const char *data_in, int in_len,
                          const char *salt,
                          Pbkdf2Params *params,
                          unsigned char *key)
{
    int iteration = params->iteration;

    unsigned char salt_bin[32] = {0};
    hex_to_rawdata (salt, salt_bin, 32);

    PKCS5_PBKDF2_HMAC (data_in, in_len,
                       salt_bin, sizeof(salt_bin),
                       iteration,
                       EVP_sha256(),
                       32, key);
    return 0;
}

// argon2id
typedef struct Argon2idParams{
    gint64 time_cost; 
    gint64 memory_cost;
    gint64 parallelism;
} Argon2idParams;

// The arguments to argon2 are separated by commas.
// Example arguments format:
// 2,102400,8
// The parameters are time_cost, memory_cost, parallelism from left to right.
static Argon2idParams *
parse_argon2id_params (const char *params_str)
{
    char **params;
    Argon2idParams *argon2_params = g_new0 (Argon2idParams, 1);
    if (params_str)
        params = g_strsplit (params_str, ",", 3);
    if (!params_str || g_strv_length(params) != 3) {
        if (params_str)
            g_strfreev (params);
        argon2_params->time_cost = 2; // 2-pass computation
        argon2_params->memory_cost = 102400; // 100 mebibytes memory usage
        argon2_params->parallelism = 8; // number of threads and lanes
        return argon2_params;
    }

    char *p = NULL;
    p = g_strstrip (params[0]);
    argon2_params->time_cost = atoll (p);
    if (argon2_params->time_cost <= 0) {
        argon2_params->time_cost = 2;
    }

    p = g_strstrip (params[1]);
    argon2_params->memory_cost = atoll (p);
    if (argon2_params->memory_cost <= 0) {
        argon2_params->memory_cost = 102400;
    }

    p = g_strstrip (params[2]);
    argon2_params->parallelism = atoll (p);
    if (argon2_params->parallelism <= 0) {
        argon2_params->parallelism = 8;
    }

    g_strfreev (params);
    return argon2_params;
}

static int
argon2id_derive_key (const char *data_in, int in_len,
                     const char *salt,
                     Argon2idParams *params,
                     unsigned char *key)
{
    unsigned char salt_bin[32] = {0};
    hex_to_rawdata (salt, salt_bin, 32);

    argon2id_hash_raw(params->time_cost, params->memory_cost, params->parallelism,
                      data_in, in_len,
                      salt_bin, sizeof(salt_bin),
                      key, 32);

    return 0;
}

// parse_pwd_hash_params is used to parse default pwd hash algorithms.
void
parse_pwd_hash_params (const char *algo, const char *params_str, PwdHashParams *params)
{
    if (g_strcmp0 (algo, PWD_HASH_PDKDF2) == 0) {
        params->algo = g_strdup (PWD_HASH_PDKDF2);
        if (params_str)
            params->params_str = g_strdup (params_str);
        else
            params->params_str = g_strdup ("1000");
    } else if (g_strcmp0 (algo, PWD_HASH_ARGON2ID) == 0) {
        params->algo = g_strdup (PWD_HASH_ARGON2ID);
        if (params_str)
            params->params_str = g_strdup (params_str);
        else
            params->params_str = g_strdup ("2,102400,8");
    } else {
        params->algo = NULL;
    }

    seaf_message ("password hash algorithms: %s, params: %s\n ", params->algo, params->params_str);
}

int
pwd_hash_derive_key (const char *data_in, int in_len,
                     const char *salt,
                     const char *algo, const char *params_str,
                     unsigned char *key)
{
    int ret = 0;
    if (g_strcmp0 (algo, PWD_HASH_ARGON2ID) == 0) {
        Argon2idParams *algo_params = parse_argon2id_params (params_str);
        ret = argon2id_derive_key (data_in, in_len,
                                   salt, algo_params, key);
        g_free (algo_params);
        return ret;
    } else {
        Pbkdf2Params *algo_params = parse_pbkdf2_sha256_params (params_str);
        ret = pbkdf2_sha256_derive_key (data_in, in_len,
                                        salt, algo_params, key);
        g_free (algo_params);
        return ret;
    }
}
