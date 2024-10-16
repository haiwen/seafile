/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef _PASSWORD_HASH_H
#define _PASSWORD_HASH_H

#define PWD_HASH_PDKDF2 "pbkdf2_sha256"
#define PWD_HASH_ARGON2ID "argon2id"

typedef struct _PwdHashParams {
    char *algo;
    char *params_str;
} PwdHashParams;

void
parse_pwd_hash_params (const char *algo, const char *params_str, PwdHashParams *params);

int
pwd_hash_derive_key (const char *data_in, int in_len,
                     const char *repo_salt,
                     const char *algo, const char *params_str,
                     unsigned char *key);

#endif
