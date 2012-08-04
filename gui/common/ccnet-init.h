/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef CCNET_INIT_H
#define CCNET_INIT_H

enum {
    ERR_PERMISSION = 1,
    ERR_CONF_FILE,
    ERR_SEAFILE_CONF,
    ERR_MAX_NUM,
};

int create_new (void);

gboolean is_valid_username(const char *username, int len);

gboolean is_valid_path(const char *path, int len);

#endif

