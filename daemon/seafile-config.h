/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_CONFIG_H
#define SEAFILE_CONFIG_H

#include "seafile-session.h"
#include "db.h"

#define KEY_CLIENT_ID "client_id"
#define KEY_CLIENT_NAME "client_name"

#define KEY_MONITOR_ID  "monitor_id"
#define KEY_CHECK_REPO_PERIOD "check_repo_period"
#define KEY_DB_HOST "db_host"
#define KEY_DB_USER "db_user"
#define KEY_DB_PASSWD "db_passwd"
#define KEY_DB_NAME "db_name"
#define KEY_UPLOAD_LIMIT "upload_limit"
#define KEY_DOWNLOAD_LIMIT "download_limit"
#define KEY_CDC_AVERAGE_BLOCK_SIZE "block_size"
#define KEY_ALLOW_INVALID_WORKTREE "allow_invalid_worktree"
#define KEY_ALLOW_REPO_NOT_FOUND_ON_SERVER "allow_repo_not_found_on_server"
#define KEY_SYNC_EXTRA_TEMP_FILE "sync_extra_temp_file"
#define KEY_DISABLE_BLOCK_HASH "disable_block_hash"
#define KEY_HIDE_WINDOWS_INCOMPATIBLE_PATH_NOTIFICATION "hide_windows_incompatible_path_notification"

/* Http sync settings. */
#define KEY_ENABLE_HTTP_SYNC "enable_http_sync"
#define KEY_DISABLE_VERIFY_CERTIFICATE "disable_verify_certificate"

/* Http sync proxy settings. */
#define KEY_USE_PROXY "use_proxy"
#define KEY_PROXY_TYPE "proxy_type"
#define KEY_PROXY_ADDR "proxy_addr"
#define KEY_PROXY_PORT "proxy_port"
#define KEY_PROXY_USERNAME "proxy_username"
#define KEY_PROXY_PASSWORD "proxy_password"
#define PROXY_TYPE_HTTP "http"
#define PROXY_TYPE_SOCKS "socks"

gboolean
seafile_session_config_exists (SeafileSession *session, const char *key);

/*
 * Returns: config value in string. The string should be freed by caller. 
 */
char *
seafile_session_config_get_string (SeafileSession *session,
                                   const char *key);

/*
 * Returns:
 * If key exists, @exists will be set to TRUE and returns the value;
 * otherwise, @exists will be set to FALSE and returns -1.
 */
int
seafile_session_config_get_int (SeafileSession *session,
                                const char *key,
                                gboolean *exists);

/*
 * Returns: config value in boolean. Return FALSE if the value is not configured. 
 */
gboolean
seafile_session_config_get_bool (SeafileSession *session,
                                 const char *key);


int
seafile_session_config_set_string (SeafileSession *session,
                                   const char *key,
                                   const char *value);

int
seafile_session_config_set_int (SeafileSession *session,
                                const char *key,
                                int value);

int
seafile_session_config_set_allow_invalid_worktree(SeafileSession *session, gboolean val);

gboolean
seafile_session_config_get_allow_invalid_worktree(SeafileSession *session);

gboolean
seafile_session_config_get_allow_repo_not_found_on_server(SeafileSession *session);

sqlite3 *
seafile_session_config_open_db (const char *db_path);


#endif
