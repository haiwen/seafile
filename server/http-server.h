#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <glib.h>

struct _SeafileSession;

struct _HttpServer;

struct _HttpServerStruct {
    struct _SeafileSession *seaf_session;

    struct _HttpServer *priv;

    char *bind_addr;
    int bind_port;
    char *http_temp_dir;        /* temp dir for file upload */
    char *windows_encoding;
    gint64 max_upload_size;
    gint64 max_download_dir_size;
    int max_indexing_threads;
};

typedef struct _HttpServerStruct HttpServerStruct;

HttpServerStruct *
seaf_http_server_new (struct _SeafileSession *session);

int
seaf_http_server_start (HttpServerStruct *htp_server);

int
seaf_http_server_invalidate_tokens (HttpServerStruct *htp_server,
                                    const GList *tokens);

#endif
