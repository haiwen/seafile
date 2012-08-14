#ifndef HTTPSERVER_H
#define HTTPSERVER_H

extern SeafileSession *seaf;

typedef struct HttpThreadData {
    SearpcClient *rpc_client;
    SearpcClient *threaded_rpc_client;
} HttpThreadData;

HttpThreadData *
http_request_thread_data (evhtp_request_t * request);

#endif /* HTTPSERVER_H */
