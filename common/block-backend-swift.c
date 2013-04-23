#include "common.h"
#include "log.h"
#include "block-backend.h"
#include <curl/curl.h>
#include <event2/buffer.h>

#include "utils.h"
#include <glib.h>
#include "string.h"
#include <json-glib/json-glib.h>

#define SWIFT_COMMIT_EA_NAME "commit"
#define MAX_BUFFER_SIZE 1 << 20 /* Buffer 1MB data */

// This is a swift user authentication information.Maybe in the future with seafile user bind. 
#define DEFAULT_TENANTNAME "myproject"
#define DEAFULT_USERNAME "renwofei"
#define DEFAULT_PASSWORD "123123"

struct _BHandle {
    char block_id[41];
    int rw_type;
    CURL *curl;   
    struct evbuffer *buffer;
    int swift_op;
};

typedef struct {
    char *auth_url;
    char *containername;
    char *tenantname;
    char *username;
    char *password;

    char *storage_url;
    char *auth_token; 

} SwiftPriv;

typedef struct SwiftObject {
    void *data;
    size_t size;
} SwiftObject;

static size_t
send_object (void *ptr, size_t size, size_t nmemb, void *userp)
{    
    size_t realsize = size *nmemb;
    size_t copy_size;
    SwiftObject *object = userp;

    if (object->size == 0)
        return 0;

    copy_size = MIN(object->size, realsize);
    memcpy (ptr, object->data, copy_size);
    object->size -= copy_size;
    object->data = object->data + copy_size;

    return copy_size;
}


static size_t
recv_object (void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    SwiftObject *object = userp;

    object->data = g_realloc (object->data, object->size + realsize);
    if (!object->data) {
        seaf_warning ("[swift http] Not enough memory.\n");
        /* return a value other than realsize to signify an error. */
        return 0;
    }

    memcpy (object->data + object->size, contents, realsize);
    object->size += realsize;

    return realsize;
}

static int
get_storage_url_and_token(SwiftPriv *priv)
{
    CURL *curl = curl_easy_init();   
    struct curl_slist *headers = NULL;
    // char data[256]="\0";
    int rc, ret = 0;
    SwiftObject *object = g_new0 (SwiftObject, 1);
    GString *url = g_string_new (priv->auth_url);
    GString *data = g_string_new (NULL);

    g_string_append_printf (data, 
                            "{\"auth\": {\"tenantName\":\"%s\", \"passwordCredentials\":{\"username\": \"%s\", \"password\": \"%s\"}}}",
                            priv->tenantname, priv->username, priv->password);   

    headers = curl_slist_append (headers, "Content-type: application/json");
    curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt (curl, CURLOPT_URL, url->str);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data->str);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(data->str));
    /* Ask libcurl to send a PUT request. */
    curl_easy_setopt (curl, CURLOPT_POST, 1L);
    // curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1L);

    /* header info */
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    // // Just for DEBUG,print to terminal:
    // curl_easy_setopt(curl, CURLOPT_WRITEHEADER, stdout);
    // curl_easy_setopt(curl, CURLOPT_WRITEDATA, stdout);

    /* Setup callback for receiving http message body. */
    curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, recv_object);
    curl_easy_setopt (curl, CURLOPT_WRITEDATA, object);    

    rc = curl_easy_perform (curl);

    if (rc != 0) {
        seaf_warning ("[Swift http] Failed to get StorageUrl and Token  [%s:%s]: %s.\n",
                      priv->auth_url, priv->username, curl_easy_strerror(rc));
        g_free (object->data);
        ret = -1;
    }

    /* Start to parser json */
    JsonParser *parser = json_parser_new();
    if (!json_parser_load_from_data(parser, object->data, -1, NULL)){
        seaf_warning("In get_storage_url_and_token, json_parser_load_from_data error\n");
    }
    JsonReader *reader = json_reader_new(json_parser_get_root(parser));

    int ret1 = json_reader_read_member(reader, "access");
    int ret2 = json_reader_read_member(reader, "token");
    int ret3 = json_reader_read_member(reader, "id");
    const char *token_id = json_reader_get_string_value(reader);
    priv->auth_token = g_strdup(token_id);

    /* restart to read storage_url */
    json_reader_end_element (reader);
    json_reader_end_member (reader);

    int ret12 = json_reader_read_member(reader, "serviceCatalog");
    int ret13 = json_reader_read_element(reader, 4);
    int ret14 = json_reader_read_member(reader, "endpoints");
    int ret15 = json_reader_read_element(reader, 0);
    int ret16 = json_reader_read_member(reader, "publicURL");
    const char *storage_url = json_reader_get_string_value(reader);    
    priv->storage_url = g_strdup(storage_url);
   
    /* Clear options for future use. */
    curl_easy_cleanup (curl);
    curl_slist_free_all (headers);
    g_string_free (url, TRUE);
    g_free (object);

    return ret;

}

static int
swift_init(SwiftPriv *priv,const char *auth_url, const char *containername)
{
    priv->auth_url = g_strdup(auth_url);
    priv->tenantname = g_strdup(DEFAULT_TENANTNAME);
    priv->username = g_strdup(DEAFULT_USERNAME);
    priv->password = g_strdup(DEFAULT_PASSWORD);
    priv->containername = g_strdup(containername);    

    if (get_storage_url_and_token(priv)<0){
        seaf_warning("Swift init Failed!\n\n");
        return -1;        
    }else{
       return 0; 
    }    
}

BHandle *
block_backend_swift_open_block (BlockBackend *bend,
                               const char *block_id,
                               int rw_type)
{
    // printf("Function::block_backend_swift_open_block ...\n");
    BHandle *handle;

    SwiftPriv *priv = bend->be_priv;
    if (get_storage_url_and_token(priv)<0){
        seaf_warning("get_storage_url_and_token in block_backend_swift_open_block Failed!\n\n");
        return -1;        
    }

    g_return_val_if_fail (block_id != NULL, NULL);
    g_return_val_if_fail (strlen(block_id) == 40, NULL);
    g_assert (rw_type == BLOCK_READ || rw_type == BLOCK_WRITE);

    handle = g_new0(BHandle, 1);
    memcpy (handle->block_id, block_id, 41);
    
    handle->rw_type = rw_type;
    
    handle->curl = curl_easy_init();  
    handle->buffer = evbuffer_new (); 
    handle->swift_op = -1;

    return handle;
}

int
swift_read(SwiftPriv *priv, BHandle *handle)
{
    CURL *curl = handle->curl;   
    GString *url = g_string_new (NULL);
    SwiftObject *object = g_new0 (SwiftObject, 1);
    int rc, ret = 0;
    GString *header_X_Auth_Token = g_string_new (NULL);
    struct curl_slist *headers = NULL;

    g_string_append_printf (url, "%s/%s/%s",priv->storage_url, priv->containername, handle->block_id);
    curl_easy_setopt (curl, CURLOPT_URL, url->str);

    /* Setup callback for receiving http message body. */
    curl_easy_setopt (curl, CURLOPT_WRITEFUNCTION, recv_object);
    curl_easy_setopt (curl, CURLOPT_WRITEDATA, object);
    curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1L);

    // curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);


    g_string_append_printf(header_X_Auth_Token,"X-Auth-Token: %s",priv->auth_token);
    headers = curl_slist_append(headers, header_X_Auth_Token->str);

    curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);

    rc = curl_easy_perform (curl);
   
    if (rc != 0) {
        ret = -1;
        g_free (object->data);
    }

    ret = (int)object->size;
    
    if (evbuffer_add (handle->buffer, object->data, ret) < 0) {
        seaf_warning ("[block bend] Failed to add to buffer.\n");
        // g_free (tmp_buf);
        return -1;
    }

    handle->swift_op = 0;

    /* Clear options for future use. */
    curl_easy_reset (handle->curl);
    curl_slist_free_all (headers);
    g_string_free (url, TRUE);
    g_string_free (header_X_Auth_Token, TRUE);
    g_free (object);
    return ret;

}

int
block_backend_swift_read_block (BlockBackend *bend, BHandle *handle,
                               void *buf, int len)
{    
    ccnet_warning("Function::block_backend_swift_read_block...");
    SwiftPriv *priv = bend->be_priv;    
    int ret;

    if(handle->swift_op < 0){
        seaf_warning("block_backend_swift_read_block handle->swift_op is %d\n",handle->swift_op);
        // char *tmp_buf;
        // // 2097152 must be bigger then max block sieze;
        // tmp_buf = g_new (char, MAX_BUFFER_SIZE);
        // char tmp_buf[MAX_BUFFER_SIZE *100];
        ret = swift_read(priv, handle);
        if (ret<0){
            seaf_warning("swift_read Failed!!!!!!\n");
            return -1;
        }

    }
    return evbuffer_remove (handle->buffer, buf, len);
}


int
swift_write(SwiftPriv *priv, BHandle *handle, const char *buf, size_t len)
{
    CURL *curl = handle->curl;
    GString *url= g_string_new (NULL);
    GString *header_len = g_string_new (NULL);
    GString *header_etag = g_string_new (NULL);
    GString *header_X_Auth_Token = g_string_new(NULL);
    SwiftObject *object = g_new0 (SwiftObject, 1);
    int rc, ret = 0;
    struct curl_slist *headers = NULL;

    headers = curl_slist_append (headers, "Content-type: application/octet-stream");

    g_string_append_printf(header_etag,"ETag: %s",
                           g_compute_checksum_for_data(G_CHECKSUM_MD5, buf, len));    
    headers = curl_slist_append (headers, header_etag->str);

    g_string_append_printf(header_len,"Content-Length: %d",len);
    headers = curl_slist_append (headers, header_len->str);

    g_string_append_printf(header_X_Auth_Token,"X-Auth-Token: %s",priv->auth_token);
    headers = curl_slist_append(headers, header_X_Auth_Token->str);

    curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);

    g_string_append_printf (url, "%s/%s/%s",
                            priv->storage_url, priv->containername, handle->block_id);
   
    curl_easy_setopt (curl, CURLOPT_URL, url->str);

    /* headers info */
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt (curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1L);

    object->data = buf;
    object->size = len;

    curl_easy_setopt (curl, CURLOPT_READFUNCTION, send_object);
    curl_easy_setopt (curl, CURLOPT_READDATA, object);
   
    rc = curl_easy_perform (curl);
    

    if (rc != 0) {
        seaf_warning ("[Swift http] Failed to put object [%s:%s]: %s.\n",
                      priv->containername, handle->block_id, curl_easy_strerror(rc));
        ret = -1;
    }

    curl_easy_reset (handle->curl);
    curl_slist_free_all (headers);
    g_string_free (url, TRUE);
    g_string_free (header_len, TRUE);
    g_string_free (header_etag, TRUE);
    g_string_free (header_X_Auth_Token, TRUE);
    g_free (object);
    ret = len;

    handle->swift_op =0;

    return ret;

}

int
block_backend_swift_write_block(BlockBackend *bend,
                                BHandle *handle,
                                const void *buf, int len)
{
    SwiftPriv *priv = bend->be_priv;

    return swift_write(priv, handle, buf, len);

}

int
block_backend_swift_commit_block (BlockBackend *bend, BHandle *handle)
{
    /* swift's both A one-time to  read and write ,
     * Maybe not need add 'commit' to Metadata 
     */

    return 0;
}

int
block_backend_swift_close_block (BlockBackend *bend, BHandle *handle)
{
    // printf("Function::block_backend_swift_close_block...\n");
    /* Nothing to do in swift */
    return 0;
}


/*
 * There is no a good method to check whether a block has existed or not.
 * So we call swift_stat().  
 */
gboolean
block_backend_swift_block_exists (BlockBackend *bend, const char *block_sha1)
{
    SwiftPriv *priv = bend->be_priv;
    int64_t size;
    time_t mtime;
    int err;

    err = swift_stat (priv, block_sha1, &size, &mtime);
    if (err < 0) {
        ccnet_warning ("[Block bend] block %s is not existed.\n", block_sha1);
        return FALSE;
    }
    return TRUE;
}


int
swift_remove(SwiftPriv *priv, const char *block_id)
{
    seaf_warning("Function::swift_remove,remove block_id is %s\n", block_id);
    ccnet_warning("Function::swift_remove,remove block_id is %s\n", block_id);
    /* When this function be called? I can't find it out now,maybe later ...*/
    // TODO:...

    return 0;

}

int
block_backend_swift_remove_block (BlockBackend *bend,
                                 const char *block_id)
{
    // printf("Function::block_backend_swift_remove_block ... \n");

    SwiftPriv *priv = bend->be_priv;
    int err;

    err = swift_remove (priv, block_id);
    if (err < 0) {
        ccnet_warning ("[block bend] Failed to remove block %s.\n", block_id);
        return -1;
    }

    return 0;
}

static size_t save_header(void *ptr, size_t size, size_t nmemb, void *data)
{
    return (size_t)(size * nmemb);
}

int 
swift_stat(SwiftPriv *priv, const char *block_id, uint64_t *psize, time_t *pmtime)
{
    
    if (get_storage_url_and_token(priv)<0){
        seaf_warning("get_storage_url_and_token in swift_stat Failed!\n\n");
        return -1;        
    }
    // Get object stats (size/mtime)
    CURL *curl = curl_easy_init(); 
    GString *url = g_string_new (NULL);
    GString *header_X_Auth_Token = g_string_new (NULL);
    int rc,ret_s,ret = 0;
    // gboolean ret;
    struct curl_slist *headers = NULL;

    g_string_append_printf (url, "%s/%s/%s",
                            priv->storage_url, priv->containername, block_id);
    curl_easy_setopt (curl, CURLOPT_URL, url->str);
    curl_easy_setopt (curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1L);

    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, save_header);
    

    g_string_append_printf(header_X_Auth_Token,"X-Auth-Token: %s",priv->auth_token);
    headers = curl_slist_append(headers, header_X_Auth_Token->str);

    curl_easy_setopt (curl, CURLOPT_HTTPHEADER, headers);

    // curl_easy_setopt (curl, CURLOPT_VERBOSE, 1L);


    /* Ask libcurl to send a HEAD request. */
    curl_easy_setopt (curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
  
    rc = curl_easy_perform (curl);
  
    if (rc != 0)
        ret = -1;
    else{
        const double filesize;
        curl_easy_getinfo(curl, CURLINFO_FILETIME, &pmtime);
        ret_s = curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &filesize);
        psize = (uint64_t)filesize;

        if (ret_s<0){
            seaf_warning("Can not get file size!\n");
        }
        else{
            seaf_warning("file size is ");
            seaf_warning("%lu bytes.\n", psize); 
        }
        
        seaf_warning("file time is ");
        seaf_warning("%s\n", ctime(&pmtime));

        ret = 0;
    }

    /* Clear options for future use. */
    curl_easy_cleanup (curl);
    g_string_free (url, TRUE);
    return ret;
}

BMetadata *
block_backend_swift_stat_block (BlockBackend *bend,
                               const char *block_id)
{
    SwiftPriv *priv = bend->be_priv;
    BMetadata *block_md;
    int err;
    uint64_t size;
    time_t mtime;

    err = swift_stat (priv, block_id, &size, &mtime);
    if (err < 0) {
        ccnet_warning ("[Block bend] Failed to stat block %s.\n", block_id);
        return NULL;
    }
    block_md = g_new0(BMetadata, 1);
    memcpy (block_md->id, block_id, 40);
    block_md->size = (uint32_t)size;

    return block_md;
}

BMetadata *
block_backend_swift_stat_block_by_handle (BlockBackend *bend,
                                         BHandle *handle)
{
    return block_backend_swift_stat_block(bend, handle->block_id);
}

void
block_backend_swift_block_handle_free (BlockBackend *bend, BHandle *handle)
{
    curl_easy_cleanup (handle->curl);
    evbuffer_free (handle->buffer);
    g_free (handle);
}

int
block_backend_swift_foreach_block (BlockBackend *bend,
                                  SeafBlockFunc process,
                                  void *user_data)
{
    return 0;
}


BlockBackend *
block_backend_swift_new (const char *auth_url, const char *containername)
{
    seaf_warning("Function::block_backend_swift_new ...\n");
    char *info = "auth_url is: %s\n";
    
    BlockBackend *bend;
    SwiftPriv *priv;


    bend = g_new0(BlockBackend, 1);
    priv = g_new0(SwiftPriv, 1);
    bend->be_priv = priv;

    if (swift_init(priv, auth_url, containername) < 0)
    {
        g_warning("[Block backend] Failed to init swift: containername name is %s.\n", containername);
        goto error;
    }
    seaf_warning("block_backend_swift_new, init finished!,\n\n");
    
    bend->open_block = block_backend_swift_open_block;
    bend->read_block = block_backend_swift_read_block;
    bend->write_block = block_backend_swift_write_block;
    bend->commit_block = block_backend_swift_commit_block;
    bend->close_block = block_backend_swift_close_block;
    bend->exists = block_backend_swift_block_exists;
    bend->remove_block = block_backend_swift_remove_block;
    bend->stat_block = block_backend_swift_stat_block;
    bend->stat_block_by_handle = block_backend_swift_stat_block_by_handle;
    bend->block_handle_free = block_backend_swift_block_handle_free;
    bend->foreach_block = block_backend_swift_foreach_block;

    return bend;

error:
    g_free(priv);
    g_free(bend);

    return NULL;

}
