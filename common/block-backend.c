
#include "common.h"

#include "string.h"

#include "block-backend.h"

extern BlockBackend *
block_backend_fs_new (const char *block_dir, const char *tmp_dir);

#ifdef SEAFILE_SERVER
extern BlockBackend *
block_backend_ceph_new (const char *ceph_conf, const char *poolname);
#endif

extern BlockBackend *
block_backend_swift_new (const char *, const char *);

BlockBackend*
load_filesystem_block_backend(GKeyFile *config)
{
    BlockBackend *bend;
    char *tmp_dir;
    char *block_dir;
    
    block_dir = g_key_file_get_string (config, "block_backend", "block_dir", NULL);
    if (!block_dir) {
        g_warning ("Block dir not set in config.\n");
        return NULL;
    }

    tmp_dir = g_key_file_get_string (config, "block_backend", "tmp_dir", NULL);
    if (!tmp_dir) {
        g_warning ("Block tmp dir not set in config.\n");
        return NULL;
    }

    bend = block_backend_fs_new (block_dir, tmp_dir);

    g_free (block_dir);
    g_free (tmp_dir);
    return bend;
}

#ifdef SEAFILE_SERVER
BlockBackend*
load_ceph_block_backend(GKeyFile *config)
{
    BlockBackend *bend;
    char *ceph_conf;
    char *poolname;

    ceph_conf = g_key_file_get_string (config, "block_backend",  "ceph_config", NULL);
    if (!ceph_conf) {
        g_warning("Ceph config file not set in config.\n");
        return NULL;
    }

    poolname = g_key_file_get_string (config, "block_backend", "pool", NULL);
    if (!poolname) {
        g_warning("Ceph poolname not set in config.\n");
        return NULL;
    }

    bend = block_backend_ceph_new (ceph_conf, poolname);

    g_free (ceph_conf);
    g_free (poolname);

    return bend;
}
#endif


BlockBackend*
load_swift_block_backend(GKeyFile *config)
{
    BlockBackend *bend;
    char auth_url[2048];
    auth_url[0]='\0';
    char *scheme;
    char *host;
    char *port;
    char *api_version;
    char *auth_url_ext;
    char *containername;

    scheme = g_key_file_get_string (config, "block_backend",  "scheme", NULL);
    if (!scheme) {
        g_warning("Swift scheme not set in config.\n");
        return NULL;
    }
    else
    {
        
        strcat(auth_url,scheme);
        strcat(auth_url,"://");
    }

    host = g_key_file_get_string (config, "block_backend",  "host", NULL);
    if (!host) {
        g_warning("Swift Host not set in config.\n");
        return NULL;
    }
    else
    {
        strcat(auth_url,host);        
    }
    
    
    port = g_key_file_get_string (config, "block_backend",  "port", NULL);
    if (!port) {
        g_warning("Swift port not set in config.\n");
        return NULL;
    }
    else
    {
        strcat(auth_url,":");
        strcat(auth_url,port);
        strcat(auth_url,"/");
    }

    api_version = g_key_file_get_string (config, "block_backend",  "api_version", NULL);
    if (!api_version) {
        g_warning("Swift api_version  not set in config.\n");
        return NULL;
    }
    else
    {
        strcat(auth_url,api_version);        
    }

    auth_url_ext = g_key_file_get_string (config, "block_backend",  "auth_url_ext", NULL);
    if (!auth_url_ext) {
        g_warning("Swift auth_url_ext not set in config. Ignore...\n");       
    }
    else
    {
        strcat(auth_url,"/");
        strcat(auth_url,auth_url_ext);
    }   

    if (!auth_url) {
        g_warning("Swift Auth Url  not set in config.\n");
        return NULL;
    }

    containername = g_key_file_get_string (config, "block_backend", "container", NULL);
    if (!containername) {        
        g_warning("Swift container not set in config.\n");
        return NULL;
    } 

    bend = block_backend_swift_new (auth_url, containername);

    g_free (scheme);
    g_free (host);
    g_free (port);
    g_free (api_version);
    g_free (auth_url_ext);
    g_free (containername);

    return bend;
}

BlockBackend*
load_block_backend (GKeyFile *config)
{
    char *backend;
    BlockBackend *bend;

    backend = g_key_file_get_string (config, "block_backend", "name", NULL);
    if (!backend) {
        return NULL;
    }

    if (strcmp(backend, "filesystem") == 0) {
        bend = load_filesystem_block_backend(config);
        g_free (backend);
        return bend;
    }
#ifdef SEAFILE_SERVER
    else if (strcmp(backend, "ceph") == 0) {
        bend = load_ceph_block_backend(config);
        g_free(backend);
        return bend;
    }
#endif

    else if (strcmp(backend, "swift") == 0){
        bend = load_swift_block_backend(config);
        g_free(backend);
        return bend;
    }

    g_warning ("Unknown backend\n");
    return NULL;
}
