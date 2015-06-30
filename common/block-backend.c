
#include "common.h"

#include "log.h"

#include "block-backend.h"

extern BlockBackend *
block_backend_fs_new (const char *block_dir, const char *tmp_dir);

BlockBackend*
load_filesystem_block_backend(GKeyFile *config)
{
    BlockBackend *bend;
    char *tmp_dir;
    char *block_dir;
    
    block_dir = g_key_file_get_string (config, "block_backend", "block_dir", NULL);
    if (!block_dir) {
        seaf_warning ("Block dir not set in config.\n");
        return NULL;
    }

    tmp_dir = g_key_file_get_string (config, "block_backend", "tmp_dir", NULL);
    if (!tmp_dir) {
        seaf_warning ("Block tmp dir not set in config.\n");
        return NULL;
    }

    bend = block_backend_fs_new (block_dir, tmp_dir);

    g_free (block_dir);
    g_free (tmp_dir);
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

    seaf_warning ("Unknown backend\n");
    return NULL;
}
