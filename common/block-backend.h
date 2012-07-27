/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef BLOCK_BACKEND_H
#define BLOCK_BACKEND_H

#include "block.h"

typedef struct BlockBackend BlockBackend;

struct BlockBackend {
    
    BHandle* (*open_block) (BlockBackend *bend, const char *block_id, int rw_type);

    int      (*read_block) (BlockBackend *bend, BHandle *handle, void *buf, int len);
    
    int      (*write_block) (BlockBackend *bend, BHandle *handle, const void *buf, int len);
    
    int      (*commit_block) (BlockBackend *bend, BHandle *handle);

    int      (*close_block) (BlockBackend *bend, BHandle *handle);

    int      (*exists) (BlockBackend *bend, const char *block_id);

    int      (*remove_block) (BlockBackend *bend, const char *block_id);

    BMetadata* (*stat_block) (BlockBackend *bend, const char *block_id);
    
    BMetadata* (*stat_block_by_handle) (BlockBackend *bend, BHandle *handle);

    void     (*block_handle_free) (BlockBackend *bend, BHandle *handle);

    int      (*foreach_block) (BlockBackend *bend, SeafBlockFunc process, void *user_data);

    void*    be_priv;           /* backend private field */

};


BlockBackend* load_block_backend (GKeyFile *config);

#endif
