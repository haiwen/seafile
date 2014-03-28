/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_BLOCK_MGR_H
#define SEAF_BLOCK_MGR_H

#include <glib.h>
#include <glib-object.h>
#include <stdint.h>

#include "block.h"

struct _SeafileSession;

typedef struct _SeafBlockManager SeafBlockManager;

struct _SeafBlockManager {
    struct _SeafileSession *seaf;

    struct BlockBackend *backend;
};


SeafBlockManager *
seaf_block_manager_new (struct _SeafileSession *seaf,
                        const char *seaf_dir);

/*
 * Open a block for read or write.
 *
 * @store_id: id for the block store
 * @version: data format version for the repo
 * @block_id: ID of block.
 * @rw_type: BLOCK_READ or BLOCK_WRITE.
 * Returns: A handle for the block.
 */
BlockHandle *
seaf_block_manager_open_block (SeafBlockManager *mgr,
                               const char *store_id,
                               int version,
                               const char *block_id,
                               int rw_type);

/*
 * Read data from a block.
 * The semantics is similar to readn.
 *
 * @handle: Hanlde returned by seaf_block_manager_open_block().
 * @buf: Data wuold be copied into this buf.
 * @len: At most @len bytes would be read.
 *
 * Returns: the bytes read.
 */
int
seaf_block_manager_read_block (SeafBlockManager *mgr,
                               BlockHandle *handle,
                               void *buf, int len);

/*
 * Write data to a block.
 * The semantics is similar to writen.
 *
 * @handle: Hanlde returned by seaf_block_manager_open_block().
 * @buf: Data to be written to the block.
 * @len: At most @len bytes would be written.
 *
 * Returns: the bytes written.
 */
int
seaf_block_manager_write_block (SeafBlockManager *mgr,
                                BlockHandle *handle,
                                const void *buf, int len);

/*
 * Commit a block to storage.
 * The block must be opened for write.
 *
 * @handle: Hanlde returned by seaf_block_manager_open_block().
 *
 * Returns: 0 on success, -1 on error.
 */
int
seaf_block_manager_commit_block (SeafBlockManager *mgr,
                                 BlockHandle *handle);

/*
 * Close an open block.
 *
 * @handle: Hanlde returned by seaf_block_manager_open_block().
 *
 * Returns: 0 on success, -1 on error.
 */
int
seaf_block_manager_close_block (SeafBlockManager *mgr,
                                BlockHandle *handle);

void
seaf_block_manager_block_handle_free (SeafBlockManager *mgr,
                                      BlockHandle *handle);

gboolean 
seaf_block_manager_block_exists (SeafBlockManager *mgr,
                                 const char *store_id,
                                 int version,
                                 const char *block_id);

int
seaf_block_manager_remove_block (SeafBlockManager *mgr,
                                 const char *store_id,
                                 int version,
                                 const char *block_id);

BlockMetadata *
seaf_block_manager_stat_block (SeafBlockManager *mgr,
                               const char *store_id,
                               int version,
                               const char *block_id);

BlockMetadata *
seaf_block_manager_stat_block_by_handle (SeafBlockManager *mgr,
                                         BlockHandle *handle);

int
seaf_block_manager_foreach_block (SeafBlockManager *mgr,
                                  const char *store_id,
                                  int version,
                                  SeafBlockFunc process,
                                  void *user_data);

int
seaf_block_manager_copy_block (SeafBlockManager *mgr,
                               const char *src_store_id,
                               int src_version,
                               const char *dst_store_id,
                               int dst_version,
                               const char *block_id);

/* Remove all blocks for a repo. Only valid for version 1 repo. */
int
seaf_block_manager_remove_store (SeafBlockManager *mgr,
                                 const char *store_id);

guint64
seaf_block_manager_get_block_number (SeafBlockManager *mgr,
                                     const char *store_id,
                                     int version);

gboolean
seaf_block_manager_verify_block (SeafBlockManager *mgr,
                                 const char *store_id,
                                 int version,
                                 const char *block_id,
                                 gboolean *io_error);

#endif
