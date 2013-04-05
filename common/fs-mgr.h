/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_FILE_MGR_H
#define SEAF_FILE_MGR_H

#include <glib.h>
#include "bitfield.h"

#include "seafile-object.h"

#include "obj-store.h"

#include "cdc/cdc.h"
#include "../common/seafile-crypt.h"

typedef struct _SeafFSManager SeafFSManager;
typedef struct _Seafile Seafile;
typedef struct _SeafDir SeafDir;
typedef struct _SeafDirent SeafDirent;

struct _Seafile {
    char        file_id[41];
    guint64     file_size;
    guint32     n_blocks;
    char        **blk_sha1s;
    int         ref_count;
};

void
seafile_ref (Seafile *seafile);

void
seafile_unref (Seafile *seafile);

typedef enum {
    SEAF_METADATA_TYPE_INVALID,
    SEAF_METADATA_TYPE_FILE,
    SEAF_METADATA_TYPE_LINK,
    SEAF_METADATA_TYPE_DIR,
} SeafMetadataType;

#define SEAF_DIR_NAME_LEN 256


struct _SeafDirent {
    guint32    mode;
    char       id[41];
    guint32    name_len;
    char       name[SEAF_DIR_NAME_LEN];
};

struct _SeafDir {
    char   dir_id[41];
    GList *entries;
};

SeafDir *
seaf_dir_new (const char *id, GList *entries, gint64 ctime);

void 
seaf_dir_free (SeafDir *dir);

SeafDir *
seaf_dir_from_data (const char *dir_id, const uint8_t *data, int len);

int 
seaf_dir_save (SeafFSManager *fs_mgr, SeafDir *dir);

int
seaf_metadata_type_from_data (const uint8_t *data, int len);

SeafDirent *
seaf_dirent_new (const char *sha1, int mode, const char *name);

SeafDirent *
seaf_dirent_dup (SeafDirent *dent);

typedef struct {
    /* TODO: GHashTable may be inefficient when we have large number of IDs. */
    GHashTable  *block_hash;
    GPtrArray   *block_ids;
    Bitfield     block_map;
    uint32_t     n_blocks;
    uint32_t     n_valid_blocks;
} BlockList;

BlockList *
block_list_new ();

void
block_list_free (BlockList *bl);

void
block_list_generate_bitmap (BlockList *bl);

void
block_list_serialize (BlockList *bl, uint8_t **buffer, uint32_t *len);

void
block_list_insert (BlockList *bl, const char *block_id);

/* Return a blocklist containing block ids which are in @bl1 but
 * not in @bl2.
 */
BlockList *
block_list_difference (BlockList *bl1, BlockList *bl2);

struct _SeafileSession;

typedef struct _SeafFSManagerPriv SeafFSManagerPriv;

struct _SeafFSManager {
    struct _SeafileSession *seaf;

    struct SeafObjStore *obj_store;

    SeafFSManagerPriv *priv;
};

SeafFSManager *
seaf_fs_manager_new (struct _SeafileSession *seaf,
                     const char *seaf_dir);

int
seaf_fs_manager_init (SeafFSManager *mgr);

#ifndef SEAFILE_SERVER

char *
seaf_fs_manager_checkin (SeafFSManager *mgr,
                         const char *path);

int 
seaf_fs_manager_checkout (SeafFSManager *mgr,
                          const char *root_id,
                          const char *output_path);

int 
seaf_fs_manager_checkout_file (SeafFSManager *mgr, 
                               const char *file_id, 
                               const char *file_path,
                               guint32 mode,
                               struct SeafileCrypt *crypt,
                               const char *conflict_suffix,
                               gboolean *conflicted);

#endif  /* not SEAFILE_SERVER */

/**
 * Check in blocks and create seafile/symlink object.
 * Returns sha1 id for the seafile/symlink object in @sha1 parameter.
 */
int
seaf_fs_manager_index_blocks (SeafFSManager *mgr,
                              const char *file_path,
                              unsigned char sha1[],
                              SeafileCrypt *crypt);

uint32_t
seaf_fs_manager_get_type (SeafFSManager *mgr, const char *id);

Seafile *
seaf_fs_manager_get_seafile (SeafFSManager *mgr, const char *file_id);

SeafDir *
seaf_fs_manager_get_seafdir (SeafFSManager *mgr, const char *dir_id);

/* Make sure entries in the returned dir is sorted in descending order.
 */
SeafDir *
seaf_fs_manager_get_seafdir_sorted (SeafFSManager *mgr, const char *dir_id);

int
seaf_fs_manager_populate_blocklist (SeafFSManager *mgr,
                                    const char *root_id,
                                    BlockList *bl);

/*
 * For dir object, set *stop to TRUE to stop traversing the subtree.
 */
typedef gboolean (*TraverseFSTreeCallback) (SeafFSManager *mgr,
                                            const char *obj_id,
                                            int type,
                                            void *user_data,
                                            gboolean *stop);

int
seaf_fs_manager_traverse_tree (SeafFSManager *mgr,
                               const char *root_id,
                               TraverseFSTreeCallback callback,
                               void *user_data);

gboolean
seaf_fs_manager_object_exists (SeafFSManager *mgr, const char *id);

gint64
seaf_fs_manager_get_file_size (SeafFSManager *mgr, const char *file_id);

gint64
seaf_fs_manager_get_fs_size (SeafFSManager *mgr, const char *root_id);

#ifndef SEAFILE_SERVER
int
seafile_write_chunk (CDCDescriptor *chunk,
                     SeafileCrypt *crypt,
                     uint8_t *checksum,
                     gboolean write_data);
#endif /* SEAFILE_SERVER */

uint32_t
calculate_chunk_size (uint64_t total_size);

int
seaf_fs_manager_count_fs_files (SeafFSManager *mgr, const char *root_id);

SeafDir *
seaf_fs_manager_get_seafdir_by_path(SeafFSManager *mgr,
                                    const char *root_id,
                                    const char *path,
                                    GError **error);
char *
seaf_fs_manager_get_seafile_id_by_path (SeafFSManager *mgr,
                                        const char *root_id,
                                        const char *path,
                                        GError **error);

char *
seaf_fs_manager_path_to_obj_id (SeafFSManager *mgr,
                                 const char *root_id,
                                 const char *path,
                                 guint32 *mode,
                                 GError **error);

char *
seaf_fs_manager_get_seafdir_id_by_path (SeafFSManager *mgr,
                                        const char *root_id,
                                        const char *path,
                                        GError **error);

#endif
