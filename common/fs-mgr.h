/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAF_FILE_MGR_H
#define SEAF_FILE_MGR_H

#include <glib.h>

#include "seafile-object.h"

#include "obj-store.h"

#include "cdc/cdc.h"
#include "../common/seafile-crypt.h"

#define CURRENT_DIR_OBJ_VERSION 1
#define CURRENT_SEAFILE_OBJ_VERSION 1

#define CDC_AVERAGE_BLOCK_SIZE (1 << 23) /* 8MB */
#define CDC_MIN_BLOCK_SIZE (6 * (1 << 20)) /* 6MB */
#define CDC_MAX_BLOCK_SIZE (10 * (1 << 20)) /* 10MB */

typedef struct _SeafFSManager SeafFSManager;
typedef struct _SeafFSObject SeafFSObject;
typedef struct _Seafile Seafile;
typedef struct _SeafDir SeafDir;
typedef struct _SeafDirent SeafDirent;

typedef enum {
    SEAF_METADATA_TYPE_INVALID,
    SEAF_METADATA_TYPE_FILE,
    SEAF_METADATA_TYPE_LINK,
    SEAF_METADATA_TYPE_DIR,
} SeafMetadataType;

/* Common to seafile and seafdir objects. */
struct _SeafFSObject {
    int type;
};

struct _Seafile {
    SeafFSObject object;
    int         version;
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

int
seafile_save (SeafFSManager *fs_mgr,
              const char *repo_id,
              int version,
              Seafile *file);

#define SEAF_DIR_NAME_LEN 256

struct _SeafDirent {
    int        version;
    guint32    mode;
    char       id[41];
    guint32    name_len;
    char       *name;

    /* attributes for version > 0 */
    gint64     mtime;
    char       *modifier;       /* for files only */
    gint64     size;            /* for files only */
};

struct _SeafDir {
    SeafFSObject object;
    int    version;
    char   dir_id[41];
    GList *entries;

    /* data in on-disk format. */
    void  *ondisk;
    int    ondisk_size;
};

SeafDir *
seaf_dir_new (const char *id, GList *entries, int version);

void 
seaf_dir_free (SeafDir *dir);

SeafDir *
seaf_dir_from_data (const char *dir_id, uint8_t *data, int len,
                    gboolean is_json);

void *
seaf_dir_to_data (SeafDir *dir, int *len);

int 
seaf_dir_save (SeafFSManager *fs_mgr,
               const char *repo_id,
               int version,
               SeafDir *dir);

SeafDirent *
seaf_dirent_new (int version, const char *sha1, int mode, const char *name,
                 gint64 mtime, const char *modifier, gint64 size);

void
seaf_dirent_free (SeafDirent *dent);

SeafDirent *
seaf_dirent_dup (SeafDirent *dent);

int
seaf_metadata_type_from_data (const char *obj_id,
                              uint8_t *data, int len, gboolean is_json);

/* Parse an fs object without knowing its type. */
SeafFSObject *
seaf_fs_object_from_data (const char *obj_id,
                          uint8_t *data, int len,
                          gboolean is_json);

void
seaf_fs_object_free (SeafFSObject *obj);

typedef struct {
    /* TODO: GHashTable may be inefficient when we have large number of IDs. */
    GHashTable  *block_hash;
    GPtrArray   *block_ids;
    uint32_t     n_blocks;
    uint32_t     n_valid_blocks;
} BlockList;

BlockList *
block_list_new ();

void
block_list_free (BlockList *bl);

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

int 
seaf_fs_manager_checkout_file (SeafFSManager *mgr, 
                               const char *repo_id,
                               int version,
                               const char *file_id, 
                               const char *file_path,
                               guint32 mode,
                               guint64 mtime,
                               struct SeafileCrypt *crypt,
                               const char *in_repo_path,
                               const char *conflict_head_id,
                               gboolean force_conflict,
                               gboolean *conflicted,
                               const char *email);

#endif  /* not SEAFILE_SERVER */

/**
 * Check in blocks and create seafile/symlink object.
 * Returns sha1 id for the seafile/symlink object in @sha1 parameter.
 */
int
seaf_fs_manager_index_file_blocks (SeafFSManager *mgr,
                                   const char *repo_id,
                                   int version,
                                   GList *paths,
                                   GList *blockids,
                                   unsigned char sha1[],
                                   gint64 file_size);

int
seaf_fs_manager_index_raw_blocks (SeafFSManager *mgr,
                                  const char *repo_id,
                                  int version,
                                  GList *paths,
                                  GList *blockids);

int
seaf_fs_manager_index_existed_file_blocks (SeafFSManager *mgr,
                                           const char *repo_id,
                                           int version,
                                           GList *blockids,
                                           unsigned char sha1[],
                                           gint64 file_size);
int
seaf_fs_manager_index_blocks (SeafFSManager *mgr,
                              const char *repo_id,
                              int version,
                              const char *file_path,
                              unsigned char sha1[],
                              gint64 *size,
                              SeafileCrypt *crypt,
                              gboolean write_data,
                              gboolean use_cdc);

Seafile *
seaf_fs_manager_get_seafile (SeafFSManager *mgr,
                             const char *repo_id,
                             int version,
                             const char *file_id);

SeafDir *
seaf_fs_manager_get_seafdir (SeafFSManager *mgr,
                             const char *repo_id,
                             int version,
                             const char *dir_id);

/* Make sure entries in the returned dir is sorted in descending order.
 */
SeafDir *
seaf_fs_manager_get_seafdir_sorted (SeafFSManager *mgr,
                                    const char *repo_id,
                                    int version,
                                    const char *dir_id);

SeafDir *
seaf_fs_manager_get_seafdir_sorted_by_path (SeafFSManager *mgr,
                                            const char *repo_id,
                                            int version,
                                            const char *root_id,
                                            const char *path);

int
seaf_fs_manager_populate_blocklist (SeafFSManager *mgr,
                                    const char *repo_id,
                                    int version,
                                    const char *root_id,
                                    BlockList *bl);

/*
 * For dir object, set *stop to TRUE to stop traversing the subtree.
 */
typedef gboolean (*TraverseFSTreeCallback) (SeafFSManager *mgr,
                                            const char *repo_id,
                                            int version,
                                            const char *obj_id,
                                            int type,
                                            void *user_data,
                                            gboolean *stop);

int
seaf_fs_manager_traverse_tree (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *root_id,
                               TraverseFSTreeCallback callback,
                               void *user_data,
                               gboolean skip_errors);

typedef gboolean (*TraverseFSPathCallback) (SeafFSManager *mgr,
                                            const char *path,
                                            SeafDirent *dent,
                                            void *user_data,
                                            gboolean *stop);

int
seaf_fs_manager_traverse_path (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *root_id,
                               const char *dir_path,
                               TraverseFSPathCallback callback,
                               void *user_data);

gboolean
seaf_fs_manager_object_exists (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *id);

void
seaf_fs_manager_delete_object (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *id);

gint64
seaf_fs_manager_get_file_size (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *file_id);

gint64
seaf_fs_manager_get_fs_size (SeafFSManager *mgr,
                             const char *repo_id,
                             int version,
                             const char *root_id);

#ifndef SEAFILE_SERVER
int
seafile_write_chunk (const char *repo_id,
                     int version,
                     CDCDescriptor *chunk,
                     SeafileCrypt *crypt,
                     uint8_t *checksum,
                     gboolean write_data);
int
seafile_check_write_chunk (CDCDescriptor *chunk,
                           uint8_t *sha1,
                           gboolean write_data);
#endif /* SEAFILE_SERVER */

uint32_t
calculate_chunk_size (uint64_t total_size);

int
seaf_fs_manager_count_fs_files (SeafFSManager *mgr,
                                const char *repo_id,
                                int version,
                                const char *root_id);

SeafDir *
seaf_fs_manager_get_seafdir_by_path(SeafFSManager *mgr,
                                    const char *repo_id,
                                    int version,
                                    const char *root_id,
                                    const char *path,
                                    GError **error);
char *
seaf_fs_manager_get_seafile_id_by_path (SeafFSManager *mgr,
                                        const char *repo_id,
                                        int version,
                                        const char *root_id,
                                        const char *path,
                                        GError **error);

char *
seaf_fs_manager_path_to_obj_id (SeafFSManager *mgr,
                                const char *repo_id,
                                int version,
                                const char *root_id,
                                const char *path,
                                guint32 *mode,
                                GError **error);

char *
seaf_fs_manager_get_seafdir_id_by_path (SeafFSManager *mgr,
                                        const char *repo_id,
                                        int version,
                                        const char *root_id,
                                        const char *path,
                                        GError **error);

SeafDirent *
seaf_fs_manager_get_dirent_by_path (SeafFSManager *mgr,
                                    const char *repo_id,
                                    int version,
                                    const char *root_id,
                                    const char *path,
                                    GError **error);

/* Check object integrity. */

gboolean
seaf_fs_manager_verify_seafdir (SeafFSManager *mgr,
                                const char *repo_id,
                                int version,
                                const char *dir_id,
                                gboolean verify_id,
                                gboolean *io_error);

gboolean
seaf_fs_manager_verify_seafile (SeafFSManager *mgr,
                                const char *repo_id,
                                int version,
                                const char *file_id,
                                gboolean verify_id,
                                gboolean *io_error);

gboolean
seaf_fs_manager_verify_object (SeafFSManager *mgr,
                               const char *repo_id,
                               int version,
                               const char *obj_id,
                               gboolean verify_id,
                               gboolean *io_error);

int
dir_version_from_repo_version (int repo_version);

int
seafile_version_from_repo_version (int repo_version);

struct _CDCFileDescriptor;
void
seaf_fs_manager_calculate_seafile_id_json (int repo_version,
                                           struct _CDCFileDescriptor *cdc,
                                           guint8 *file_id_sha1);

int
seaf_fs_manager_remove_store (SeafFSManager *mgr,
                              const char *store_id);

#endif
