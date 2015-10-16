#ifndef OBJ_STORE_H
#define OBJ_STORE_H

#include <glib.h>
#include <sys/types.h>

struct _SeafileSession;
struct SeafObjStore;
struct CEventManager;

struct SeafObjStore *
seaf_obj_store_new (struct _SeafileSession *seaf, const char *obj_type);

int
seaf_obj_store_init (struct SeafObjStore *obj_store,
                     gboolean enable_async,
                     struct CEventManager *ev_mgr);

/* Synchronous I/O interface. */

int
seaf_obj_store_read_obj (struct SeafObjStore *obj_store,
                         const char *repo_id,
                         int version,
                         const char *obj_id,
                         void **data,
                         int *len);

int
seaf_obj_store_write_obj (struct SeafObjStore *obj_store,
                          const char *repo_id,
                          int version,
                          const char *obj_id,
                          void *data,
                          int len,
                          gboolean need_sync);

gboolean
seaf_obj_store_obj_exists (struct SeafObjStore *obj_store,
                           const char *repo_id,
                           int version,
                           const char *obj_id);

void
seaf_obj_store_delete_obj (struct SeafObjStore *obj_store,
                           const char *repo_id,
                           int version,
                           const char *obj_id);

typedef gboolean (*SeafObjFunc) (const char *repo_id,
                                 int version,
                                 const char *obj_id,
                                 void *user_data);

int
seaf_obj_store_foreach_obj (struct SeafObjStore *obj_store,
                            const char *repo_id,
                            int version,
                            SeafObjFunc process,
                            void *user_data);

int
seaf_obj_store_copy_obj (struct SeafObjStore *obj_store,
                         const char *src_store_id,
                         int src_version,
                         const char *dst_store_id,
                         int dst_version,
                         const char *obj_id);

/* Asynchronous I/O interface. */

typedef struct OSAsyncResult {
    guint32 rw_id;
    char    obj_id[41];
    /* @data is owned by obj-store, don't free it. */
    void    *data;
    int     len;
    gboolean success;
} OSAsyncResult;

typedef void (*OSAsyncCallback) (OSAsyncResult *res, void *cb_data);

/* Async read */
guint32
seaf_obj_store_register_async_read (struct SeafObjStore *obj_store,
                                    const char *repo_id,
                                    int version,
                                    OSAsyncCallback callback,
                                    void *cb_data);

void
seaf_obj_store_unregister_async_read (struct SeafObjStore *obj_store,
                                      guint32 reader_id);

int
seaf_obj_store_async_read (struct SeafObjStore *obj_store,
                           guint32 reader_id,
                           const char *obj_id);

/* Async write */
guint32
seaf_obj_store_register_async_write (struct SeafObjStore *obj_store,
                                     const char *repo_id,
                                     int version,
                                     OSAsyncCallback callback,
                                     void *cb_data);

void
seaf_obj_store_unregister_async_write (struct SeafObjStore *obj_store,
                                       guint32 writer_id);

int
seaf_obj_store_async_write (struct SeafObjStore *obj_store,
                            guint32 writer_id,
                            const char *obj_id,
                            const void *obj_data,
                            int data_len,
                            gboolean need_sync);

/* Async stat */
guint32
seaf_obj_store_register_async_stat (struct SeafObjStore *obj_store,
                                    const char *repo_id,
                                    int version,
                                    OSAsyncCallback callback,
                                    void *cb_data);

void
seaf_obj_store_unregister_async_stat (struct SeafObjStore *obj_store,
                                      guint32 stat_id);

int
seaf_obj_store_async_stat (struct SeafObjStore *obj_store,
                           guint32 stat_id,
                           const char *obj_id);

int
seaf_obj_store_remove_store (struct SeafObjStore *obj_store,
                             const char *store_id);
#endif
