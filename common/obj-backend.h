#ifndef OBJ_BACKEND_H
#define OBJ_BACKEND_H

#include <glib.h>
#include "obj-store.h"

typedef struct ObjBackend ObjBackend;

struct ObjBackend {
    int         (*read) (ObjBackend *bend,
                         const char *repo_id,
                         int version,
                         const char *obj_id,
                         void **data,
                         int *len);

    int         (*write) (ObjBackend *bend,
                          const char *repo_id,
                          int version,
                          const char *obj_id,
                          void *data,
                          int len,
                          gboolean need_sync);

    gboolean    (*exists) (ObjBackend *bend,
                           const char *repo_id,
                           int version,
                           const char *obj_id);

    void        (*delete) (ObjBackend *bend,
                           const char *repo_id,
                           int version,
                           const char *obj_id);

    int         (*foreach_obj) (ObjBackend *bend,
                                const char *repo_id,
                                int version,
                                SeafObjFunc process,
                                void *user_data);

    int         (*copy) (ObjBackend *bend,
                         const char *src_repo_id,
                         int src_version,
                         const char *dst_repo_id,
                         int dst_version,
                         const char *obj_id);

    int        (*remove_store) (ObjBackend *bend,
                                const char *store_id);

    void *priv;
};

#endif
