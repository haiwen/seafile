#ifndef OBJ_BACKEND_H
#define OBJ_BACKEND_H

#include <glib.h>

typedef struct ObjBackend ObjBackend;

struct ObjBackend {
    int         (*read) (ObjBackend *bend,
                         const char *obj_id,
                         void **data,
                         int *len);

    int         (*write) (ObjBackend *bend,
                          const char *obj_id,
                          void *data,
                          int len,
                          gboolean need_sync);

    gboolean    (*exists) (ObjBackend *bend,
                           const char *obj_id);

    void        (*delete) (ObjBackend *bend,
                           const char *obj_id);

    void *priv;
};

#endif
