#include "common.h"
#include "obj-backend.h"

typedef struct FsPriv {
    char *obj_dir;
    int   dir_len;
} FsPriv;

static void
id_to_path (FsPriv *priv, const char *obj_id, char path[])
{
    char *pos = path;

    memcpy (pos, priv->obj_dir, priv->dir_len);
    pos[priv->dir_len] = '/';
    pos += priv->dir_len + 1;

    memcpy (pos, obj_id, 2);
    pos[2] = '/';
    pos += 3;

    memcpy (pos, obj_id + 2, 41 - 2);
}

static int
obj_backend_fs_read (ObjBackend *bend,
                     const char *obj_id,
                     void **data,
                     int *len)
{
    char path[SEAF_PATH_MAX];
    gsize tmp_len;
    GError *error = NULL;

    id_to_path (bend->priv, obj_id, path);

    g_file_get_contents (path, (gchar**)data, &tmp_len, &error);
    if (error) {
        g_clear_error (&error);
        return -1;
    }

    *len = (int)tmp_len;
    return 0;
}

static int
obj_backend_fs_write (ObjBackend *bend,
                      const char *obj_id,
                      void *data,
                      int len)
{
    char path[SEAF_PATH_MAX];
    struct stat st;
    GError *error = NULL;

    id_to_path (bend->priv, obj_id, path);

    /* Don't overwrite existing objects. */
    if (g_lstat (path, &st) == 0)
        return 0;

    g_file_set_contents (path, data, len, &error);
    if (error) {
        g_warning ("[obj backend] Failed to write object %s: %s.\n",
                   obj_id, error->message);
        g_clear_error (&error);
        return -1;
    }

    return 0;
}

static gboolean
obj_backend_fs_exists (ObjBackend *bend,
                       const char *obj_id)
{
    char path[SEAF_PATH_MAX];
    struct stat st;

    id_to_path (bend->priv, obj_id, path);

    if (g_lstat (path, &st) == 0)
        return TRUE;

    return FALSE;
}

static void
obj_backend_fs_delete (ObjBackend *bend,
                       const char *obj_id)
{
    char path[SEAF_PATH_MAX];

    id_to_path (bend->priv, obj_id, path);
    g_unlink (path);
}

static void
init_obj_dir (ObjBackend *bend)
{
    FsPriv *priv = bend->priv;
    int i;
    int len = priv->dir_len;
    char path[SEAF_PATH_MAX];
    char *pos;

    memcpy (path, priv->obj_dir, len);
    pos = path + len;

    /*
     * Create 256 sub-directories.
     */
    for (i = 0; i < 256; ++i) {
        snprintf (pos, sizeof(path) - len, "/%02x", i);
        if (g_access (path, F_OK) != 0)
            g_mkdir (path, 0777);
    }
}

ObjBackend *
obj_backend_fs_new (const char *obj_dir)
{
    ObjBackend *bend;
    FsPriv *priv;

    bend = g_new0(ObjBackend, 1);
    priv = g_new0(FsPriv, 1);
    bend->priv = priv;

    priv->obj_dir = g_strdup (obj_dir);
    priv->dir_len = strlen (obj_dir);

    if (g_mkdir_with_parents (obj_dir, 0777) < 0) {
        g_warning ("[Obj Backend] Objects dir %s does not exist and"
                   " is unable to create\n", obj_dir);
        goto onerror;
    }

    init_obj_dir (bend);

    bend->read = obj_backend_fs_read;
    bend->write = obj_backend_fs_write;
    bend->exists = obj_backend_fs_exists;
    bend->delete = obj_backend_fs_delete;

    return bend;

onerror:
    g_free (bend);
    g_free (bend->priv);

    return NULL;
}
