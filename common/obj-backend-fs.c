#include "common.h"
#include "utils.h"
#include "obj-backend.h"

#ifndef WIN32
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#endif

#ifdef WIN32
#include <windows.h>
#include <io.h>
#endif

#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"

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
        seaf_debug ("[obj backend] Failed to read object %s: %s.\n",
                    obj_id, error->message);
        g_clear_error (&error);
        return -1;
    }

    *len = (int)tmp_len;
    return 0;
}

/*
 * Flush operating system and disk caches for @fd.
 */
static int
fsync_obj_contents (int fd)
{
#ifdef __linux__
    if (fsync (fd) < 0) {
        seaf_warning ("Failed to fsync: %s.\n", strerror(errno));
        return -1;
    }
    return 0;
#endif

#ifdef __APPLE__
    /* OS X: fcntl() is required to flush disk cache, fsync() only
     * flushes operating system cache.
     */
    if (fcntl (fd, F_FULLFSYNC, NULL) < 0) {
        seaf_warning ("Failed to fsync: %s.\n", strerror(errno));
        return -1;
    }
    return 0;
#endif

#ifdef WIN32
    HANDLE handle;

    handle = (HANDLE)_get_osfhandle (fd);
    if (handle == INVALID_HANDLE_VALUE) {
        seaf_warning ("Failed to get handle from fd.\n");
        return -1;
    }

    if (!FlushFileBuffers (handle)) {
        seaf_warning ("FlushFileBuffer() failed: %lu.\n", GetLastError());
        return -1;
    }

    return 0;
#endif
}

/*
 * Rename file from @tmp_path to @obj_path.
 * This also makes sure the changes to @obj_path's parent folder
 * is flushed to disk.
 */
static int
rename_and_sync (const char *tmp_path, const char *obj_path)
{
#ifdef __linux__
    char *parent_dir;
    int ret = 0;

    if (rename (tmp_path, obj_path) < 0) {
        seaf_warning ("Failed to rename from %s to %s: %s.\n",
                      tmp_path, obj_path, strerror(errno));
        return -1;
    }

    parent_dir = g_path_get_dirname (obj_path);
    int dir_fd = open (parent_dir, O_RDONLY);
    if (dir_fd < 0) {
        seaf_warning ("Failed to open dir %s: %s.\n", parent_dir, strerror(errno));
        ret = -1;
        goto out;
    }

    if (fsync (dir_fd) < 0) {
        seaf_warning ("Failed to fsync dir %s: %s.\n", parent_dir, strerror(errno));
        ret = -1;
        goto out;
    }

out:
    g_free (parent_dir);
    close (dir_fd);
    return ret;
#endif

#ifdef __APPLE__
    /*
     * OS X garantees an existence of obj_path always exists,
     * even when the system crashes.
     */
    if (rename (tmp_path, obj_path) < 0) {
        seaf_warning ("Failed to rename from %s to %s: %s.\n",
                      tmp_path, obj_path, strerror(errno));
        return -1;
    }
    return 0;
#endif

#ifdef WIN32
    wchar_t *w_tmp_path = g_utf8_to_utf16 (tmp_path, -1, NULL, NULL, NULL);
    wchar_t *w_obj_path = g_utf8_to_utf16 (obj_path, -1, NULL, NULL, NULL);
    int ret = 0;

    if (!MoveFileExW (w_tmp_path, w_obj_path,
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        seaf_warning ("MoveFilExW failed: %lu.\n", GetLastError());
        ret = -1;
        goto out;
    }

out:
    g_free (w_tmp_path);
    g_free (w_obj_path);
    return ret;
#endif
}

static int
save_obj_contents (const char *path, const void *data, int len)
{
    char tmp_path[SEAF_PATH_MAX];
    int fd;

    snprintf (tmp_path, SEAF_PATH_MAX, "%s.XXXXXX", path);
    fd = g_mkstemp (tmp_path);
    if (fd < 0) {
        seaf_warning ("[obj backend] Failed to open tmp file %s: %s.\n",
                      tmp_path, strerror(errno));
        return -1;
    }

    if (writen (fd, data, len) < 0) {
        seaf_warning ("[obj backend] Failed to write obj %s: %s.\n",
                      tmp_path, strerror(errno));
        return -1;
    }

    if (fsync_obj_contents (fd) < 0)
        return -1;

    close (fd);

    if (rename_and_sync (tmp_path, path) < 0)
        return -1;

    return 0;
}

static int
obj_backend_fs_write (ObjBackend *bend,
                      const char *obj_id,
                      void *data,
                      int len,
                      gboolean need_sync)
{
    char path[SEAF_PATH_MAX];

    id_to_path (bend->priv, obj_id, path);

    /* GTimeVal s, e; */

    /* g_get_current_time (&s); */

    if (need_sync) {
        /* seaf_message ("need sync.\n"); */
        if (save_obj_contents (path, data, len) < 0) {
            seaf_warning ("[obj backend] Failed to write obj %s.\n", obj_id);
            return -1;
        }
    } else {
        GError *error = NULL;
        if (!g_file_set_contents (path, data, len, &error) < 0) {
            seaf_warning ("[obj backend] Failed to write obj %s: %s.\n",
                          obj_id, error->message);
            g_clear_error (&error);
            return -1;
        }
    }

    /* g_get_current_time (&e); */

    /* seaf_message ("write obj time: %ldms.\n", */
    /*               ((e.tv_sec*1000000+e.tv_usec) - (s.tv_sec*1000000+s.tv_usec))/1000); */

    return 0;
}

static gboolean
obj_backend_fs_exists (ObjBackend *bend,
                       const char *obj_id)
{
    char path[SEAF_PATH_MAX];
    SeafStat st;

    id_to_path (bend->priv, obj_id, path);

    if (seaf_stat (path, &st) == 0)
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

static int
obj_backend_fs_foreach_obj (ObjBackend *bend,
                            SeafObjFunc process,
                            void *user_data)
{
    FsPriv *priv = bend->priv;
    char *obj_dir = priv->obj_dir;
    int dir_len = priv->dir_len;
    GDir *dir1, *dir2;
    const char *dname1, *dname2;
    char obj_id[128];
    char path[SEAF_PATH_MAX], *pos;
    int ret = 0;

    dir1 = g_dir_open (obj_dir, 0, NULL);
    if (!dir1) {
        g_warning ("Failed to open object dir %s.\n", obj_dir);
        return -1;
    }

    memcpy (path, obj_dir, dir_len);
    pos = path + dir_len;

    while ((dname1 = g_dir_read_name(dir1)) != NULL) {
        snprintf (pos, sizeof(path) - dir_len, "/%s", dname1);

        dir2 = g_dir_open (path, 0, NULL);
        if (!dir2) {
            g_warning ("Failed to open object dir %s.\n", path);
            continue;
        }

        while ((dname2 = g_dir_read_name(dir2)) != NULL) {
            snprintf (obj_id, sizeof(obj_id), "%s%s", dname1, dname2);
            if (!process (obj_id, user_data)) {
                g_dir_close (dir2);
                goto out;
            }
        }
        g_dir_close (dir2);
    }

out:
    g_dir_close (dir1);

    return ret;
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
    bend->foreach_obj = obj_backend_fs_foreach_obj;

    return bend;

onerror:
    g_free (bend);
    g_free (bend->priv);

    return NULL;
}
