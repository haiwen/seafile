#include "common.h"
#include "symlink.h"

#include <fcntl.h>

int
seaf_symlink_stat (const char *path, SeafStat *st, gboolean preserve)
{
#ifndef WIN32
    if (preserve) {
        if (lstat (path, st) < 0)
            return -1;
        if (S_ISLNK(st->st_mode)) {
            st->st_mode = S_IFREG | 0644;
            st->st_size = SEAF_SYMLINK_HEADER_SIZE + SEAF_SYMLINK_ENCODED_SIZE(st->st_size);
        }
        return 0;
    }
#endif
    return seaf_stat (path, st);
}

int
seaf_symlink_index_path (const char *path, char **tmp_path)
{
    *tmp_path = NULL;
#ifndef WIN32
    struct stat st;
    if (lstat (path, &st) < 0)
        return -1;
    if (!S_ISLNK(st.st_mode))
        return 0;

    char target[SEAF_SYMLINK_TARGET_MAX + 1];
    ssize_t len = readlink (path, target, sizeof(target));
    if (len < 0)
        return -1;
    if (len == 0 || len > SEAF_SYMLINK_TARGET_MAX) {
        errno = ENAMETOOLONG;
        return -1;
    }

    int fd = g_file_open_tmp ("seafile-link-XXXXXX", tmp_path, NULL);
    if (fd < 0)
        return -1;
    char *encoded = g_base64_encode ((guchar *)target, len);
    gsize encoded_len = strlen(encoded);
    int ret = 1;
    if (writen (fd, SEAF_SYMLINK_MAGIC, SEAF_SYMLINK_HEADER_SIZE) != SEAF_SYMLINK_HEADER_SIZE ||
        writen (fd, encoded, encoded_len) != encoded_len)
        ret = -1;
    g_free (encoded);
    if (close (fd) < 0)
        ret = -1;
    if (ret < 0) {
        g_unlink (*tmp_path);
        g_clear_pointer (tmp_path, g_free);
    }
    return ret;
#else
    return 0;
#endif
}

int
seaf_symlink_materialize (const char *path)
{
#ifndef WIN32
    struct stat st;
    if (lstat (path, &st) < 0)
        return -1;
    if (!S_ISREG(st.st_mode) || st.st_size <= SEAF_SYMLINK_HEADER_SIZE ||
        st.st_size > SEAF_SYMLINK_HEADER_SIZE + SEAF_SYMLINK_ENCODED_SIZE(SEAF_SYMLINK_TARGET_MAX))
        return 0;

    int fd = open (path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    char record[SEAF_SYMLINK_HEADER_SIZE + SEAF_SYMLINK_ENCODED_SIZE(SEAF_SYMLINK_TARGET_MAX) + 1];
    ssize_t len = readn (fd, record, sizeof(record));
    close (fd);
    if (len < 0)
        return -1;
    if (len <= SEAF_SYMLINK_HEADER_SIZE || len >= sizeof(record) ||
        memcmp (record, SEAF_SYMLINK_MAGIC, SEAF_SYMLINK_HEADER_SIZE) != 0 ||
        memchr (record + SEAF_SYMLINK_HEADER_SIZE, 0, len - SEAF_SYMLINK_HEADER_SIZE))
        return 0;
    record[len] = 0;

    gsize target_len;
    guchar *target = g_base64_decode (record + SEAF_SYMLINK_HEADER_SIZE, &target_len);
    char *canonical = g_base64_encode (target, target_len);
    gboolean valid = target_len > 0 && target_len <= SEAF_SYMLINK_TARGET_MAX &&
        memchr (target, 0, target_len) == NULL &&
        strcmp (canonical, record + SEAF_SYMLINK_HEADER_SIZE) == 0;
    g_free (canonical);
    if (!valid) {
        g_free (target);
        return 0;
    }
    char *target_path = g_strndup ((char *)target, target_len);
    g_free (target);

    /* Create beside the download, then rename atomically. A private directory
     * avoids both predictable temporary symlink names and following targets. */
    char *parent = g_path_get_dirname (path);
    /* ._* is already ignored by all supported clients. Use a short
     * sibling name so a long destination basename doesn't exceed NAME_MAX. */
    char *dir = g_build_filename (parent, "._seafile-link-XXXXXX", NULL);
    g_free (parent);
    if (!g_mkdtemp (dir)) {
        g_free (dir);
        g_free (target_path);
        return -1;
    }
    char *link = g_build_filename (dir, "link", NULL);
    int ret = symlink (target_path, link);
    if (ret == 0)
        ret = g_rename (link, path);
    int saved_errno = errno;
    g_unlink (link);
    g_rmdir (dir);
    g_free (link);
    g_free (dir);
    g_free (target_path);
    errno = saved_errno;
    return ret == 0 ? 1 : -1;
#else
    return 0;
#endif
}

gboolean
seaf_symlink_exists (const char *path)
{
#ifndef WIN32
    struct stat st;
    return lstat (path, &st) == 0;
#else
    return seaf_util_exists (path);
#endif
}

int
seaf_symlink_set_time (const char *path, guint64 mtime)
{
#ifndef WIN32
    struct timespec times[2] = {{mtime, 0}, {mtime, 0}};
    return utimensat (AT_FDCWD, path, times, AT_SYMLINK_NOFOLLOW);
#else
    return seaf_set_file_time (path, mtime);
#endif
}
