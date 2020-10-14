/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#ifdef WIN32
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x500
#endif
#endif

#include "utils.h"

#ifdef WIN32

#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <Rpc.h>
#include <shlobj.h>
#include <psapi.h>
#include <openssl/applink.c>

#else
#include <arpa/inet.h>
#endif

#ifndef WIN32
#include <config.h>
#include <pwd.h>
#include <uuid/uuid.h>
#endif

#ifndef WIN32
#include <unistd.h>
#include <dirent.h>
#endif
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <string.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <searpc-utils.h>

#include <jansson.h>

#ifndef WIN32
#include <utime.h>
#endif

#include <zlib.h>

#include "log.h"



void
rawdata_to_hex (const unsigned char *rawdata, char *hex_str, int n_bytes)
{
    static const char hex[] = "0123456789abcdef";
    int i;

    for (i = 0; i < n_bytes; i++) {
        unsigned int val = *rawdata++;
        *hex_str++ = hex[val >> 4];
        *hex_str++ = hex[val & 0xf];
    }
    *hex_str = '\0';
}

static unsigned hexval(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return ~0;
}

int
hex_to_rawdata (const char *hex_str, unsigned char *rawdata, int n_bytes)
{
    int i;
    for (i = 0; i < n_bytes; i++) {
        unsigned int val = (hexval(hex_str[0]) << 4) | hexval(hex_str[1]);
        if (val & ~0xff)
            return -1;
        *rawdata++ = val;
        hex_str += 2;
    }
    return 0;
}

size_t
ccnet_strlcpy (char *dest, const char *src, size_t size)
{
    size_t ret = strlen(src);

    if (size) {
        size_t len = (ret >= size) ? size - 1 : ret;
        memcpy(dest, src, len);
        dest[len] = '\0';
    }
    return ret;
}


int
checkdir (const char *dir)
{
    SeafStat st;

#ifdef WIN32
    /* remove trailing '\\' */
    char *path = g_strdup(dir);
    char *p = (char *)path + strlen(path) - 1;
    while (*p == '\\' || *p == '/') *p-- = '\0';
    if ((seaf_stat(dir, &st) < 0) || !S_ISDIR(st.st_mode)) {
        g_free (path);
        return -1;
    }
    g_free (path);
    return 0;
#else
    if ((seaf_stat(dir, &st) < 0) || !S_ISDIR(st.st_mode))
        return -1;
    return 0;
#endif
}

int
checkdir_with_mkdir (const char *dir)
{
#ifdef WIN32
    int ret;
    char *path = g_strdup(dir);
    char *p = (char *)path + strlen(path) - 1;
    while (*p == '\\' || *p == '/') *p-- = '\0';
    ret = g_mkdir_with_parents(path, 0755);
    g_free (path);
    return ret;
#else
    return g_mkdir_with_parents(dir, 0755);
#endif
}

int
objstore_mkdir (const char *base)
{
    int ret;
    int i, j, len;
    static const char hex[] = "0123456789abcdef";
    char subdir[SEAF_PATH_MAX];

    if ( (ret = checkdir_with_mkdir(base)) < 0)
        return ret;

    len = strlen(base);
    memcpy(subdir, base, len);
    subdir[len] = G_DIR_SEPARATOR;
    subdir[len+3] = '\0';

    for (i = 0; i < 16; i++) {
        subdir[len+1] = hex[i];
        for (j = 0; j < 16; j++) {
            subdir[len+2] = hex[j];
            if ( (ret = checkdir_with_mkdir(subdir)) < 0)
                return ret;
        }
    }
    return 0;
}

void
objstore_get_path (char *path, const char *base, const char *obj_id)
{
    int len;

    len = strlen(base);
    memcpy(path, base, len);
    path[len] = G_DIR_SEPARATOR;
    path[len+1] = obj_id[0];
    path[len+2] = obj_id[1];
    path[len+3] = G_DIR_SEPARATOR;
    strcpy(path+len+4, obj_id+2);
}

#ifdef WIN32

/* UNIX epoch expressed in Windows time, the unit is 100 nanoseconds.
 * See http://msdn.microsoft.com/en-us/library/ms724228
 */
#define UNIX_EPOCH 116444736000000000ULL

__time64_t
file_time_to_unix_time (FILETIME *ftime)
{
    guint64 win_time, unix_time;

    win_time = (guint64)ftime->dwLowDateTime + (((guint64)ftime->dwHighDateTime)<<32);
    unix_time = (win_time - UNIX_EPOCH)/10000000;

    return (__time64_t)unix_time;
}

static int
get_utc_file_time_fd (int fd, __time64_t *mtime, __time64_t *ctime)
{
    HANDLE handle;
    FILETIME write_time, create_time;

    handle = (HANDLE)_get_osfhandle (fd);
    if (handle == INVALID_HANDLE_VALUE) {
        g_warning ("Failed to get handle from fd: %lu.\n", GetLastError());
        return -1;
    }

    if (!GetFileTime (handle, &create_time, NULL, &write_time)) {
        g_warning ("Failed to get file time: %lu.\n", GetLastError());
        return -1;
    }

    *mtime = file_time_to_unix_time (&write_time);
    *ctime = file_time_to_unix_time (&create_time);

    return 0;
}

#define EPOCH_DIFF 11644473600ULL

inline static void
unix_time_to_file_time (guint64 unix_time, FILETIME *ftime)
{
    guint64 win_time;

    win_time = (unix_time + EPOCH_DIFF) * 10000000;
    ftime->dwLowDateTime = win_time & 0xFFFFFFFF;
    ftime->dwHighDateTime = (win_time >> 32) & 0xFFFFFFFF;
}

static int
set_utc_file_time (const char *path, const wchar_t *wpath, guint64 mtime)
{
    HANDLE handle;
    FILETIME write_time;

    handle = CreateFileW (wpath,
                          GENERIC_WRITE,
                          FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                          NULL,
                          OPEN_EXISTING,
                          FILE_FLAG_BACKUP_SEMANTICS,
                          NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        g_warning ("Failed to open %s: %lu.\n", path, GetLastError());
        return -1;
    }

    unix_time_to_file_time (mtime, &write_time);

    if (!SetFileTime (handle, NULL, NULL, &write_time)) {
        g_warning ("Failed to set file time for %s: %lu.\n", path, GetLastError());
        CloseHandle (handle);
        return -1;
    }
    CloseHandle (handle);

    return 0;
}

wchar_t *
win32_long_path (const char *path)
{
    char *long_path, *p;
    wchar_t *long_path_w;

    if (strncmp(path, "//", 2) == 0)
        long_path = g_strconcat ("\\\\?\\UNC\\", path + 2, NULL);
    else
        long_path = g_strconcat ("\\\\?\\", path, NULL);
    for (p = long_path; *p != 0; ++p)
        if (*p == '/')
            *p = '\\';

    long_path_w = g_utf8_to_utf16 (long_path, -1, NULL, NULL, NULL);

    g_free (long_path);
    return long_path_w;
}

/* Convert a (possible) 8.3 format path to long path */
wchar_t *
win32_83_path_to_long_path (const char *worktree, const wchar_t *path, int path_len)
{
    wchar_t *worktree_w = g_utf8_to_utf16 (worktree, -1, NULL, NULL, NULL);
    int wt_len;
    wchar_t *p;
    wchar_t *fullpath_w = NULL;
    wchar_t *fullpath_long = NULL;
    wchar_t *ret = NULL;
    char *fullpath;

    for (p = worktree_w; *p != L'\0'; ++p)
        if (*p == L'/')
            *p = L'\\';

    wt_len = wcslen(worktree_w);

    fullpath_w = g_new0 (wchar_t, wt_len + path_len + 6);
    wcscpy (fullpath_w, L"\\\\?\\");
    wcscat (fullpath_w, worktree_w);
    wcscat (fullpath_w, L"\\");
    wcsncat (fullpath_w, path, path_len);

    fullpath_long = g_new0 (wchar_t, SEAF_PATH_MAX);

    DWORD n = GetLongPathNameW (fullpath_w, fullpath_long, SEAF_PATH_MAX);
    if (n == 0) {
        /* Failed. */
        fullpath = g_utf16_to_utf8 (fullpath_w, -1, NULL, NULL, NULL);
        g_free (fullpath);

        goto out;
    } else if (n > SEAF_PATH_MAX) {
        /* In this case n is the necessary length for the buf. */
        g_free (fullpath_long);
        fullpath_long = g_new0 (wchar_t, n);

        if (GetLongPathNameW (fullpath_w, fullpath_long, n) != (n - 1)) {
            fullpath = g_utf16_to_utf8 (fullpath_w, -1, NULL, NULL, NULL);
            g_free (fullpath);

            goto out;
        }
    }

    /* Remove "\\?\worktree\" from the beginning. */
    ret = wcsdup (fullpath_long + wt_len + 5);

out:
    g_free (worktree_w);
    g_free (fullpath_w);
    g_free (fullpath_long);

    return ret;
}

static int
windows_error_to_errno (DWORD error)
{
    switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return ENOENT;
    case ERROR_ALREADY_EXISTS:
        return EEXIST;
    case ERROR_ACCESS_DENIED:
    case ERROR_SHARING_VIOLATION:
        return EACCES;
    case ERROR_DIR_NOT_EMPTY:
        return ENOTEMPTY;
    default:
        return 0;
    }
}

#endif

int
seaf_stat (const char *path, SeafStat *st)
{
#ifdef WIN32
    wchar_t *wpath = win32_long_path (path);
    WIN32_FILE_ATTRIBUTE_DATA attrs;
    int ret = 0;

    if (!GetFileAttributesExW (wpath, GetFileExInfoStandard, &attrs)) {
        ret = -1;
        errno = windows_error_to_errno (GetLastError());
        goto out;
    }

    memset (st, 0, sizeof(SeafStat));

    if (attrs.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        st->st_mode = S_IFDIR;
    else
        st->st_mode = S_IFREG;

    st->st_atime = file_time_to_unix_time (&attrs.ftLastAccessTime);
    st->st_ctime = file_time_to_unix_time (&attrs.ftCreationTime);
    st->st_mtime = file_time_to_unix_time (&attrs.ftLastWriteTime);

    st->st_size = ((((__int64)attrs.nFileSizeHigh)<<32) + attrs.nFileSizeLow);

out:
    g_free (wpath);

    return ret;
#else
    return stat (path, st);
#endif
}

int
seaf_fstat (int fd, SeafStat *st)
{
#ifdef WIN32
    if (_fstat64 (fd, st) < 0)
        return -1;

    if (get_utc_file_time_fd (fd, &st->st_mtime, &st->st_ctime) < 0)
        return -1;

    return 0;
#else
    return fstat (fd, st);
#endif
}

#ifdef WIN32

void
seaf_stat_from_find_data (WIN32_FIND_DATAW *fdata, SeafStat *st)
{
    memset (st, 0, sizeof(SeafStat));

    if (fdata->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        st->st_mode = S_IFDIR;
    else
        st->st_mode = S_IFREG;

    st->st_atime = file_time_to_unix_time (&fdata->ftLastAccessTime);
    st->st_ctime = file_time_to_unix_time (&fdata->ftCreationTime);
    st->st_mtime = file_time_to_unix_time (&fdata->ftLastWriteTime);

    st->st_size = ((((__int64)fdata->nFileSizeHigh)<<32) + fdata->nFileSizeLow);
}

#endif

int
seaf_set_file_time (const char *path, guint64 mtime)
{
#ifndef WIN32
    struct stat st;
    struct utimbuf times;

    if (stat (path, &st) < 0) {
        g_warning ("Failed to stat %s: %s.\n", path, strerror(errno));
        return -1;
    }

    times.actime = st.st_atime;
    times.modtime = (time_t)mtime;

    return utime (path, &times);
#else
    wchar_t *wpath = win32_long_path (path);
    int ret = 0;

    if (set_utc_file_time (path, wpath, mtime) < 0)
        ret = -1;

    g_free (wpath);
    return ret;
#endif
}

int
seaf_util_unlink (const char *path)
{
#ifdef WIN32
    wchar_t *wpath = win32_long_path (path);
    int ret = 0;

    if (!DeleteFileW (wpath)) {
        ret = -1;
        errno = windows_error_to_errno (GetLastError());
    }

    g_free (wpath);
    return ret;
#else
    return unlink (path);
#endif
}

int
seaf_util_rmdir (const char *path)
{
#ifdef WIN32
    wchar_t *wpath = win32_long_path (path);
    int ret = 0;

    if (!RemoveDirectoryW (wpath)) {
        ret = -1;
        errno = windows_error_to_errno (GetLastError());
    }

    g_free (wpath);
    return ret;
#else
    return rmdir (path);
#endif
}

int
seaf_util_mkdir (const char *path, mode_t mode)
{
#ifdef WIN32
    wchar_t *wpath = win32_long_path (path);
    int ret = 0;

    if (!CreateDirectoryW (wpath, NULL)) {
        ret = -1;
        errno = windows_error_to_errno (GetLastError());
    }

    g_free (wpath);
    return ret;
#else
    return mkdir (path, mode);
#endif
}

int
seaf_util_open (const char *path, int flags)
{
#ifdef WIN32
    wchar_t *wpath;
    DWORD access = 0;
    HANDLE handle;
    int fd;

    access |= GENERIC_READ;
    if (flags & (O_WRONLY | O_RDWR))
        access |= GENERIC_WRITE;

    wpath = win32_long_path (path);

    handle = CreateFileW (wpath,
                          access,
                          FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL,
                          OPEN_EXISTING,
                          0,
                          NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        errno = windows_error_to_errno (GetLastError());
        g_free (wpath);
        return -1;
    }

    fd = _open_osfhandle ((intptr_t)handle, 0);

    g_free (wpath);
    return fd;
#else
    return open (path, flags);
#endif
}

int
seaf_util_create (const char *path, int flags, mode_t mode)
{
#ifdef WIN32
    wchar_t *wpath;
    DWORD access = 0;
    HANDLE handle;
    int fd;

    access |= GENERIC_READ;
    if (flags & (O_WRONLY | O_RDWR))
        access |= GENERIC_WRITE;

    wpath = win32_long_path (path);

    handle = CreateFileW (wpath,
                          access,
                          FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
                          NULL,
                          CREATE_ALWAYS,
                          0,
                          NULL);
    if (handle == INVALID_HANDLE_VALUE) {
        errno = windows_error_to_errno (GetLastError());
        g_free (wpath);
        return -1;
    }

    fd = _open_osfhandle ((intptr_t)handle, 0);

    g_free (wpath);
    return fd;
#else
    return open (path, flags, mode);
#endif
}

int
seaf_util_rename (const char *oldpath, const char *newpath)
{
#ifdef WIN32
    wchar_t *oldpathw = win32_long_path (oldpath);
    wchar_t *newpathw = win32_long_path (newpath);
    int ret = 0;

    if (!MoveFileExW (oldpathw, newpathw, MOVEFILE_REPLACE_EXISTING)) {
        ret = -1;
        errno = windows_error_to_errno (GetLastError());
    }

    g_free (oldpathw);
    g_free (newpathw);
    return ret;
#else
    return rename (oldpath, newpath);
#endif
}

gboolean
seaf_util_exists (const char *path)
{
#ifdef WIN32
    wchar_t *wpath = win32_long_path (path);
    DWORD attrs;
    gboolean ret;

    attrs = GetFileAttributesW (wpath);
    ret = (attrs != INVALID_FILE_ATTRIBUTES);

    g_free (wpath);
    return ret;
#else
    return (access (path, F_OK) == 0);
#endif
}

gint64
seaf_util_lseek (int fd, gint64 offset, int whence)
{
#ifdef WIN32
    return _lseeki64 (fd, offset, whence);
#else
    return lseek (fd, offset, whence);
#endif
}

#ifdef WIN32

int
traverse_directory_win32 (wchar_t *path_w,
                          DirentCallback callback,
                          void *user_data)
{
    WIN32_FIND_DATAW fdata;
    HANDLE handle;
    wchar_t *pattern;
    char *path;
    int path_len_w;
    DWORD error;
    gboolean stop;
    int ret = 0;

    path = g_utf16_to_utf8 (path_w, -1, NULL, NULL, NULL);
    if (!path)
        return -1;

    path_len_w = wcslen(path_w);

    pattern = g_new0 (wchar_t, (path_len_w + 3));
    wcscpy (pattern, path_w);
    wcscat (pattern, L"\\*");

    handle = FindFirstFileW (pattern, &fdata);
    if (handle == INVALID_HANDLE_VALUE) {
        g_warning ("FindFirstFile failed %s: %lu.\n",
                   path, GetLastError());
        ret = -1;
        goto out;
    }

    do {
        if (wcscmp (fdata.cFileName, L".") == 0 ||
            wcscmp (fdata.cFileName, L"..") == 0)
            continue;

        ++ret;

        stop = FALSE;
        if (callback (path_w, &fdata, user_data, &stop) < 0) {
            ret = -1;
            FindClose (handle);
            goto out;
        }
        if (stop) {
            FindClose (handle);
            goto out;
        }
    } while (FindNextFileW (handle, &fdata) != 0);

    error = GetLastError();
    if (error != ERROR_NO_MORE_FILES) {
        g_warning ("FindNextFile failed %s: %lu.\n",
                   path, error);
        ret = -1;
    }

    FindClose (handle);

out:
    g_free (path);
    g_free (pattern);
    return ret;
}

#endif

#ifdef WIN32
static inline gboolean
has_trailing_space_or_period (const char *path)
{
    int len = strlen(path);
    if (path[len - 1] == ' ' || path[len - 1] == '.') {
        return TRUE;
    }

    return FALSE;
}
#endif

gboolean
should_ignore_on_checkout (const char *file_path, IgnoreReason *ignore_reason)
{
    gboolean ret = FALSE;

#ifdef WIN32
    static char illegals[] = {'\\', ':', '*', '?', '"', '<', '>', '|', '\b', '\t'};
    char **components = g_strsplit (file_path, "/", -1);
    int n_comps = g_strv_length (components);
    int j = 0;
    char *file_name;
    int i;
    char c;

    for (; j < n_comps; ++j) {
        file_name = components[j];

        if (has_trailing_space_or_period (file_name)) {
            /* Ignore files/dir whose path has trailing spaces. It would cause
             * problem on windows. */
            /* g_debug ("ignore '%s' which contains trailing space in path\n", path); */
            ret = TRUE;
            if (ignore_reason)
                *ignore_reason = IGNORE_REASON_END_SPACE_PERIOD;
            goto out;
        }

        for (i = 0; i < G_N_ELEMENTS(illegals); i++) {
            if (strchr (file_name, illegals[i])) {
                ret = TRUE;
                if (ignore_reason)
                    *ignore_reason = IGNORE_REASON_INVALID_CHARACTER;
                goto out;
            }
        }

        for (c = 1; c <= 31; c++) {
            if (strchr (file_name, c)) {
                ret = TRUE;
                if (ignore_reason)
                    *ignore_reason = IGNORE_REASON_INVALID_CHARACTER;
                goto out;
            }
        }
    }

out:
    g_strfreev (components);
#endif

    return ret;
}

ssize_t						/* Read "n" bytes from a descriptor. */
readn(int fd, void *vptr, size_t n)
{
	size_t	nleft;
	ssize_t	nread;
	char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nread = read(fd, ptr, nleft)) < 0) {
			if (errno == EINTR)
				nread = 0;		/* and call read() again */
			else
				return(-1);
		} else if (nread == 0)
			break;				/* EOF */

		nleft -= nread;
		ptr   += nread;
	}
	return(n - nleft);		/* return >= 0 */
}

ssize_t						/* Write "n" bytes to a descriptor. */
writen(int fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}


ssize_t						/* Read "n" bytes from a descriptor. */
recvn(evutil_socket_t fd, void *vptr, size_t n)
{
	size_t	nleft;
	ssize_t	nread;
	char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
#ifndef WIN32
        if ( (nread = read(fd, ptr, nleft)) < 0)
#else
        if ( (nread = recv(fd, ptr, nleft, 0)) < 0)
#endif
        {
			if (errno == EINTR)
				nread = 0;		/* and call read() again */
			else
				return(-1);
		} else if (nread == 0)
			break;				/* EOF */

		nleft -= nread;
		ptr   += nread;
	}
	return(n - nleft);		/* return >= 0 */
}

ssize_t						/* Write "n" bytes to a descriptor. */
sendn(evutil_socket_t fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
#ifndef WIN32
        if ( (nwritten = write(fd, ptr, nleft)) <= 0)
#else
        if ( (nwritten = send(fd, ptr, nleft, 0)) <= 0)
#endif
        {
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}

#ifdef WIN32
static SOCKET pg_serv_sock = INVALID_SOCKET;
static struct sockaddr_in pg_serv_addr;

/* seaf_pipe() should only be called in the main loop,
 * since it accesses the static global socket.
 */
int
seaf_pipe (seaf_pipe_t handles[2])
{
    int len = sizeof( pg_serv_addr );

    handles[0] = handles[1] = INVALID_SOCKET;

    if (pg_serv_sock == INVALID_SOCKET) {
        if ((pg_serv_sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
            seaf_warning("seaf_pipe failed to create socket: %d\n", WSAGetLastError());
            return -1;
        }

        memset(&pg_serv_addr, 0, sizeof(pg_serv_addr));
        pg_serv_addr.sin_family = AF_INET;
        pg_serv_addr.sin_port = htons(0);
        pg_serv_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (bind(pg_serv_sock, (SOCKADDR *)&pg_serv_addr, len) == SOCKET_ERROR) {
            seaf_warning("seaf_pipe failed to bind: %d\n", WSAGetLastError());
            closesocket(pg_serv_sock);
            pg_serv_sock = INVALID_SOCKET;
            return -1;
        }

        if (listen(pg_serv_sock, SOMAXCONN) == SOCKET_ERROR) {
            seaf_warning("seaf_pipe failed to listen: %d\n", WSAGetLastError());
            closesocket(pg_serv_sock);
            pg_serv_sock = INVALID_SOCKET;
            return -1;
        }

        struct sockaddr_in tmp_addr;
        int tmp_len = sizeof(tmp_addr);
        if (getsockname(pg_serv_sock, (SOCKADDR *)&tmp_addr, &tmp_len) == SOCKET_ERROR) {
            seaf_warning("seaf_pipe failed to getsockname: %d\n", WSAGetLastError());
            closesocket(pg_serv_sock);
            pg_serv_sock = INVALID_SOCKET;
            return -1;
        }
        pg_serv_addr.sin_port = tmp_addr.sin_port;
    }

    if ((handles[1] = socket(PF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
    {
        seaf_warning("seaf_pipe failed to create socket 2: %d\n", WSAGetLastError());
        closesocket(pg_serv_sock);
        pg_serv_sock = INVALID_SOCKET;
        return -1;
    }

    if (connect(handles[1], (SOCKADDR *)&pg_serv_addr, len) == SOCKET_ERROR)
    {
        seaf_warning("seaf_pipe failed to connect socket: %d\n", WSAGetLastError());
        closesocket(handles[1]);
        handles[1] = INVALID_SOCKET;
        closesocket(pg_serv_sock);
        pg_serv_sock = INVALID_SOCKET;
        return -1;
    }

    struct sockaddr_in client_addr;
    int client_len = sizeof(client_addr);
    if ((handles[0] = accept(pg_serv_sock, (SOCKADDR *)&client_addr, &client_len)) == INVALID_SOCKET)
    {
        seaf_warning("seaf_pipe failed to accept socket: %d\n", WSAGetLastError());
        closesocket(handles[1]);
        handles[1] = INVALID_SOCKET;
        closesocket(pg_serv_sock);
        pg_serv_sock = INVALID_SOCKET;
        return -1;
    }

    return 0;
}

int
seaf_pipe_read (seaf_pipe_t fd, char *buf, int len)
{
    return recv (fd, buf, len, 0);
}

int
seaf_pipe_write (seaf_pipe_t fd, const char *buf, int len)
{
    return send (fd, buf, len, 0);
}

int
seaf_pipe_close (seaf_pipe_t fd)
{
    return closesocket (fd);
}

ssize_t seaf_pipe_readn (seaf_pipe_t fd, void *vptr, size_t n)
{
    return recvn (fd, vptr, n);
}

ssize_t seaf_pipe_writen (seaf_pipe_t fd, const void *vptr, size_t n)
{
    return sendn (fd, vptr, n);
}

#else

int
seaf_pipe (seaf_pipe_t handles[2])
{
    return pipe (handles);
}

int
seaf_pipe_read (seaf_pipe_t fd, char *buf, int len)
{
    return read (fd, buf, len);
}

int
seaf_pipe_write (seaf_pipe_t fd, const char *buf, int len)
{
    return write (fd, buf, len);
}

int
seaf_pipe_close (seaf_pipe_t fd)
{
    return close (fd);
}

ssize_t seaf_pipe_readn (seaf_pipe_t fd, void *vptr, size_t n)
{
    return readn (fd, vptr, n);
}

ssize_t seaf_pipe_writen (seaf_pipe_t fd, const void *vptr, size_t n)
{
    return writen (fd, vptr, n);
}

#endif

int copy_fd (int ifd, int ofd)
{
    while (1) {
        char buffer[8192];
        ssize_t len = readn (ifd, buffer, sizeof(buffer));
        if (!len)
            break;
        if (len < 0) {
            close (ifd);
            return -1;
        }
        if (writen (ofd, buffer, len) < 0) {
            close (ofd);
            return -1;
        }
    }
    close(ifd);
    return 0;
}

int copy_file (const char *dst, const char *src, int mode)
{
    int fdi, fdo, status;

    if ((fdi = g_open (src, O_RDONLY | O_BINARY, 0)) < 0)
        return fdi;

    fdo = g_open (dst, O_WRONLY | O_CREAT | O_EXCL | O_BINARY, mode);
    if (fdo < 0 && errno == EEXIST) {
        close (fdi);
        return 0;
    } else if (fdo < 0){
        close (fdi);
        return -1;
    }

    status = copy_fd (fdi, fdo);
    if (close (fdo) != 0)
        return -1;

    return status;
}

char*
ccnet_expand_path (const char *src)
{
#ifdef WIN32
    char new_path[SEAF_PATH_MAX + 1];
    char *p = new_path;
    const char *q = src;

    memset(new_path, 0, sizeof(new_path));
    if (*src == '~') {
        const char *home = g_get_home_dir();
        memcpy(new_path, home, strlen(home));
        p += strlen(new_path);
        q++;
    }
    memcpy(p, q, strlen(q));

    /* delete the charactor '\' or '/' at the end of the path
     * because the function stat faied to deal with directory names
     * with '\' or '/' in the end */
    p = new_path + strlen(new_path) - 1;
    while(*p == '\\' || *p == '/') *p-- = '\0';

    return strdup (new_path);
#else
    const char *next_in, *ntoken;
    char new_path[SEAF_PATH_MAX + 1];
    char *next_out;
    int len;

   /* special cases */
    if (!src || *src == '\0')
        return NULL;
    if (strlen(src) > SEAF_PATH_MAX)
        return NULL;

    next_in = src;
    next_out = new_path;
    *next_out = '\0';

    if (*src == '~') {
        /* handle src start with '~' or '~<user>' like '~plt' */
        struct passwd *pw = NULL;

        for ( ; *next_in != '/' && *next_in != '\0'; next_in++) ;
        
        len = next_in - src;
        if (len == 1) {
            pw = getpwuid (geteuid());
        } else {
            /* copy '~<user>' to new_path */
            memcpy (new_path, src, len);
            new_path[len] = '\0';
            pw = getpwnam (new_path + 1);
        }
        if (pw == NULL)
            return NULL;
       
        len = strlen (pw->pw_dir);
        memcpy (new_path, pw->pw_dir, len);
        next_out = new_path + len;
        *next_out = '\0';

        if (*next_in == '\0')
            return strdup (new_path);
    } else if (*src != '/') {
        getcwd (new_path, SEAF_PATH_MAX);
        for ( ; *next_out; next_out++) ; /* to '\0' */
    }
    
    while (*next_in != '\0') {
        /* move ntoken to the next not '/' char  */
        for (ntoken = next_in; *ntoken == '/'; ntoken++) ;

        for (next_in = ntoken; *next_in != '/' 
                 && *next_in != '\0'; next_in++) ;
 
        len = next_in - ntoken;

        if (len == 0) {
            /* the path ends with '/', keep it */
            *next_out++ = '/';
            *next_out = '\0';
            break;
        }

        if (len == 2 && ntoken[0] == '.' && ntoken[1] == '.') 
        {
            /* '..' */
            for (; next_out > new_path && *next_out != '/'; next_out--)
                ;
            *next_out = '\0';
        } else if (ntoken[0] != '.' || len != 1) {
            /* not '.' */
            *next_out++ = '/';
            memcpy (next_out, ntoken, len);
            next_out += len;
            *next_out = '\0';
        }
    }

    /* the final special case */
    if (new_path[0] == '\0') {
        new_path[0] = '/';
        new_path[1] = '\0';
    }
    return strdup (new_path);
#endif
}


int
calculate_sha1 (unsigned char *sha1, const char *msg, int len)
{
    GChecksum *c;
    gsize cs_len = 20;

    if (len < 0)
        len = strlen(msg);

    c = g_checksum_new (G_CHECKSUM_SHA1);
    g_checksum_update(c, (const unsigned char *)msg, len);    
    g_checksum_get_digest (c, sha1, &cs_len);
    g_checksum_free (c);
    return 0;
}

uint32_t
ccnet_sha1_hash (const void *v)
{
    /* 31 bit hash function */
    const unsigned char *p = v;
    uint32_t h = 0;
    int i;

    for (i = 0; i < 20; i++)
        h = (h << 5) - h + p[i];

    return h;
}

int
ccnet_sha1_equal (const void *v1,
                  const void *v2)
{
    const unsigned char *p1 = v1;
    const unsigned char *p2 = v2;
    int i;

    for (i = 0; i < 20; i++)
        if (p1[i] != p2[i])
            return 0;
    
    return 1;
}

#ifndef WIN32
char* gen_uuid ()
{
    char *uuid_str = g_malloc (37);
    uuid_t uuid;

    uuid_generate (uuid);
    uuid_unparse_lower (uuid, uuid_str);

    return uuid_str;
}

void gen_uuid_inplace (char *buf)
{
    uuid_t uuid;

    uuid_generate (uuid);
    uuid_unparse_lower (uuid, buf);
}

gboolean
is_uuid_valid (const char *uuid_str)
{
    uuid_t uuid;

    if (!uuid_str)
        return FALSE;

    if (uuid_parse (uuid_str, uuid) < 0)
        return FALSE;
    return TRUE;
}

#else
char* gen_uuid ()
{
    char *uuid_str = g_malloc (37);
    unsigned char *str = NULL;
    UUID uuid;

    UuidCreate(&uuid);
    UuidToStringA(&uuid, &str);
    memcpy(uuid_str, str, 37);
    RpcStringFreeA(&str);
    return uuid_str;
}

void gen_uuid_inplace (char *buf)
{
    unsigned char *str = NULL;
    UUID uuid;

    UuidCreate(&uuid);
    UuidToStringA(&uuid, &str);
    memcpy(buf, str, 37);
    RpcStringFreeA(&str);
}

gboolean
is_uuid_valid (const char *uuid_str)
{
    if (!uuid_str)
        return FALSE;

    UUID uuid;
    if (UuidFromStringA((unsigned char *)uuid_str, &uuid) != RPC_S_OK)
        return FALSE;
    return TRUE;
}

#endif

gboolean
is_object_id_valid (const char *obj_id)
{
    if (!obj_id)
        return FALSE;

    int len = strlen(obj_id);
    int i;
    char c;

    if (len != 40)
        return FALSE;

    for (i = 0; i < len; ++i) {
        c = obj_id[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            continue;
        return FALSE;
    }

    return TRUE;
}

char** strsplit_by_space (char *string, int *length)
{
    char *remainder, *s;
    int size = 8, num = 0, done = 0;
    char **array;
    
    if (string == NULL || string[0] == '\0') {
        if (length != NULL) {
          *length = 0;
        }
        return NULL;
    }

    array = malloc (sizeof(char *) * size);
    if (array == NULL) {
      return NULL;
    }
    
    remainder = string;
    while (!done) {
        for (s = remainder; *s != ' ' && *s != '\0'; ++s) ;

        if (*s == '\0')
            done = 1;
        else
            *s = '\0';

        array[num++] = remainder;
        if (!done && num == size) {
            size <<= 1;
            char** tmp = realloc (array, sizeof(char *) * size);
            if (tmp == NULL) {
              free(array);
              return NULL;
            }
            array = tmp;
        }

        remainder = s + 1;
    }
    
    if (length != NULL) {
      *length = num;
    }

    return array;
}

char** strsplit_by_char (char *string, int *length, char c)
{
    char *remainder, *s;
    int size = 8, num = 0, done = 0;
    char **array;
    
    if (string == NULL || string[0] == '\0') {
        *length = 0;
        return NULL;
    }

    array = malloc (sizeof(char *) * size);
    if (array == NULL) {
      return NULL;
    }
    
    remainder = string;
    while (!done) {
        for (s = remainder; *s != c && *s != '\0'; ++s) ;

        if (*s == '\0')
            done = 1;
        else
            *s = '\0';

        array[num++] = remainder;
        if (!done && num == size) {
            size <<= 1;
            char** tmp = realloc (array, sizeof(char *) * size);
            if (tmp == NULL) {
              free(array);
              return NULL;
            }
            array = tmp;
        }

        remainder = s + 1;
    }
    
    if (length != NULL) {
      *length = num;
    }

    return array;
}

char* strjoin_n (const char *seperator, int argc, char **argv)
{
    GString *buf;
    int i;
    char *str;

    if (argc == 0)
        return NULL;
    
    buf = g_string_new (argv[0]);
    for (i = 1; i < argc; ++i) {
        g_string_append (buf, seperator);
        g_string_append (buf, argv[i]);
    }

    str = buf->str;
    g_string_free (buf, FALSE);
    return str;
}


gboolean is_ipaddr_valid (const char *ip)
{
    unsigned char buf[sizeof(struct in6_addr)];

    if (evutil_inet_pton(AF_INET, ip, buf) == 1)
        return TRUE;

    if (evutil_inet_pton(AF_INET6, ip, buf) == 1)
        return TRUE;
    
    return FALSE;
}

void parse_key_value_pairs (char *string, KeyValueFunc func, void *data)
{
    char *line = string, *next, *space;
    char *key, *value;

    while (*line) {
        /* handle empty line */
        if (*line == '\n') {
            ++line;
            continue;
        }

        for (next = line; *next != '\n' && *next; ++next) ;
        *next = '\0';
        
        for (space = line; space < next && *space != ' '; ++space) ;
        if (*space != ' ') {
            g_warning ("Bad key value format: %s\n", line);
            return;
        }
        *space = '\0';
        key = line;
        value = space + 1;
        
        func (data, key, value);

        line = next + 1;
    }
}

void parse_key_value_pairs2 (char *string, KeyValueFunc2 func, void *data)
{
    char *line = string, *next, *space;
    char *key, *value;

    while (*line) {
        /* handle empty line */
        if (*line == '\n') {
            ++line;
            continue;
        }

        for (next = line; *next != '\n' && *next; ++next) ;
        *next = '\0';
        
        for (space = line; space < next && *space != ' '; ++space) ;
        if (*space != ' ') {
            g_warning ("Bad key value format: %s\n", line);
            return;
        }
        *space = '\0';
        key = line;
        value = space + 1;
        
        if (func(data, key, value) == FALSE)
            break;

        line = next + 1;
    }
}

/**
 * handle the empty string problem.
 */
gchar* 
ccnet_key_file_get_string (GKeyFile *keyf,
                           const char *category,
                           const char *key)
{
    gchar *v;

    if (!g_key_file_has_key (keyf, category, key, NULL))
        return NULL;

    v = g_key_file_get_string (keyf, category, key, NULL);
    if (v != NULL && v[0] == '\0') {
        g_free(v);
        return NULL;
    }

    return v;
}

/**
 * string_list_is_exists:
 * @str_list: 
 * @string: a C string or %NULL
 *
 * Check whether @string is in @str_list.
 *
 * returns: %TRUE if @string is in str_list, %FALSE otherwise
 */
gboolean
string_list_is_exists (GList *str_list, const char *string)
{
    GList *ptr;
    for (ptr = str_list; ptr; ptr = ptr->next) {
        if (g_strcmp0(string, ptr->data) == 0)
            return TRUE;
    }
    return FALSE;
}

/**
 * string_list_append:
 * @str_list: 
 * @string: a C string (can't be %NULL
 *
 * Append @string to @str_list if it is in the list.
 *
 * returns: the new start of the list
 */
GList*
string_list_append (GList *str_list, const char *string)
{
    g_return_val_if_fail (string != NULL, str_list);

    if (string_list_is_exists(str_list, string))
        return str_list;

    str_list = g_list_append (str_list, g_strdup(string));
    return str_list;
}

GList *
string_list_append_sorted (GList *str_list, const char *string)
{
    g_return_val_if_fail (string != NULL, str_list);

    if (string_list_is_exists(str_list, string))
        return str_list;

    str_list = g_list_insert_sorted_with_data (str_list, g_strdup(string),
                                 (GCompareDataFunc)g_strcmp0, NULL);
    return str_list;
}


GList *
string_list_remove (GList *str_list, const char *string)
{
    g_return_val_if_fail (string != NULL, str_list);

    GList *ptr;

    for (ptr = str_list; ptr; ptr = ptr->next) {
        if (strcmp((char *)ptr->data, string) == 0) {
            g_free (ptr->data);
            return g_list_delete_link (str_list, ptr);
        }
    }
    return str_list;
}


void
string_list_free (GList *str_list)
{
    GList *ptr = str_list;

    while (ptr) {
        g_free (ptr->data);
        ptr = ptr->next;
    }

    g_list_free (str_list);
}


void
string_list_join (GList *str_list, GString *str, const char *seperator)
{
    GList *ptr;
    if (!str_list)
        return;

    ptr = str_list;
    g_string_append (str, ptr->data);

    for (ptr = ptr->next; ptr; ptr = ptr->next) {
        g_string_append (str, seperator);
        g_string_append (str, (char *)ptr->data);
    }
}

GList *
string_list_parse (const char *list_in_str, const char *seperator)
{
    if (!list_in_str)
        return NULL;

    GList *list = NULL;
    char **array = g_strsplit (list_in_str, seperator, 0);
    char **ptr;

    for (ptr = array; *ptr; ptr++) {
        list = g_list_prepend (list, g_strdup(*ptr));
    }
    list = g_list_reverse (list);
    
    g_strfreev (array);
    return list;
}

GList *
string_list_parse_sorted (const char *list_in_str, const char *seperator)
{
    GList *list = string_list_parse (list_in_str, seperator);

    return g_list_sort (list, (GCompareFunc)g_strcmp0);
}

gboolean
string_list_sorted_is_equal (GList *list1, GList *list2)
{
    GList *ptr1 = list1, *ptr2 = list2;

    while (ptr1 && ptr2) {
        if (g_strcmp0(ptr1->data, ptr2->data) != 0)
            break;

        ptr1 = ptr1->next;
        ptr2 = ptr2->next;
    }

    if (!ptr1 && !ptr2)
        return TRUE;
    return FALSE;
}

char **
ncopy_string_array (char **orig, int n)
{
    char **ret = g_malloc (sizeof(char *) * n);
    int i = 0;

    for (; i < n; i++)
        ret[i] = g_strdup(orig[i]);
    return ret;
}

void
nfree_string_array (char **array, int n)
{
    int i = 0;

    for (; i < n; i++)
        g_free (array[i]);
    g_free (array);
}

gint64
get_current_time()
{
    GTimeVal tv;
    gint64 t;

    g_get_current_time (&tv);
    t = tv.tv_sec * (gint64)1000000 + tv.tv_usec;
    return t;
}

/* convert locale specific input to utf8 encoded string  */
char *ccnet_locale_to_utf8 (const gchar *src)
{
    if (!src)
        return NULL;

    gsize bytes_read = 0;
    gsize bytes_written = 0;
    GError *error = NULL;
    gchar *dst = NULL;

    dst = g_locale_to_utf8
        (src,                   /* locale specific string */
         strlen(src),           /* len of src */
         &bytes_read,           /* length processed */
         &bytes_written,        /* output length */
         &error);

    if (error) {
        return NULL;
    }

    return dst;
}

/* convert utf8 input to locale specific string  */
char *ccnet_locale_from_utf8 (const gchar *src)
{
    if (!src)
        return NULL;

    gsize bytes_read = 0;
    gsize bytes_written = 0;
    GError *error = NULL;
    gchar *dst = NULL;

    dst = g_locale_from_utf8
        (src,                   /* locale specific string */
         strlen(src),           /* len of src */
         &bytes_read,           /* length processed */
         &bytes_written,        /* output length */
         &error);

    if (error) {
        return NULL;
    }

    return dst;
}

#ifdef WIN32

static HANDLE
get_process_handle (const char *process_name_in)
{
    char name[256];
    if (strstr(process_name_in, ".exe")) {
        snprintf (name, sizeof(name), "%s", process_name_in);
    } else {
        snprintf (name, sizeof(name), "%s.exe", process_name_in);
    }

    DWORD aProcesses[1024], cbNeeded, cProcesses;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return NULL;

    /* Calculate how many process identifiers were returned. */
    cProcesses = cbNeeded / sizeof(DWORD);

    HANDLE hProcess;
    HMODULE hMod;
    char process_name[SEAF_PATH_MAX];
    unsigned int i;

    for (i = 0; i < cProcesses; i++) {
        if(aProcesses[i] == 0)
            continue;
        hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);
        if (!hProcess)
            continue;
            
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseNameA(hProcess, hMod, process_name, 
                              sizeof(process_name)/sizeof(char));
        }

        if (strcasecmp(process_name, name) == 0)
            return hProcess;
        else {
            CloseHandle(hProcess);
        }
    }
    /* Not found */
    return NULL;
}

int count_process (const char *process_name_in)
{
    char name[SEAF_PATH_MAX];
    char process_name[SEAF_PATH_MAX];
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    HANDLE hProcess;
    HMODULE hMods[1024];
    int count = 0;
    int i, j;
    
    if (strstr(process_name_in, ".exe")) {
        snprintf (name, sizeof(name), "%s", process_name_in);
    } else {
        snprintf (name, sizeof(name), "%s.exe", process_name_in);
    }

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return 0;
    }

    /* Calculate how many process identifiers were returned. */
    cProcesses = cbNeeded / sizeof(DWORD);

    for (i = 0; i < cProcesses; i++) {
        if(aProcesses[i] == 0)
            continue;
        hProcess = OpenProcess (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
        if (!hProcess) {
            continue;
        }
            
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (j = 0; j < cbNeeded / sizeof(HMODULE); j++) {
                if (GetModuleBaseNameA(hProcess, hMods[j], process_name,
                                      sizeof(process_name))) {
                    if (strcasecmp(process_name, name) == 0)
                        count++;
                }
            } 
        }

        CloseHandle(hProcess);
    }
    
    return count;
}

gboolean
process_is_running (const char *process_name)
{
    HANDLE proc_handle = get_process_handle(process_name);

    if (proc_handle) {
        CloseHandle(proc_handle);
        return TRUE;
    } else {
        return FALSE;
    }
}

int
win32_kill_process (const char *process_name)
{
    HANDLE proc_handle = get_process_handle(process_name);

    if (proc_handle) {
        TerminateProcess(proc_handle, 0);
        CloseHandle(proc_handle);
        return 0;
    } else {
        return -1;
    }
}

int
win32_spawn_process (char *cmdline_in, char *working_directory_in)
{
    if (!cmdline_in)
        return -1;

    wchar_t *cmdline_w = NULL;
    wchar_t *working_directory_w = NULL;

    cmdline_w = wchar_from_utf8 (cmdline_in);
    if (!cmdline_in) {
        g_warning ("failed to convert cmdline_in");
        return -1;
    }
    
    if (working_directory_in) {
        working_directory_w = wchar_from_utf8 (working_directory_in);
        if (!working_directory_w) {
            g_warning ("failed to convert working_directory_in");
            return -1;
        }
    }

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    unsigned flags;
    BOOL success;

    /* we want to execute seafile without crreating a console window */
    flags = CREATE_NO_WINDOW;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_FORCEOFFFEEDBACK;
    si.hStdInput = (HANDLE) _get_osfhandle(0);
    si.hStdOutput = (HANDLE) _get_osfhandle(1);
    si.hStdError = (HANDLE) _get_osfhandle(2);
    
    memset(&pi, 0, sizeof(pi));

    success = CreateProcessW (NULL, cmdline_w, NULL, NULL, TRUE, flags,
                              NULL, working_directory_w, &si, &pi);
    free (cmdline_w);
    if (working_directory_w) free (working_directory_w);
    
    if (!success) {
        g_warning ("failed to fork_process: GLE=%lu\n", GetLastError());
        return -1;
    }

    /* close the handle of thread so that the process object can be freed by
     * system
     */
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}

char *
wchar_to_utf8 (const wchar_t *wch)
{
    if (wch == NULL) {
        return NULL;
    }

    char *utf8 = NULL;
    int bufsize, len;

    bufsize = WideCharToMultiByte
        (CP_UTF8,               /* multibyte code page */
         0,                     /* flags */
         wch,                   /* src */
         -1,                    /* src len, -1 for all includes \0 */
         utf8,                  /* dst */
         0,                     /* dst buf len */
         NULL,                  /* default char */
         NULL);                 /* BOOL flag indicates default char is used */

    if (bufsize <= 0) {
        g_warning ("failed to convert a string from wchar to utf8 0");
        return NULL;
    }

    utf8 = g_malloc(bufsize);
    len = WideCharToMultiByte
        (CP_UTF8,               /* multibyte code page */
         0,                     /* flags */
         wch,                   /* src */
         -1,                    /* src len, -1 for all includes \0 */
         utf8,                  /* dst */
         bufsize,               /* dst buf len */
         NULL,                  /* default char */
         NULL);                 /* BOOL flag indicates default char is used */

    if (len != bufsize) {
        g_free (utf8);
        g_warning ("failed to convert a string from wchar to utf8");
        return NULL;
    }

    return utf8;
}

wchar_t *
wchar_from_utf8 (const char *utf8)
{
    if (utf8 == NULL) {
        return NULL;
    }

    wchar_t *wch = NULL;
    int bufsize, len;

    bufsize = MultiByteToWideChar
        (CP_UTF8,               /* multibyte code page */
         0,                     /* flags */
         utf8,                  /* src */
         -1,                    /* src len, -1 for all includes \0 */
         wch,                   /* dst */
         0);                    /* dst buf len */

    if (bufsize <= 0) {
        g_warning ("failed to convert a string from wchar to utf8 0");
        return NULL;
    }

    wch = g_malloc (bufsize * sizeof(wchar_t));
    len = MultiByteToWideChar
        (CP_UTF8,               /* multibyte code page */
         0,                     /* flags */
         utf8,                  /* src */
         -1,                    /* src len, -1 for all includes \0 */
         wch,                   /* dst */
         bufsize);              /* dst buf len */

    if (len != bufsize) {
        g_free (wch);
        g_warning ("failed to convert a string from utf8 to wchar");
        return NULL;
    }

    return wch;
}

#endif  /* ifdef WIN32 */

#ifdef __linux__
/* read the link of /proc/123/exe and compare with `process_name' */
static int
find_process_in_dirent(struct dirent *dir, const char *process_name)
{
    char path[512];
    /* fisrst construct a path like /proc/123/exe */
    if (sprintf (path, "/proc/%s/exe", dir->d_name) < 0) {
        return -1;
    }

    char buf[SEAF_PATH_MAX];
    /* get the full path of exe */
    ssize_t l = readlink(path, buf, SEAF_PATH_MAX);

    if (l < 0)
        return -1;
    buf[l] = '\0';

    /* get the base name of exe */
    char *base = g_path_get_basename(buf);
    int ret = strcmp(base, process_name);
    g_free(base);

    if (ret == 0)
        return atoi(dir->d_name);
    else
        return -1;
}

/* read the /proc fs to determine whether some process is running */
gboolean process_is_running (const char *process_name)
{
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        fprintf (stderr, "failed to open /proc/ dir\n");
        return FALSE;
    }

    struct dirent *subdir = NULL;
    while ((subdir = readdir(proc_dir))) {
        char first = subdir->d_name[0];
        /* /proc/[1-9][0-9]* */
        if (first > '9' || first < '1')
            continue;
        int pid = find_process_in_dirent(subdir, process_name);
        if (pid > 0) {
            closedir(proc_dir);
            return TRUE;
        }
    }

    closedir(proc_dir);
    return FALSE;
}

int count_process(const char *process_name)
{
    int count = 0;
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        g_warning ("failed to open /proc/ :%s\n", strerror(errno));
        return FALSE;
    }

    struct dirent *subdir = NULL;
    while ((subdir = readdir(proc_dir))) {
        char first = subdir->d_name[0];
        /* /proc/[1-9][0-9]* */
        if (first > '9' || first < '1')
            continue;
        if (find_process_in_dirent(subdir, process_name) > 0) {
            count++;
        }
    }

    closedir (proc_dir);
    return count;
}

#endif

#ifdef __APPLE__
gboolean process_is_running (const char *process_name)
{
    //TODO
    return FALSE;
}
#endif

char*
ccnet_object_type_from_id (const char *object_id)
{
    char *ptr;

    if ( !(ptr = strchr(object_id, '/')) )
        return NULL;

    return g_strndup(object_id, ptr - object_id);
}


#ifdef WIN32
/**
 * In Win32 we need to use _stat64 for files larger than 2GB. _stat64 needs
 * the `path' argument in gbk encoding.
 */
    #define STAT_STRUCT struct __stat64
    #define STAT_FUNC win_stat64_utf8

static inline int
win_stat64_utf8 (char *path_utf8, STAT_STRUCT *sb)
{
    wchar_t *path_w = wchar_from_utf8 (path_utf8);
    int result = _wstat64 (path_w, sb);
    free (path_w);
    return result;
}

#else
    #define STAT_STRUCT struct stat
    #define STAT_FUNC stat
#endif

static gint64
calc_recursively (const char *path, GError **calc_error)
{
    gint64 sum = 0;

    GError *error = NULL;
    GDir *folder = g_dir_open(path, 0, &error);
    if (!folder) {
        g_set_error (calc_error, CCNET_DOMAIN, 0,
                     "g_open() dir %s failed:%s\n", path, error->message);
        return -1;
    }

    const char *name = NULL;
    while ((name = g_dir_read_name(folder)) != NULL) {
        STAT_STRUCT sb;
        char *full_path= g_build_filename (path, name, NULL);
        if (STAT_FUNC(full_path, &sb) < 0) {
            g_set_error (calc_error, CCNET_DOMAIN, 0, "failed to stat on %s: %s\n",
                         full_path, strerror(errno));
            g_free(full_path);
            g_dir_close(folder);
            return -1;
        }

        if (S_ISDIR(sb.st_mode)) {
            gint64 size = calc_recursively(full_path, calc_error);
            if (size < 0) {
                g_free (full_path);
                g_dir_close (folder);
                return -1;
            }
            sum += size;
            g_free(full_path);
        } else if (S_ISREG(sb.st_mode)) {
            sum += sb.st_size;
            g_free(full_path);
        }
    }

    g_dir_close (folder);
    return sum;
}

gint64
ccnet_calc_directory_size (const char *path, GError **error)
{
    return calc_recursively (path, error);
}

#ifdef WIN32
/*
 * strtok_r code directly from glibc.git /string/strtok_r.c since windows
 * doesn't have it.
 */
char *
strtok_r(char *s, const char *delim, char **save_ptr)
{
    char *token;
    
    if(s == NULL)
        s = *save_ptr;
    
    /* Scan leading delimiters.  */
    s += strspn(s, delim);
    if(*s == '\0') {
        *save_ptr = s;
        return NULL;
    }
    
    /* Find the end of the token.  */
    token = s;
    s = strpbrk(token, delim);
    
    if(s == NULL) {
        /* This token finishes the string.  */
        *save_ptr = strchr(token, '\0');
    } else {
        /* Terminate the token and make *SAVE_PTR point past it.  */
        *s = '\0';
        *save_ptr = s + 1;
    }
    
    return token;
}
#endif

/* JSON related utils. For compatibility with json-glib. */

const char *
json_object_get_string_member (json_t *object, const char *key)
{
    json_t *string = json_object_get (object, key);
    if (!string)
        return NULL;
    return json_string_value (string);
}

gboolean
json_object_has_member (json_t *object, const char *key)
{
    return (json_object_get (object, key) != NULL);
}

gint64
json_object_get_int_member (json_t *object, const char *key)
{
    json_t *integer = json_object_get (object, key);
    return json_integer_value (integer);
}

void
json_object_set_string_member (json_t *object, const char *key, const char *value)
{
    json_object_set_new (object, key, json_string (value));
}

void
json_object_set_int_member (json_t *object, const char *key, gint64 value)
{
    json_object_set_new (object, key, json_integer (value));
}

void
clean_utf8_data (char *data, int len)
{
    const char *s, *e;
    char *p;
    gboolean is_valid;

    s = data;
    p = data;

    while ((s - data) != len) {
        is_valid = g_utf8_validate (s, len - (s - data), &e);
        if (is_valid)
            break;

        if (s != e)
            p += (e - s);
        *p = '?';
        ++p;
        s = e + 1;
    }
}

char *
normalize_utf8_path (const char *path)
{
    if (!g_utf8_validate (path, -1, NULL))
        return NULL;
    return g_utf8_normalize (path, -1, G_NORMALIZE_NFC);
}

/* zlib related wrapper functions. */

#define ZLIB_BUF_SIZE 16384

int
seaf_compress (guint8 *input, int inlen, guint8 **output, int *outlen)
{
    int ret;
    unsigned have;
    z_stream strm;
    guint8 out[ZLIB_BUF_SIZE];
    GByteArray *barray;

    if (inlen == 0)
        return -1;

    /* allocate deflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        g_warning ("deflateInit failed.\n");
        return -1;
    }

    strm.avail_in = inlen;
    strm.next_in = input;
    barray = g_byte_array_new ();

    do {
        strm.avail_out = ZLIB_BUF_SIZE;
        strm.next_out = out;
        ret = deflate(&strm, Z_FINISH);    /* no bad return value */
        have = ZLIB_BUF_SIZE - strm.avail_out;
        g_byte_array_append (barray, out, have);
    } while (ret != Z_STREAM_END);

    *outlen = barray->len;
    *output = g_byte_array_free (barray, FALSE);

    /* clean up and return */
    (void)deflateEnd(&strm);
    return 0;
}

int
seaf_decompress (guint8 *input, int inlen, guint8 **output, int *outlen)
{
    int ret;
    unsigned have;
    z_stream strm;
    unsigned char out[ZLIB_BUF_SIZE];
    GByteArray *barray;

    if (inlen == 0) {
        g_warning ("Empty input for zlib, invalid.\n");
        return -1;
    }

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        g_warning ("inflateInit failed.\n");
        return -1;
    }

    strm.avail_in = inlen;
    strm.next_in = input;
    barray = g_byte_array_new ();

    do {
        strm.avail_out = ZLIB_BUF_SIZE;
        strm.next_out = out;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret < 0) {
            g_warning ("Failed to inflate.\n");
            goto out;
        }
        have = ZLIB_BUF_SIZE - strm.avail_out;
        g_byte_array_append (barray, out, have);
    } while (ret != Z_STREAM_END);

out:
    /* clean up and return */
    (void)inflateEnd(&strm);

    if (ret == Z_STREAM_END) {
        *outlen = barray->len;
        *output = g_byte_array_free (barray, FALSE);
        return 0;
    } else {
        g_byte_array_free (barray, TRUE);
        return -1;
    }
}

char*
format_dir_path (const char *path)
{
    int path_len = strlen (path);
    char *rpath;
    if (path[0] != '/') {
        rpath = g_strconcat ("/", path, NULL);
        path_len++;
    } else {
        rpath = g_strdup (path);
    }
    while (path_len > 1 && rpath[path_len-1] == '/') {
        rpath[path_len-1] = '\0';
        path_len--;
    }

    return rpath;
}

gboolean
is_empty_string (const char *str)
{
    return !str || strcmp (str, "") == 0;
}

gboolean
is_permission_valid (const char *perm)
{
    if (is_empty_string (perm)) {
        return FALSE;
    }

    return strcmp (perm, "r") == 0 || strcmp (perm, "rw") == 0;
}

gboolean
is_eml_file (const char *path)
{
    int len = strlen(path);
    const char *ext;

    if (len < 5)
        return FALSE;
    ext = &path[len-4];
    return (strcasecmp (ext, ".eml") == 0);
}

char *
canonical_server_url (const char *url_in)
{
    char *url = g_strdup(url_in);
    int len = strlen(url);

    if (url[len - 1] == '/')
        url[len - 1] = 0;

    return url;
}
