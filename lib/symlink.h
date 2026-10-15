#ifndef SEAF_SYMLINK_H
#define SEAF_SYMLINK_H

#include "utils.h"

/* Ordinary file contents on the wire. The terminating C NUL is not stored.
 * Targets are base64-encoded filesystem bytes, not necessarily UTF-8.
 * No newlines: even a link named seafile-ignore.txt is inert to old clients. */
#define SEAF_SYMLINK_MAGIC "\0SEAFILE-SYMLINK:8e5fd83c-3179-4e82-96d5-cc491901bea7:1:"
#define SEAF_SYMLINK_HEADER_SIZE (sizeof(SEAF_SYMLINK_MAGIC) - 1)
#define SEAF_SYMLINK_TARGET_MAX 4095
#define SEAF_SYMLINK_ENCODED_SIZE(n) ((((n) + 2) / 3) * 4)

/* Present links as their regular-file wire representation to the sync index. */
int seaf_symlink_stat (const char *path, SeafStat *st, gboolean preserve);

/* Return 1 and a private temporary regular file for a link, 0 for other
 * files, or -1 on error. The caller must unlink and free *tmp_path. */
int seaf_symlink_index_path (const char *path, char **tmp_path);

/* Recognize a downloaded regular file and atomically replace it with a link.
 * Return 1 for a link, 0 for ordinary/invalid/unknown-version contents,
 * or -1 on I/O or materialization failure. Never follow an existing link. */
int seaf_symlink_materialize (const char *path);

/* Unlike stat/access/utime, these also handle dangling links. */
gboolean seaf_symlink_exists (const char *path);
int seaf_symlink_set_time (const char *path, guint64 mtime);

#endif
