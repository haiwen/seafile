/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef COMMON_H
#define COMMON_H

#ifdef HAVE_CONFIG_H
 #include <config.h>
#endif

#ifndef WIN32
#include <unistd.h>
#include <utime.h>
#endif
#include <stdlib.h>
#include <stdint.h>             /* uint32_t */
#include <sys/types.h>          /* size_t */
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

#include <glib.h>
#include <glib/gstdio.h>

#ifdef WIN32
#define strcasecmp _stricmp
#define strncasecmp _strnicmp

#if !defined S_ISDIR
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif

#if !defined(S_ISREG) && defined(S_IFMT) && defined(S_IFREG)
#define S_ISREG(m) (((m) & S_IFMT) == S_IFREG)
#endif

#define F_OK 0
#endif

#define EMPTY_SHA1  "0000000000000000000000000000000000000000"

#define CURRENT_ENC_VERSION 3

#define DEFAULT_PROTO_VERSION 1
#define CURRENT_PROTO_VERSION 7

#define CURRENT_REPO_VERSION 1

#define CURRENT_SYNC_PROTO_VERSION 2

/* For compatibility with the old protocol, use an UUID for signature.
 * Listen manager on the server will use the new block tx protocol if it
 * receives this signature as "token".
 */
#define BLOCK_PROTOCOL_SIGNATURE "529319a0-577f-4d6b-a6c3-3c20f56f290c"

#define SEAF_PATH_MAX 4096

#endif
