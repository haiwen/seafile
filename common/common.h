/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef COMMON_H
#define COMMON_H

#ifdef HAVE_CONFIG_H
 #include <config.h>
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>             /* uint32_t */
#include <sys/types.h>          /* size_t */
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <utime.h>

#include <glib.h>
#include <glib/gstdio.h>

#define EMPTY_SHA1  "0000000000000000000000000000000000000000"

#define CURRENT_ENC_VERSION 1

#define DEFAULT_PROTO_VERSION 1
#define CURRENT_PROTO_VERSION 3

#define SEAF_PATH_MAX 4096

#ifndef ccnet_warning
#define ccnet_warning(fmt, ...) g_warning("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#ifndef ccnet_error
#define ccnet_error(fmt, ...)   g_error("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#ifndef ccnet_message
#define ccnet_message(fmt, ...) g_message("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#endif
