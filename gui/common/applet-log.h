#ifndef APPLET_LOG_H
#define APPLET_LOG_H


#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef __APPLE__
#define __BASEFILE__ ((strrchr(__FILE__, '/') ?: __FILE__ - 1) + 1)
#else
#define __BASEFILE__ __FILE__
#endif

#define applet_warning(fmt, ...) \
    g_warning("%s(%d): " fmt, __BASEFILE__, __LINE__, ##__VA_ARGS__)
#define applet_message(fmt, ...) \
    g_message("%s(%d): " fmt, __BASEFILE__, __LINE__, ##__VA_ARGS__)
#define applet_debug(fmt, ...) \
    g_debug("%s(%d): " fmt, __BASEFILE__, __LINE__, ##__VA_ARGS__)


int applet_log_init (const char *config_dir);

#endif
