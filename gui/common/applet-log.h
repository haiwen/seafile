#ifndef APPLET_LOG_H
#define APPLET_LOG_H


#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


#define applet_warning(fmt, ...) \
    g_warning("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define applet_message(fmt, ...) \
    g_message("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define applet_debug(fmt, ...) \
    g_debug("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)


int applet_log_init (const char *config_dir);

#endif
