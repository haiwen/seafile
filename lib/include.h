
#include <stdint.h>
#ifndef WIN32
#include <config.h>
#include <unistd.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include "utils.h"

#ifndef ccnet_warning
  #define ccnet_warning(fmt, ...) g_warning( "%s: " fmt,  __func__ , ##__VA_ARGS__)
#endif

#ifndef ccnet_error
  #define ccnet_error(fmt, ...)   g_error( "%s: " fmt,  __func__ , ##__VA_ARGS__)
#endif

#ifndef ccnet_message
  #define ccnet_message(fmt, ...) g_message(fmt, ##__VA_ARGS__)
#endif

#ifndef ccnet_debug
  #define ccnet_debug(fmt, ...) g_debug(fmt, ##__VA_ARGS__)
#endif


#ifndef ENABLE_DEBUG
#undef g_debug
#define g_debug(...)  
#endif
