#ifndef LOG_H
#define LOG_H

#define SEAFILE_DOMAIN g_quark_from_string("seafile")

#ifndef seaf_warning
#define seaf_warning(fmt, ...) g_warning("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#ifndef seaf_message
#define seaf_message(fmt, ...) g_message("%s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif


int seafile_log_init (const char *logfile, const char *ccnet_debug_level_str,
                      const char *seafile_debug_level_str);
int seafile_log_reopen ();

void
seafile_debug_set_flags_string (const gchar *flags_string);

typedef enum
{
    SEAFILE_DEBUG_TRANSFER = 1 << 1,
    SEAFILE_DEBUG_SYNC = 1 << 2,
    SEAFILE_DEBUG_WATCH = 1 << 3, /* wt-monitor */
    SEAFILE_DEBUG_HTTP = 1 << 4,  /* http server */
    SEAFILE_DEBUG_MERGE = 1 << 5,
    SEAFILE_DEBUG_OTHER = 1 << 6,
} SeafileDebugFlags;

void seafile_debug_impl (SeafileDebugFlags flag, const gchar *format, ...);

#ifdef DEBUG_FLAG

#undef seaf_debug
#define seaf_debug(fmt, ...)  \
    seafile_debug_impl (DEBUG_FLAG, "%.10s(%d): " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

#endif  /* DEBUG_FLAG */

#endif
