/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <stdio.h>
#include <glib/gstdio.h>

#include "log.h"
#include "utils.h"

/* message with greater log levels will be ignored */
static int ccnet_log_level;
static int seafile_log_level;
static int seafile_log_options = 0;
static char logf_path[PATH_MAX];
static FILE *logfp;

/* Maximum size of a logfile (in bytes), default is 5MB */
#ifndef MAX_LOG_SIZE
#define MAX_LOG_SIZE 1024 * 1024 * 5
#endif

/* Maximum number of logfiles */
#ifndef MAX_LOG_NUM
#define MAX_LOG_NUM 10
#endif

static void
rotate_log()
{
    int i, rc;
    char fn_new[PATH_MAX];

    long fpos = ftell(logfp);
    g_return_if_fail (fpos >= 0);

    if (fpos < MAX_LOG_SIZE) {
        /* Nothing to do, size not exceeded maximumm size */
        return;
    }

    fclose(logfp);

    /* Rename logfiles: <filename>.<num> to <filename.<num + 1>
       Last logfile will be removed */
    for (i = MAX_LOG_NUM - 1; i >= 0; i--) {
        char fn_old[PATH_MAX];

        snprintf(fn_old, sizeof(fn_old), "%s.%i", logf_path, i);

        if (i < MAX_LOG_NUM - 1) {
            /* Move logfile */

            snprintf(fn_new, sizeof(fn_new), "%s.%i", logf_path, i + 1);
            rc = rename(fn_old, fn_new);
        } else {
            /* The last logfile will be removed */
            rc = unlink(fn_old);
        }

        if (rc == -1 && errno != ENOENT) {
            /* Do not log on error here, simply write to stderr and continue */
            perror(__FUNCTION__);
        }
    }

    /* Move current logfile from <filename> to <filename>.0 */
    snprintf(fn_new, sizeof(fn_new), "%s.0", logf_path);
    rc = rename(logf_path, fn_new);
    if (rc == -1) {
        perror(__FUNCTION__);
        abort(); /* This is a serious error! */
    }

    /* Re-open logfile */
    if ((logfp = fopen(logf_path, "a+")) == NULL) {
        perror(__FUNCTION__);
        abort();
    }
}

static void
do_log (GLogLevelFlags log_level, int log_max_level, const gchar *message)
{
    time_t t;
    struct tm *tm;
    char buf[1024];
    int len;

    if (log_level > log_max_level)
        return;

    t = time(NULL);
    tm = localtime(&t);
    len = strftime (buf, 1024, "[%x %X] ", tm);
    g_return_if_fail (len < 1024);
    fputs (buf, logfp);
    fputs (message, logfp);
    fflush (logfp);

    if ((seafile_log_options & SEAFILE_LOG_ROTATE) > 0 && *logf_path != '\0')
        rotate_log();
}

static void
seafile_log (const gchar *log_domain, GLogLevelFlags log_level,
             const gchar *message,    gpointer user_data)
{
    do_log(log_level, seafile_log_level, message);
}

static void
ccnet_log (const gchar *log_domain, GLogLevelFlags log_level,
             const gchar *message,    gpointer user_data)
{
    do_log(log_level, ccnet_log_level, message);
}

static int
get_debug_level(const char *str, int default_level)
{
    if (strcmp(str, "debug") == 0)
        return G_LOG_LEVEL_DEBUG;
    if (strcmp(str, "info") == 0)
        return G_LOG_LEVEL_INFO;
    if (strcmp(str, "warning") == 0)
        return G_LOG_LEVEL_WARNING;
    return default_level;
}

int
seafile_log_init (const char *logfile, const char *ccnet_debug_level_str,
                  const char *seafile_debug_level_str)
{
    g_log_set_handler (NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
                       | G_LOG_FLAG_RECURSION, seafile_log, NULL);
    g_log_set_handler ("Ccnet", G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
                       | G_LOG_FLAG_RECURSION, ccnet_log, NULL);

    /* record all log message */
    ccnet_log_level = get_debug_level(ccnet_debug_level_str, G_LOG_LEVEL_INFO);
    seafile_log_level = get_debug_level(seafile_debug_level_str, G_LOG_LEVEL_DEBUG);

    strncpy(logf_path, logfile, PATH_MAX - 1);
    logf_path[PATH_MAX - 1] = '\0';

    if (strcmp(logfile, "-") == 0) {
        logfp = stdout;
        *logf_path = '\0';
    } else {
        logfile = ccnet_expand_path(logfile);
        if ((logfp = g_fopen (logfile, "a+")) == NULL) {
            return -1;
        }
    }

    return 0;
}

int seafile_log_set_option(SeafileLogOption options) {
    seafile_log_options |= options;
}

static SeafileDebugFlags debug_flags = 0;

static GDebugKey debug_keys[] = {
  { "Transfer", SEAFILE_DEBUG_TRANSFER },
  { "Sync", SEAFILE_DEBUG_SYNC },
  { "Watch", SEAFILE_DEBUG_WATCH },
  { "Http", SEAFILE_DEBUG_HTTP },
  { "Merge", SEAFILE_DEBUG_MERGE },
  { "Other", SEAFILE_DEBUG_OTHER },
};

gboolean
seafile_debug_flag_is_set (SeafileDebugFlags flag)
{
    return (debug_flags & flag) != 0;
}

void
seafile_debug_set_flags (SeafileDebugFlags flags)
{
    g_message ("Set debug flags %#x\n", flags);
    debug_flags |= flags;
}

void
seafile_debug_set_flags_string (const gchar *flags_string)
{
    guint nkeys = G_N_ELEMENTS (debug_keys);

    if (flags_string)
        seafile_debug_set_flags (
            g_parse_debug_string (flags_string, debug_keys, nkeys));
}

void
seafile_debug_impl (SeafileDebugFlags flag, const gchar *format, ...)
{
    if (flag & debug_flags) {
        va_list args;
        va_start (args, format);
        g_logv (G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG, format, args);
        va_end (args);
    }
}
