#include "applet-log.h"

#include "utils.h"
#include <errno.h>
#include <time.h>
#include <glib/gstdio.h>

static FILE *logfp;

static GLogLevelFlags applet_log_level;

static void
applet_log (const gchar *log_domain, GLogLevelFlags log_level,
            const gchar *message, gpointer user_data)
{
    if (log_level > applet_log_level)
        return;

    if (log_level & G_LOG_FLAG_FATAL)
        fputs (message, stderr);

    time_t t;
    struct tm *tm;
    char buf[1024];
    size_t len;

    if (log_level > applet_log_level)
        return;

    t = time(NULL);
    tm = localtime(&t);
    len = strftime (buf, 1024, "[%x %X] ", tm);
    g_return_if_fail (len < 1024);
    fputs (buf, logfp);
    fputs (message, logfp);
    fflush (logfp);
}

int
applet_log_init (const char *config_dir)
{
    char *logdir = g_build_filename (config_dir, "logs", NULL);
    char *logfile = g_build_filename(logdir, "applet.log", NULL);

    checkdir_with_mkdir (logdir);
    g_free (logdir);

    g_log_set_handler (NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
                       | G_LOG_FLAG_RECURSION, applet_log, NULL);

    g_log_set_handler ("Ccnet", G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
                       | G_LOG_FLAG_RECURSION, applet_log, NULL);
    
    /* record all log message */
    applet_log_level = G_LOG_LEVEL_DEBUG;

    char *file = ccnet_expand_path (logfile);
    g_free (logfile);

#ifdef DEBUG
    logfp = stderr;
#else
    if ((logfp = (FILE *)(long)g_fopen (file, "a+")) == NULL) {
        applet_warning ("Open file %s failed errno=%d\n", file, errno);
        g_free (file);
        return -1;
    }
#endif
    g_free (file);

    return 0;
}
