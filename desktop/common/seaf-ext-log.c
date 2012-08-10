/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "platform.h"

#include <time.h>
#include <stdarg.h>

#include "seaf-ext-log.h"
#include "seaf-utils.h"
#include "strbuf.h"


static FILE *log_fp;

static char *
get_log_path()
{
    const char *home = get_home_dir();
    if (!home)
        return NULL;

    struct strbuf sb = STRBUF_INIT;
    strbuf_addf (&sb, "%s/seafile_extension.log", home);

    return strbuf_detach(&sb, NULL);
}

void
seaf_ext_log_start ()
{
    if (log_fp)
        return;

    static char *log_path;
    if (!log_path)
        log_path = get_log_path();

    if (log_path)
        log_fp = fopen (log_path, "a");

    if (log_fp) {
        seaf_ext_log ("\n----------------------------------\n"
                      "log file initialized, %s"
                      "\n----------------------------------\n"
                      , log_path);
    } else {
        fprintf (stderr, "[LOG] Can't init log file, %s\n", log_path);
    }
}

void
seaf_ext_log_stop ()
{
    if (log_fp) {
        fclose (log_fp);
        log_fp = NULL;
    }
}

inline void
seaf_ext_log_aux (char *format, ... )
{
    if (!log_fp)
        seaf_ext_log_start();

    if (log_fp) {
        va_list params;
        char buffer[1024];
        int length = 0;
        
        va_start(params, format);
        length = vsnprintf(buffer, sizeof(buffer), format, params);
        va_end(params);
        
        /* Write the timestamp. */
        time_t t;
        struct tm *tm;
        char buf[256];
        
        t = time(NULL);
        tm = localtime(&t);
        strftime (buf, 256, "[%y/%m/%d %H:%M:%S] ", tm);

        fputs (buf, log_fp);
        if (fwrite(buffer, sizeof(char), length, log_fp) < length)
            return;

        fputc('\n', log_fp);
        fflush(log_fp);
    }
}
