/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <stdlib.h>

#include <ccnet/processor.h>
#include <utils.h>
#include "opendir-proc.h"
#include "seafile-applet.h"


G_DEFINE_TYPE (CcnetOpendirProc, ccnet_opendir_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{

    CCNET_PROCESSOR_CLASS (ccnet_opendir_proc_parent_class)->release_resource (processor);
}


static void
ccnet_opendir_proc_class_init (CcnetOpendirProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
    proc_class->name = "opendir-proc";
}

static void
ccnet_opendir_proc_init (CcnetOpendirProc *processor)
{
}

static void
strnjoin (int n, char **strs, GString *buf)
{
    int i;

    if (n == 0)
        return;

    g_string_append (buf, strs[0]);

    for (i = 1; i < n; i++) {
        g_string_append (buf, " ");
        g_string_append (buf, strs[i]);
    }
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char *path;
    GString *str;
    if (argc < 1) {
        ccnet_processor_send_response (processor, "401", "Bad arguments",
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    str = g_string_new("");
    strnjoin(argc, argv, str);
    path = str->str;
    if (checkdir (path) < 0) {
        ccnet_processor_send_response (processor, "402", "No such directory",
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
        g_string_free(str, TRUE);
        return -1;
    }

    ccnet_open_dir (path);

    ccnet_processor_send_response (processor, "200", "OK", NULL, 0);
    ccnet_processor_done (processor, TRUE);
    g_string_free(str, TRUE);

    return 0;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{

}
