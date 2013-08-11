/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <ccnet.h>
#include "seafile-session.h"
#include "putcs-v2-proc.h"

G_DEFINE_TYPE (SeafilePutcsV2Proc, seafile_putcs_v2_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_putcs_v2_proc_parent_class)->release_resource (processor);
}


static void
seafile_putcs_v2_proc_class_init (SeafilePutcsV2ProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "putcs-v2-proc";
    proc_class->start = start;
    proc_class->release_resource = release_resource;
}

static void
seafile_putcs_v2_proc_init (SeafilePutcsV2Proc *processor)
{
}

static char *
hostname_from_service_url (const char *service_url)
{
    const char *start, *end;

    start = strstr (service_url, "//");
    if (!start)
        start = service_url;
    else
        start += 2;

    end = strchr (start, ':');
    if (end)
        return g_strndup (start, end - start);

    end = strchr (start, '/');
    if (!end)
        return g_strdup (start);
    else
        return g_strndup (start, end - start);
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char *hostname;
    GString *buf = g_string_new("");

    hostname = hostname_from_service_url (seaf->session->base.service_url);
    g_string_printf (buf, "%s:%d\n", hostname, seaf->listen_mgr->port);
    g_free (hostname);

    ccnet_processor_send_response (processor, SC_OK, SS_OK, buf->str, buf->len+1);
    g_string_free (buf, TRUE);
    
    ccnet_processor_done (processor, TRUE);

    return 0;
}
