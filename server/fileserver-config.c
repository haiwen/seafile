#include "common.h"

#include <glib.h>

#include "fileserver-config.h"

const char *OLD_GROUP_NAME = "httpserver";
const char *GROUP_NAME = "fileserver";

static const char *
get_group_name(GKeyFile *config)
{
    return g_key_file_has_group (config, GROUP_NAME) ? GROUP_NAME : OLD_GROUP_NAME;
}

int
fileserver_config_get_integer(GKeyFile *config, char *key, GError **error)
{
    const char *group = get_group_name(config);
    return g_key_file_get_integer (config, group, key, error);
}

char *
fileserver_config_get_string(GKeyFile *config, char *key, GError **error)
{
    const char *group = get_group_name(config);
    return g_key_file_get_string (config, group, key, error);
}

gboolean
fileserver_config_get_boolean(GKeyFile *config, char *key, GError **error)
{
    const char *group = get_group_name(config);
    return g_key_file_get_boolean (config, group, key, error);
}
