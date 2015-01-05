#ifndef SEAFILE_FILESERVER_CONFIG_H
#define SEAFILE_FILESERVER_CONFIG_H

struct GKeyFile;

int
fileserver_config_get_integer(GKeyFile *config, char *key, GError **error);

char *
fileserver_config_get_string(GKeyFile *config, char *key, GError **error);

gboolean
fileserver_config_get_boolean(GKeyFile *config, char *key, GError **error);

#endif // SEAFILE_FILESERVER_CONFIG_H
