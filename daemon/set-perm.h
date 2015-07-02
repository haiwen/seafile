#ifndef SEAF_SET_PERM_H
#define SEAF_SET_PERM_H

enum SeafPathPerm {
    SEAF_PATH_PERM_UNKNOWN = 0,
    SEAF_PATH_PERM_RO,
    SEAF_PATH_PERM_RW,
};
typedef enum SeafPathPerm SeafPathPerm;

int
seaf_set_path_permission (const char *path, SeafPathPerm perm, gboolean recursive);

int
seaf_unset_path_permission (const char *path, gboolean recursive);

SeafPathPerm
seaf_get_path_permission (const char *path);

#endif
