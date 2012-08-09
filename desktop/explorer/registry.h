/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
/*
 * This is basically a simplified regedit engine that supports
 * custom patterns through get_registry_path() that is required
 * to be provided by the clients.
 *
 * It attempts to convert values to LONG to create REG_DWORD values
 */

#define MAX_REGISTRY_PATH MAX_PATH

#define CURRENT_WINDOWS "Software\\Microsoft\\Windows\\CurrentVersion\\"
#define APPROVED_EXT "Shell Extensions\\Approved"
#define CLASSES_ROOT "Software\\Classes\\"

typedef struct reg_value {
    char *path;
    char *name;
    char *value;
} reg_value;

/*
 * Clients need to provide the implementation of this function.
 * The simplest implementation includes just strcpy(dst, src);
 */
char *get_registry_path(const char *src, char dst[MAX_REGISTRY_PATH]);

HRESULT create_reg_entries(const HKEY root, reg_value const info[]);
HRESULT delete_reg_entries(HKEY const root, reg_value const info[]);
