/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "platform.h"
#include "registry.h"

/* uses get_registry_path to replace patterns */
HRESULT create_reg_entries(const HKEY root, reg_value const info[])
{
    HRESULT result;
    int i;

    for (i = 0; NULL != info[i].path; ++i) {
        char path[MAX_REGISTRY_PATH];
        char name[MAX_REGISTRY_PATH], *regname = NULL;
        char value [MAX_REGISTRY_PATH], *regvalue = NULL;

        HKEY key;
        DWORD disp;

        get_registry_path(info[i].path, path);
        result = RegCreateKeyEx(root, path,
            0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_WOW64_64KEY, NULL,
            &key, &disp);
        if (ERROR_SUCCESS != result)
            return (result);

        regname = get_registry_path(info[i].name, name);
        regvalue = get_registry_path(info[i].value, value);

        /*
         * regname can legitimately be NULL,
         * but if value is NULL, it's just a key
         */
        if (NULL != regvalue) {
            char *endptr;
            DWORD dwValue = strtoul(regvalue, &endptr, 10);
            if (endptr && !*endptr)
                result = RegSetValueEx(key, regname, 0,
                        REG_DWORD,
                        (LPBYTE)&dwValue,
                        sizeof(dwValue));
            else
                result = RegSetValueEx(key, regname, 0,
                        REG_SZ,
                        (LPBYTE)regvalue,
                        (DWORD)strlen(regvalue));
        }

        RegCloseKey(key);
        if (ERROR_SUCCESS != result)
            return (result);
    }

    return ERROR_SUCCESS;
}

static inline HRESULT mask_errors(HRESULT const result)
{
    switch (result) {
        case ERROR_FILE_NOT_FOUND: return ERROR_SUCCESS;
    }

    return result;
}

HRESULT delete_reg_entries(HKEY const root, reg_value const info[])
{
    HRESULT result;
    int i = 0;

    /* count items in the array */
    while (NULL != info[i].path)
        i++;

    /* walk the array backwards (we're at the terminating triple-null) */
    while (--i >= 0) {
        char path[MAX_REGISTRY_PATH];
        HKEY key;
        
        get_registry_path(info[i].path, path);
        
        if (info[i].name || info[i].value) {
            /* delete the value */

            char name[MAX_REGISTRY_PATH], *regname = NULL;

            result = mask_errors(RegOpenKeyEx(root, path,
                    0, KEY_WRITE | KEY_WOW64_64KEY, &key));
            if (ERROR_SUCCESS != result)
                return result;

            /*
             * some of our errors are masked (e.g. not found)
             * don't work on this key if we could not open it
             */
            if (NULL == key)
                continue;

            regname = get_registry_path(info[i].name, name);
            result = mask_errors(RegDeleteValue(key, regname));

            RegCloseKey(key);
        } else /* not the value, delete the key */
            result = mask_errors(RegDeleteKey(root, path));

        if (ERROR_SUCCESS != result)
            return (result);
    } 

    return ERROR_SUCCESS;
}
