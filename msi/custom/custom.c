#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <string.h>

#ifndef KEY_WOW64_64KEY
#define KEY_WOW64_64KEY 0x0100
#endif

#ifndef KEY_WOW64_32KEY
#define KEY_WOW64_32KEY 0x0200
#endif

#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define AT __FILE__ ":" TOSTRING(__LINE__)

void msgbox(const char *msg)
{
    MessageBox(NULL, msg, "Seafile Custom", MB_OK);
}

BOOL readRegValue(HKEY root, const char *subkey, const char *name, char **value)
{
    HKEY hKey;
    char *buf = NULL;
    BOOL ret = FALSE;
    LONG result = RegOpenKeyEx(root,
                               subkey,
                               0L,
                               // KEY_READ | KEY_WOW64_64KEY,
                               KEY_READ,
                               &hKey);
    if (result != ERROR_SUCCESS) {
        msgbox("here: " AT);
        goto out;
    }

    DWORD len, type;
    result = RegQueryValueEx(hKey,
                             name,
                             NULL,  // reserved
                             &type, // type
                             NULL,  // data
                             &len); // size
    if (result != ERROR_SUCCESS || type != REG_SZ) {
        msgbox("here: " AT);
        char buf[128];
        snprintf(buf, sizeof(buf), "len is %lu", len);
        msgbox(buf);
        goto out;
    }

    buf = malloc (len + 1);
    buf[len] = 0;
    result = RegQueryValueEx(hKey,
                             name,
                             NULL,          // reserved
                             NULL,          // type
                             (LPBYTE) buf,  // data
                             &len);         // size
    if (result != ERROR_SUCCESS) {
        msgbox("here: " AT);
        char buf[128];
        snprintf(buf, sizeof(buf), "error code %lu", result);
        msgbox(buf);
        goto out;
    }

    *value = buf;
    ret = TRUE;

out:
    RegCloseKey(hKey);
    return ret;
}


/* Remove auto start entry for seafile when uninstall. Error is ignored. */
UINT __stdcall RemoveExtDll(HANDLE hModule)
{
    const char *dll_path_key = "SOFTWARE\\Classes\\CLSID\\{D14BEDD3-4E05-4F2F-B0DE-C0381E6AE606}\\InProcServer32";
    char *path = NULL;
    if (!readRegValue(HKEY_LOCAL_MACHINE, dll_path_key, "", &path)) {
        msgbox("failed to read registry value");
        return ERROR_SUCCESS;
    }

    if (!path) {
        msgbox("path is null");
        return ERROR_SUCCESS;
    }

    int n = strlen(path);
    char *path2 = malloc (n + 3);
    memcpy (path2, path, strlen(path));
    path2[n] = '.';
    path2[n + 1] = '1';
    path2[n + 2] = 0;

    if (MoveFileEx(path, path2, MOVEFILE_REPLACE_EXISTING) == 0) {
        char buf[128];
        snprintf(buf, sizeof(buf), "MoveFileEx error is %lu", GetLastError());
        msgbox(buf);
    } else {
        msgbox("MoveFileEx success");
    }

    free(path);
    free(path2);

    return ERROR_SUCCESS;
}
