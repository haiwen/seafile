#include <windows.h>

#define S_WINDOW_NAME "seafile-applet"

/* UINT __stdcall TerminateSeafile(MSIHANDLE hModule) */
UINT __stdcall TerminateSeafile(HANDLE hModule)
{
    HWND hWnd = FindWindow(S_WINDOW_NAME, S_WINDOW_NAME);
    if (hWnd)
    {
        PostMessage(hWnd, WM_CLOSE, (WPARAM)NULL, (LPARAM)NULL);
        int i;
        for (i = 0; i < 10; ++i)
        {
            Sleep(500);
            if (!IsWindow(hWnd))
            {
                /* seafile-applet is now killed. */
                return ERROR_SUCCESS;
            }
        }
        return ERROR_SUCCESS;
    }
    
    /* seafile-applet is not running. */
    return ERROR_SUCCESS;
}

/* Remove auto start entry for seafile when uninstall. Error is ignored. */
UINT __stdcall RemoveSeafileAutoStart(HANDLE hModule)
{
    const char *key_run = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char *appname = "Seafile";
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_CURRENT_USER,
                               key_run,
                               0L,KEY_WRITE | KEY_READ,
                               &hKey);
    if (result != ERROR_SUCCESS) {
        goto out;
    }

    result = RegDeleteValue (hKey, appname);
    RegCloseKey(hKey);

out:
    return ERROR_SUCCESS;
}
