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
