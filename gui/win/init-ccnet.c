/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <ccnet.h>

#include "stdafx.h"
#include "resource.h"
#include "applet-po-gbk.h"
#include "trayicon.h"
#include <commdlg.h>
#include <ShlObj.h>
#include <shlwapi.h>

#include "utils.h"
#include "ccnet-init.h"

#include "rpc-wrapper.h"
#include "seafile-applet.h"
#include "applet-log.h"

#define INIT_CCNET_SUCCESS  0
#define INIT_CCNET_FAILED   -1

#define IS_DLG_CONTROL(ID)   ((HWND)(lParam) == GetDlgItem(hDlg, (ID)))

static const char *error_str[] =
{
    S_UNKNOWN_ERR,
    S_PERMISSION_ERROR,
    S_CREATE_CONF_FAILED,
    S_CREATE_SEAFILE_CONF_FAILED,
};

static const char *
error_code_to_str (const int code)
{
    if (code <= 0 || code >= ERR_MAX_NUM)
        return S_UNKNOWN_ERR;

    return error_str[code];
}

BOOL
msgbox_yes_or_no (HWND hWnd, char *format, ...)
{
    va_list params;
    char buf[2048];

    va_start(params, format);
    vsnprintf(buf, sizeof(buf), format, params);
    va_end(params);

    int res = MessageBox(hWnd, buf, "Seafile", MB_ICONQUESTION | MB_YESNO);

    return (res == IDYES);
}

void
make_wnd_foreground (HWND hwndDlg)
{
    /* Center the window */

    // Get the owner window and dialog box rectangles.

    HWND hwndOwner;
    RECT rc, rcDlg, rcOwner;
    if ((hwndOwner = GetParent(hwndDlg)) == NULL) {
        hwndOwner = GetDesktopWindow();
    }

    if (hwndOwner == applet->hWnd) {
        hwndOwner = GetDesktopWindow();
    }

    GetWindowRect(hwndOwner, &rcOwner);
    GetWindowRect(hwndDlg, &rcDlg);
    CopyRect(&rc, &rcOwner);

    // Offset the owner and dialog box rectangles so that right and bottom
    // values represent the width and height, and then offset the owner again
    // to discard space taken up by the dialog box.

    OffsetRect(&rcDlg, -rcDlg.left, -rcDlg.top);
    OffsetRect(&rc, -rc.left, -rc.top);
    OffsetRect(&rc, -rcDlg.right, -rcDlg.bottom);

    // The new position is the sum of half the remaining space and the owner's
    // original position.

    SetWindowPos(hwndDlg,
                 HWND_TOP,
                 rcOwner.left + (rc.right / 2),
                 rcOwner.top + (rc.bottom / 2),
                 0, 0,          // Ignores size arguments.
                 SWP_NOSIZE);


    ShowWindow (hwndDlg,  SW_SHOWNORMAL );
    SetWindowPos (hwndDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOSIZE|SWP_NOMOVE);
    SetWindowPos (hwndDlg, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOSIZE|SWP_NOMOVE);
    SetForegroundWindow (hwndDlg);
}

void
set_control_font (HWND hControl, char *font)
{
    HFONT hFont;
 
    hFont = CreateFont(12,
                       0,
                       0,
                       0,
                       FW_BOLD,
                       0,
                       0,
                       0,
                       GB2312_CHARSET,
                       OUT_DEFAULT_PRECIS,
                       CLIP_DEFAULT_PRECIS,
                       DEFAULT_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE,
                       NULL);

    SendMessage (hControl, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(1,0));
    DeleteObject(hFont);
}

void set_dlg_icon(HWND hDlg, UINT icon_id)
{
    static HICON hIcon = NULL;
    if (!hIcon) {
        hIcon = LoadIcon (applet->hInstance,
                          MAKEINTRESOURCE(icon_id));
    }
    SendMessage(hDlg, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    SendMessage(hDlg, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
}

static BOOL first_use = FALSE;

static void
InitComboxList(HWND hDlg)
{
    HWND hwndGroupsBox = GetDlgItem(hDlg, IDC_COMBOX_DISK);
    char drivers[MAX_PATH];
    char *p;
    ULARGE_INTEGER free_space;
    ULARGE_INTEGER largest_free_space;
    int i = 0;
    int largest_disk_index = 0;

    largest_free_space.QuadPart = 0;

    GetLogicalDriveStrings (sizeof(drivers), drivers);
    SendMessage(hwndGroupsBox, CB_RESETCONTENT, 0, 0);
    for (p = drivers; *p; p+=strlen(p)+1) {
        /* Skip floppy disk, network drive, etc */
        if (GetDriveType(p) != DRIVE_FIXED)
            continue;

        if (GetDiskFreeSpaceEx (p, &free_space, NULL, NULL)) {
            if (free_space.QuadPart > largest_free_space.QuadPart) {
                largest_free_space.QuadPart = free_space.QuadPart;
                largest_disk_index = i;
            }
        } else {
            free_space.QuadPart = 0;
            applet_warning ("failed to GetDiskFreeSpaceEx(), GLE=%lu\n",
                            GetLastError());
        }

        char buf[128];

        if (free_space.QuadPart) {
            double d = ((double)(free_space.QuadPart)) / (1024 * 1024 * 1024);
            snprintf (buf, sizeof(buf), "%s\t   (%.1f GB " S_AVAILABLE ")",
                      p, d);
        } else
            snprintf (buf, sizeof(buf), "%s\t   (" S_AVAILABLE_UNKNOWN ")", p);

        i++;

        SendMessage(hwndGroupsBox, CB_ADDSTRING, 0, (LPARAM) buf);
    }

    SendDlgItemMessage(hDlg, IDC_COMBOX_DISK, CB_SETCURSEL,
                       largest_disk_index, 0);
}

extern char *seafile_bin_dir;

/* 1. set seafile-data directory to hidden
   2. set seafile folder icon (via Desktop.ini)
*/
static void
set_seafdir_attributes ()
{
    char *seafdir = g_path_get_dirname (applet->seafile_dir);
    char *icon_path = NULL;
    char *locale_icon_path = NULL;
    char *ini_file_path = NULL;

    FILE *ini_file = NULL;

    /* Make seafile-data directory hidden. */
    SetFileAttributes(applet->seafile_dir,
                      FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

    /* Set seafdir folder icon. */
    SetFileAttributes(seafdir, FILE_ATTRIBUTE_SYSTEM);
    ini_file_path = g_build_filename (seafdir, "Desktop.ini", NULL);

    if (!(ini_file = g_fopen(ini_file_path, "w"))) {
        applet_warning ("failed to open %s\n", ini_file_path);
        goto out;
    }

    icon_path = g_build_filename (seafile_bin_dir, "seafdir.ico", NULL);

    /* Replace all / with \ */
    char *ptr = icon_path;
    while (*ptr != '\0') {
        if (*ptr == '/')
            *ptr = '\\'; 

        ptr++;
    }

    locale_icon_path = ccnet_locale_from_utf8 (icon_path);
        
    fputs   ("[.ShellClassInfo]\n", ini_file);
    fprintf (ini_file, "IconFile=%s\n", locale_icon_path);
    fputs   ("IconIndex=0\n", ini_file);

    /* Make the "Desktop.ini" file hidden. */
    SetFileAttributes(ini_file_path,
                      FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);

out:
    g_free (seafdir);

    g_free (ini_file_path);
    if (ini_file)
        fclose (ini_file);
    g_free (icon_path);
    g_free (locale_icon_path);

}

extern char *seafile_bin_dir;

/* Copy manual from install dir to Seafile directory */
void
copy_user_manual()
{
    char installdir[MAX_PATH];
    char *seafdir;              /* like C:\\Seafile */
    char src_path[MAX_PATH];
    char dst_path[MAX_PATH];

    g_strlcpy(installdir, seafile_bin_dir, sizeof(installdir));
    PathRemoveBackslash(installdir);
    PathRemoveFileSpec(installdir);

    seafdir = g_path_get_dirname (applet->seafile_dir);
    PathRemoveBackslash(seafdir);

    snprintf (src_path, sizeof(src_path),
              "%s\\%s", installdir, S_USER_MANUAL_FILENAME);

    snprintf (dst_path, sizeof(dst_path),
              "%s\\%s", seafdir, S_USER_MANUAL_FILENAME);
    
    /* Skip if already exist */
    /* Ver1.1: Manual Changed. We need to overwrite it. */
    BOOL failIfExist = FALSE;
    CopyFile(src_path, dst_path, failIfExist);

    g_free (seafdir);
}

static BOOL CALLBACK
InitSeafileProc (HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    int len;
    char seafiledir[MAX_PATH];

    memset(seafiledir, 0, sizeof(seafiledir));

    switch (message) {
    case WM_CREATE:
        break;

    case WM_INITDIALOG:
        InitComboxList(hDlg);
        set_dlg_icon (hDlg, IDI_STATUS_UP);
        SetWindowText (GetDlgItem(hDlg, IDC_STATIC_TITLE), S_INIT_DISK);
        set_control_font (GetDlgItem(hDlg, IDC_STATIC_TITLE), S_BOLD_FONT);
        make_wnd_foreground(hDlg);
        return TRUE;
        break;

        
    case WM_CTLCOLORSTATIC:
        if (IS_DLG_CONTROL (IDC_STATIC_TITLE)) {

            SetBkMode((HDC)wParam, TRANSPARENT);
            return (BOOL)GetStockObject(NULL_BRUSH);
        }
        break;

    case WM_COMMAND:
        switch(LOWORD(wParam)) {
        case IDOK: {
            len = GetWindowText (GetDlgItem(hDlg,IDC_COMBOX_DISK),
                                 seafiledir, sizeof(seafiledir));
            seafiledir[len] = '\0';
            int i = 0;
            while (seafiledir[i] != '\t')
                i++;

            seafiledir[i] = '\0';

            applet->seafile_dir = g_build_filename(seafiledir,
                                                   "Seafile",
                                                   "seafile-data", NULL);

            if (checkdir_with_mkdir(applet->seafile_dir) < 0) {
                g_free (applet->seafile_dir);
                applet->seafile_dir = NULL;
                EndDialog (hDlg, INIT_CCNET_FAILED);
                return TRUE;
            }

            set_seafdir_attributes ();
            EndDialog (hDlg, INIT_CCNET_SUCCESS);
            return TRUE;
        }

        case IDCANCEL:
            if (msgbox_yes_or_no (hDlg, S_ENSURE_QUIT_INIT)) {
                EndDialog (hDlg, INIT_CCNET_FAILED);
            }
            return TRUE;
        default:
            break;
        }
        break;

    case WM_CLOSE:
        if (msgbox_yes_or_no (hDlg, S_ENSURE_QUIT_INIT)) {
            EndDialog (hDlg, INIT_CCNET_FAILED);
        }
        return TRUE;

    default:
        break;
    }
    return 0;
}

int
show_init_seafile_window ()
{
    int response;

    first_use = TRUE;

    response = DialogBox (applet->hInstance,
                          MAKEINTRESOURCE(IDD_INIT_SEAFILE),
                          applet->hWnd, InitSeafileProc);
    if (response != INIT_CCNET_SUCCESS) {
        return -1;
    }

    return 0;
}

static inline void
open_browser(const char *url)
{
    ShellExecute(NULL, "open", url, NULL, NULL, SW_SHOWNORMAL);
}

static BOOL CALLBACK
Win7TipProc (HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch(message) {
    case WM_INITDIALOG:
        set_dlg_icon (hDlg, IDI_STATUS_UP);
        make_wnd_foreground (hDlg);
        break;

    case WM_COMMAND:
        if (LOWORD(wParam) == ID_FINISH) {
            EndDialog (hDlg,0);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        EndDialog (hDlg,0);
        return TRUE;
        break;

    case WM_DESTROY:
        break;

    default:
        break;
    }

    return FALSE;
}

static BOOL
is_windows_seven ()
{
    OSVERSIONINFOEX ver = {0};

    ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

    if (!GetVersionEx((LPOSVERSIONINFO)&ver)) {
        applet_warning ("GetVersionEx failed, GLE=%lu\n", GetLastError());
        return TRUE;
    }

    /* tell if seafile is running on Windows 7 */
    if (ver.dwMajorVersion == 6
        && ver.dwMinorVersion == 1
        && ver.wProductType == VER_NT_WORKSTATION) {
        return TRUE;
    }

    return FALSE;
}

void prompt_win7_tip_if_necessary ()
{
    if (!is_windows_seven () || !first_use)
        return;

    first_use = FALSE;

    DialogBox (applet->hInstance,
               MAKEINTRESOURCE(IDD_WIN7_TIP),
               applet->hWnd, Win7TipProc);
}
