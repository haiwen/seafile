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

#include "utils.h"
#include "ccnet-init.h"

#include "rpc-wrapper.h"
#include "seafile-applet.h"
#include "applet-log.h"

#define SEAHUB_OFFICIAL_REGISTER_ADDR "http://cloud.seafile.com.cn/accounts/register"

#define INIT_CCNET_SUCCESS  0
#define INIT_CCNET_FAILED   -1

#define ENABLE_CONTROL(name) EnableWindow (GetDlgItem(hDlg, (name)), TRUE)
#define DISABLE_CONTROL(name) EnableWindow (GetDlgItem(hDlg, (name)), FALSE)
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

    icon_path = g_build_filename (seafile_bin_dir, "icons",
                                  "seafdir.ico", NULL);

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

static void
open_seahub_reg_page()
{
    open_browser(SEAHUB_OFFICIAL_REGISTER_ADDR);
}

/**
               relay connected and send username/passwd
   LOGIN_INIT -------------------------------------------> LOGIN_SENT

                 SUCCESS                LOGIN_SUCCESSFUL
   LOGIN_SENT --------------------->
                 FAIL                   LOGIN_INIT

   LOGIN_SUCCESSFUL ---------------->   END

 */

static BOOL CALLBACK
SeahubLoginProc (HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    int len;
    static char username[32] = {0};
    static char passwd[32] = {0};

    if (message == WM_INITDIALOG) {
        applet->login_status = LOGIN_INIT;

        SetWindowText (GetDlgItem(hDlg, IDC_STATIC_LOGIN_INFO), "");
        SetWindowText (GetDlgItem(hDlg, IDC_STATIC_TITLE), S_INIT_LOGIN);
        set_control_font (GetDlgItem(hDlg, IDC_STATIC_TITLE), S_BOLD_FONT);
        set_dlg_icon (hDlg, IDI_STATUS_UP);
        make_wnd_foreground(hDlg);

        /* Set input focus to username filed. */
        if (GetDlgCtrlID((HWND) wParam) != IDC_EDIT_SEAHUB_USERNAME) {
            SetFocus(GetDlgItem(hDlg, IDC_EDIT_SEAHUB_USERNAME));
            return FALSE;
        }
        return TRUE;

    } else if (message == WM_CLOSE) {
        if (msgbox_yes_or_no (hDlg, S_ENSURE_QUIT_INIT)) {
            EndDialog (hDlg, INIT_CCNET_FAILED);
        }
        return TRUE;
        
    } else if (message == WM_CTLCOLORSTATIC) {
        if (IS_DLG_CONTROL (IDC_STATIC_TITLE)) {

            SetBkMode((HDC)wParam, TRANSPARENT);
            return (BOOL)GetStockObject(NULL_BRUSH);
        }

    } else if (message == WM_COMMAND) {
        WORD id = LOWORD(wParam);
        if (id == ID_LOGIN) {

            memset (username, 0, sizeof(username));
            memset (passwd, 0, sizeof(passwd));
            /* clear error msg */
            SetWindowText(GetDlgItem(hDlg, IDC_STATIC_LOGIN_INFO), "");
            len = GetWindowText (GetDlgItem(hDlg,IDC_EDIT_SEAHUB_USERNAME),
                                 username, sizeof(username));
            if (len < 3) {
                SetWindowText (GetDlgItem(hDlg, IDC_STATIC_LOGIN_INFO),
                               S_USERNAME_TOO_SHORT);
                return TRUE;
            }

            len = GetWindowText (GetDlgItem(hDlg,IDC_EDIT_SEAHUB_PASSWD),
                                 passwd, sizeof(passwd));
            if (len < 3) {
                SetWindowText (GetDlgItem(hDlg, IDC_STATIC_LOGIN_INFO),
                               S_PASSWD_TOO_SHORT);
                return TRUE;
            }

            DISABLE_CONTROL (IDC_EDIT_SEAHUB_USERNAME);
            DISABLE_CONTROL (IDC_EDIT_SEAHUB_PASSWD);
            DISABLE_CONTROL (ID_LOGIN);

            if (applet->login_status == LOGIN_INIT) {
                SetWindowText(GetDlgItem(hDlg, IDC_STATIC_LOGIN_INFO),
                              S_CONNECTING_TO_SERVER);

            } else {
                SetWindowText(GetDlgItem(hDlg, IDC_STATIC_LOGIN_INFO),
                              S_VALIDATING_USER);
                do_login_relay (username, passwd);
                applet->login_status = LOGIN_SENT;
            }

            SetTimer(hDlg, QUERY_LOGIN_TIMER_ID, 1000, NULL);

            return TRUE;

        } else if (id == ID_REGISTER) {
            open_seahub_reg_page();
            return TRUE;

        } else if (id == ID_SKIP_LOGIN) {
            if (msgbox_yes_or_no (hDlg, S_ENSURE_SKIP_LOGIN)) {
                ccnet_set_config (applet->ccnet_rpc_client, "login_finished", "true");
                EndDialog (hDlg, INIT_CCNET_SUCCESS);
            }
            return TRUE;
        }

        return FALSE;

    } else if (message == WM_TIMER) {
        int status;
        char *errmsg = NULL;

        switch (applet->login_status) {
        case LOGIN_SUCCESSFUL:
            KillTimer (hDlg, QUERY_LOGIN_TIMER_ID);
            EndDialog (hDlg, INIT_CCNET_SUCCESS);
            break;

        case LOGIN_INIT: {
            static int retry = 0;

            if (get_conn_relay_status () != 0) {
                /* not connected yet */
                /* Allow five seconds delay */
                if (++retry >= 5) {
                    errmsg = S_LOGIN_FAILED S_CONN_SERVER_TIEMOUT;
                    retry = 0;
                    goto error;
                }

            } else {
                /* relay connected */
                SetWindowText (GetDlgItem(hDlg, IDC_STATIC_LOGIN_INFO),
                               S_VALIDATING_USER);
                /* Login to relay. */
                do_login_relay (username, passwd);
                applet->login_status = LOGIN_SENT;
                retry = 0;
            }
            break;
        }

        case LOGIN_SENT: {

            status = get_login_status ();
            if (status < 0) {
                /* login error */
                applet->login_status = LOGIN_INIT;
                errmsg = S_LOGIN_FAILED S_INVALID_USER;
                goto error;

            } else if (status == 0) {
                /* login success */
                applet->login_status = LOGIN_SUCCESSFUL;
                ccnet_set_config (applet->ccnet_rpc_client, "login_finished", "true");
                /* show 'login success' for one second */
                SetWindowText (GetDlgItem(hDlg, IDC_STATIC_LOGIN_INFO),
                               S_LOGIN_SUCCESS);
                break;

            } else {
                break;
            }

            error:
            KillTimer (hDlg, QUERY_LOGIN_TIMER_ID);
            if (errmsg) {
                SetWindowText (GetDlgItem(hDlg, IDC_STATIC_LOGIN_INFO), errmsg);
            }
            ENABLE_CONTROL (IDC_EDIT_SEAHUB_USERNAME);
            ENABLE_CONTROL (IDC_EDIT_SEAHUB_PASSWD);
            ENABLE_CONTROL (ID_LOGIN);

            break;
        }

        default:
            break;
        }

        return TRUE;
    }

    return FALSE;
}

int
show_login_window ()
{
    int response;
    response = DialogBox (applet->hInstance,
                          MAKEINTRESOURCE(IDD_LOGIN),
                          applet->hWnd, SeahubLoginProc);

    if (response != INIT_CCNET_SUCCESS) {
        return -1;
    }
    return 0;
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

    DialogBox (applet->hInstance,
               MAKEINTRESOURCE(IDD_WIN7_TIP),
               applet->hWnd, Win7TipProc);
    
}
