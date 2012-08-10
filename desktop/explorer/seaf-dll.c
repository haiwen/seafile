/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "platform.h"

#include <shlobj.h>
#include <psapi.h>

#include "seaf-dll.h"
#include "seaf-utils.h"
#include "seaf-factory.h"
#include "registry.h"
#include "seaf-ext-log.h"
#include "menu-engine.h"

const char *program_name = "Seafile";
const char *program_version = "Seafile.Application.1";
const char *program_id = "Seafile.Application";

volatile long object_count;
volatile long lock_count;

HINSTANCE dll_hInst;

HRESULT PASCAL
DllGetClassObject (REFCLSID obj_guid,
                   REFIID factory_guid,
                   void **factory_handle)
{
    if (IsEqualCLSID(obj_guid, &CLSID_seaf_shell_ext)) {
        return class_factory_query_interface(&factory,
                factory_guid, factory_handle);
    }

    *factory_handle = 0;
    return CLASS_E_CLASSNOTAVAILABLE;
}

HRESULT PASCAL
DllCanUnloadNow (void)
{
    if (object_count == 0 && lock_count == 0) {
        return S_OK;
    } else {
        return S_FALSE;
    }
}

static char *whitelist[] = {
    "explorer.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "verclsid.exe",
    NULL
};

static BOOL
is_allowed_process()
{
    /* Only allow explorer and installer process to load this dll. Other process are refused, including:
     *  1. iexplore.exe
     *  2. firefox/chrome
     *  3. visual studio
     *  4. And many more ...
     */
    char buf[MAX_PATH];
    if (!GetModuleBaseName(GetCurrentProcess(), NULL, buf, sizeof(buf))) {
        seaf_ext_log ("Failed to GetModuleBaseName(), GLE=%lu",
                      GetLastError());
        return FALSE;
    }

    seaf_ext_log ("checking for %s", buf);

    char **ptr = whitelist;
    while (*ptr) {
        char *name = *ptr;
        if (strcasecmp(name, buf) == 0)
            return TRUE;
        ptr++;
    }

    return FALSE;
}

BOOL WINAPI
DllMain (HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    dll_hInst = instance;

    if (reason == DLL_PROCESS_ATTACH) {

        object_count = lock_count = 0;
        DisableThreadLibraryCalls(instance);

        seaf_ext_log ("DllMain() called for ATTACH");

        if (!is_allowed_process()) {
            return FALSE;
        }

        /* init mutex */
        if(!seaf_ext_mutex_init()) {
            seaf_ext_log ("DllMain() failed because mutex init failed.");
            seaf_ext_log_stop ();
            return FALSE;
        }

        seaf_ext_pipe_prepare();
        /* calc menu icons path according to user's installation path */
        translate_icon_paths();

    } else if (reason == DLL_PROCESS_DETACH) {
        seaf_ext_log ("DllMain() called for DETACH");
        seaf_ext_log_stop ();
    }

    return TRUE;
}

/* replaces a substring pattern with a string replacement within a string
   the replacement occurs in-place, hence string must be large enough to
   hold the result

   the function does not handle recursive replacements, e.g.
     strreplace ("foo", "bar", "another bar");

   always returns *string
*/
static char *
strreplace(char *string, const size_t size,
           const char *pattern, const char *replacement)
{
    size_t len = strlen(string);
    const size_t pattern_len = strlen(pattern);
    const size_t replace_len = strlen(replacement);

    char *found = strstr(string, pattern);

    while (found) {
        /* if the new len is greater than size, bail out */
        if (len + replace_len - pattern_len >= size)
            return string;

        if (pattern_len != replace_len)
            memmove(found + replace_len,
                    found + pattern_len,
                len - (found - string) - pattern_len + 1);
        memcpy(found, replacement, replace_len);
        len += replace_len - pattern_len;

        found = strstr(string, pattern);
    }

    return string;
}

/*
 * The following is the data for our minimal regedit engine,
 * required for registration/unregistration of the extension
 */
#define CLASS_SEAFILE CLASSES_ROOT "CLSID\\@@CLSID@@"

#define CONTEXTMENUHANDLER "shellex\\ContextMenuHandlers\\@@PROGRAM_NAME@@"

#define SHELL_ICON_OVERLAY                                              \
    CURRENT_WINDOWS "Explorer\\ShellIconOverlayIdentifiers\\000@@PROGRAM_NAME@@"

#define AUTO_START CURRENT_WINDOWS "Run"

/* as per "How to: Convert Between System::Guid and _GUID" */
static const char *
get_class_id()
{
    static char class_id[MAX_REGISTRY_PATH] = { '\0' };

    if (!*class_id) {
        GUID guid = CLSID_seaf_shell_ext;
        sprintf(class_id,
                "{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
                (unsigned int)guid.Data1, guid.Data2, guid.Data3,
                guid.Data4[0], guid.Data4[1], guid.Data4[2],
                guid.Data4[3], guid.Data4[4], guid.Data4[5],
                guid.Data4[6], guid.Data4[7]);
    }

    return class_id;
}

/* context menu handler can be registered in HKEY_CURRENT_USER */
static const reg_value machine_registry_info[] = {
    { CURRENT_WINDOWS APPROVED_EXT, "@@CLSID@@", "@@PROGRAM_NAME@@" },
    { CURRENT_WINDOWS APPROVED_EXT "\\@@CLSID@@", NULL, NULL },
    { CURRENT_WINDOWS APPROVED_EXT "\\@@CLSID@@", NULL,"@@PROGRAM_NAME@@" },

    { CLASS_SEAFILE, NULL, NULL },
    { CLASS_SEAFILE, NULL, "@@PROGRAM_NAME@@" },
    { CLASS_SEAFILE "\\InProcServer32", NULL, NULL },
    { CLASS_SEAFILE "\\InProcServer32", NULL, "@@PROGRAM_PATH@@"},
    { CLASS_SEAFILE "\\InProcServer32", "ThreadingModel", "Apartment" },

    /* Menu extension */
    { CLASSES_ROOT "Directory\\" CONTEXTMENUHANDLER, NULL, NULL },
    { CLASSES_ROOT "Directory\\" CONTEXTMENUHANDLER, NULL, "@@CLSID@@" },
    { CLASSES_ROOT "Directory\\Background\\" CONTEXTMENUHANDLER, NULL, NULL },
    { CLASSES_ROOT "Directory\\Background\\" CONTEXTMENUHANDLER, NULL, "@@CLSID@@" },
    { CLASSES_ROOT "Folder\\" CONTEXTMENUHANDLER, NULL, NULL },
    { CLASSES_ROOT "Folder\\" CONTEXTMENUHANDLER, NULL, "@@CLSID@@" },

    /* Icon extension */
    { SHELL_ICON_OVERLAY, NULL, NULL },
    { SHELL_ICON_OVERLAY, NULL, "@@CLSID@@" },

    { NULL, NULL, NULL }
};

/* Auto start info */
static const reg_value auto_start_registry_info[] = {
    { AUTO_START, "@@PROGRAM_NAME@@", "@@APPLET_PATH@@" },
    { NULL, NULL, NULL }
};

/*
 * required by registry.c
 * supports @@PROGRAM_NAME@@, @@PROGRAM_PATH@@, @@CLSID@@ patterns
 */
char *
get_registry_path(const char *src, char dst[MAX_REGISTRY_PATH])
{
    if (NULL == src)
        return NULL;

    strcpy(dst, src);

    strreplace(dst, MAX_REGISTRY_PATH,
               "@@PROGRAM_NAME@@", program_name);

    strreplace(dst, MAX_REGISTRY_PATH,
               "@@PROGRAM_PATH@@", get_this_dll_filename());

    strreplace(dst, MAX_REGISTRY_PATH,
               "@@CLSID@@", get_class_id());

    char applet_path[MAX_PATH] = {0};
    snprintf (applet_path, sizeof(applet_path), "\"%s%s\"",
              get_this_dll_folder(), "seafile-applet.exe");

    char *p;
    for (p = applet_path; *p != '\0'; p++) {
        if (*p == '/')
            *p = '\\';
    }
    
    strreplace(dst, MAX_REGISTRY_PATH,
               "@@APPLET_PATH@@", applet_path);

    return dst;
}

HRESULT PASCAL
DllInstall(BOOL bInstall, LPCWSTR pszCmdLine)
{
    if (bInstall) {

        create_reg_entries(HKEY_LOCAL_MACHINE, machine_registry_info);
        create_reg_entries(HKEY_CURRENT_USER, auto_start_registry_info);

        kill_process("explorer.exe");
        Sleep(5000);

    } else {
        delete_reg_entries(HKEY_LOCAL_MACHINE, machine_registry_info);
        delete_reg_entries(HKEY_CURRENT_USER, auto_start_registry_info);
    }

    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST,NULL,NULL);
    return S_OK;
}

HRESULT PASCAL
DllRegisterServer(void)
{
    return DllInstall(TRUE, NULL);
}

HRESULT PASCAL
DllUnregisterServer(void)
{
    return DllInstall(FALSE, NULL);
}

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
