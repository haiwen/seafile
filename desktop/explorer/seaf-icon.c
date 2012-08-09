/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/* This module implemented `IShellIconOverlayIdentifier' interface, which add
 * a special icon overlay to any top level repo folder in Explorer. */


#include "platform.h"
#include <wchar.h>
#include <unistd.h>

#include "seaf-dll.h"
#include "seaf-utils.h"
#include "seaf-ext-log.h"

#include "seaf-icon.h"

struct IShellIconOverlay_Vtbl
{
    STDMETHOD(QueryInterface)(void *, REFIID, PVOID*);
    STDMETHOD_(ULONG, AddRef)(void *);
    STDMETHOD_(ULONG, Release)(void *);
    STDMETHOD(IsMemberOf)(void *, LPCWSTR, DWORD);
    STDMETHOD(GetOverlayInfo)(void *, LPWSTR, int, int *, DWORD *);
    STDMETHOD(GetPriority)(void *, int *);

};

extern char *seaf_repo_ico;

static STDMETHODIMP
GetOverlayInfo(void *p, LPWSTR pwszIconFile, int cchMax,
               int *pIndex, DWORD *pdwFlags)
{
    if (!seaf_repo_ico) {
        seaf_ext_log ("failed to get seaf_repo_ico");
        return S_FALSE;
    }

    wchar_t *seaf_repo_ico_w = char_to_wchar(seaf_repo_ico);
    if (!seaf_repo_ico_w) {
        seaf_ext_log ("Convert seaf_repo_ico to wchar_t failed");
        return S_FALSE;
    }

    int wlen = wcslen(seaf_repo_ico_w);
    if (wlen + 1 > cchMax)
        return S_FALSE;

    wmemcpy (pwszIconFile, seaf_repo_ico_w, wlen + 1);
    free (seaf_repo_ico_w);
    *pdwFlags = ISIOI_ICONFILE;
    seaf_ext_log ("[ICON] set icon file %s", seaf_repo_ico);

    return S_OK;
}

static STDMETHODIMP
GetPriority(void *p, int *priority)
{
    /* The priority value can be 0 ~ 100, with 0 be the highest */
    *priority = 0;

    return S_OK;
}

static STDMETHODIMP
IsMemberOf(void *p, LPCWSTR path_w, DWORD attr)
{
    HRESULT ret = S_FALSE;
    char *path = wchar_to_char(path_w);

    if (!path) {
        seaf_ext_log ("convert to char failed");
        return S_FALSE;
    }

    /* If length of path is shorter than 3, it should be a drive path,
     * such as C:\ , which should not be a repo folder ; And the
     * current folder being displayed must be "My Computer". If we
     * don't return quickly, it will lag the display.
     */
    if (strlen(path) <= 3) {
        free (path);
        return S_FALSE;
    }
    
    if (access(path, F_OK) < 0 ||
        !(GetFileAttributes(path) & FILE_ATTRIBUTE_DIRECTORY)) {
        ret = S_FALSE;

    } else if (is_repo_top_dir(path)) {
        seaf_ext_log ("[ICON] Set for %s", path);
        ret =  S_OK;

    } else {
        ret =  S_FALSE;
    }

    free (path);
    return ret;
}

static ULONG STDMETHODCALLTYPE
add_ref_seaf_icon_overlay(void *p)
{
    SeafIconOverlay *seaf_icon_overlay = p;
    return ++(seaf_icon_overlay->count);
}

static ULONG STDMETHODCALLTYPE
release_seaf_icon_overlay(void *p)
{
    SeafIconOverlay *seaf_icon_overlay = p;
    --(seaf_icon_overlay->count);
    if (seaf_icon_overlay->count == 0) {

        free (seaf_icon_overlay);
        InterlockedDecrement(&object_count);
        return 0;
    }
    return seaf_icon_overlay->count;
}

static STDMETHODIMP
query_interface_seaf_icon_overlay (void *p, REFIID iid, LPVOID FAR *pointer)
{
    /* IShellExInit */
    if (IsEqualIID(iid, &CLSID_seaf_shell_ext) ||
        IsEqualIID(iid, &IID_IUnknown) ||
        IsEqualIID(iid, &IID_IShellIconOverlayIdentifier)) {

        *pointer = p;

    } else {
        return E_NOINTERFACE;
    }

    add_ref_seaf_icon_overlay(p);

    return NOERROR;
}

/* IShellIconOverlayIdentifier Vtable */
struct IShellIconOverlay_Vtbl IShellIconOverlay_Vtbl = {
    query_interface_seaf_icon_overlay,
    add_ref_seaf_icon_overlay,
    release_seaf_icon_overlay,
    IsMemberOf,
    GetOverlayInfo,
    GetPriority
};

SeafIconOverlay *
seaf_icon_overlay_new ()
{
    SeafIconOverlay *seaf_icon_overlay;
    seaf_icon_overlay = (SeafIconOverlay*)malloc(sizeof(SeafIconOverlay));
    seaf_icon_overlay->virtual_table = &IShellIconOverlay_Vtbl;
    seaf_icon_overlay->count = 1;

    return seaf_icon_overlay;
}

