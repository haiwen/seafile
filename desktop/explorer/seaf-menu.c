/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include "platform.h"

#include <shlobj.h>
#include <io.h>

#include "seaf-dll.h"
#include "seaf-utils.h"
#include "seaf-ext-log.h"
#include "seaf-menu.h"
#include "menu-engine.h"

struct IShellExtInit_vtbl
{
    STDMETHOD(query_interface)(void *, REFIID, PVOID*);
    STDMETHOD_(ULONG, add_ref)(void *);
    STDMETHOD_(ULONG, release)(void *);
    STDMETHOD(initialize)(void *, LPCITEMIDLIST, LPDATAOBJECT, HKEY);
};

struct IContextMenu_vtbl
{
    STDMETHOD(query_interface)(void *, REFIID, PVOID*);
    STDMETHOD_(ULONG, add_ref)(void *);
    STDMETHOD_(ULONG, release)(void *);
    STDMETHOD(query_context_menu)(void *, HMENU, UINT, UINT, UINT, UINT);
    STDMETHOD(invoke_command)(void *, LPCMINVOKECOMMANDINFO);
    STDMETHOD(get_command_string)(void *, UINT, UINT, PUINT, LPSTR, UINT);
    STDMETHOD(HandleMenuMsg)(void *,UINT,WPARAM,LPARAM);
    STDMETHOD(HandleMenuMsg2)(void *, UINT,WPARAM,LPARAM,LRESULT*);
};

static ULONG STDMETHODCALLTYPE
add_ref_seaf_menu(void *p)
{
    SeafMenu *seaf_menu = p;
    return ++(seaf_menu->count);
}

static ULONG STDMETHODCALLTYPE
add_ref_seaf_ishellextinit(void *p)
{
    struct seaf_IShellExtInit *s = p;
    SeafMenu *seaf_menu = s->seaf_menu;
    return add_ref_seaf_menu(seaf_menu);
}

static ULONG STDMETHODCALLTYPE
release_seaf_menu(void *p)
{
    SeafMenu *seaf_menu = p;
    --(seaf_menu->count);
    if (seaf_menu->count == 0) {

        seaf_menu_free (seaf_menu);
        InterlockedDecrement(&object_count);
        return 0;
    }
    return seaf_menu->count;
}

static ULONG STDMETHODCALLTYPE
release_seaf_ishellextinit(void *p)
{
    struct seaf_IShellExtInit *s = p;
    SeafMenu *seaf_menu = s->seaf_menu;
    return release_seaf_menu(seaf_menu);
}

static STDMETHODIMP
query_interface_seaf_menu (void *p, REFIID iid, LPVOID FAR *pointer)
{
    SeafMenu *seaf_menu = p;
    /* IShellExInit */
    if (IsEqualIID(iid, &IID_IShellExtInit) ||
        IsEqualIID(iid, &CLSID_seaf_shell_ext) ||
        IsEqualIID(iid, &IID_IUnknown)) {

        *pointer = &seaf_menu->ishellextinit;

    }
    /* IContextMenu */
    else if (IsEqualIID(iid, &IID_IContextMenu) ||
             IsEqualIID(iid, &IID_IContextMenu2) ||
             IsEqualIID(iid, &IID_IContextMenu3)) {

        *pointer = p;

    } else {
        return E_NOINTERFACE;
    }

    add_ref_seaf_menu(p);

    return S_OK;
}

static STDMETHODIMP
query_interface_seaf_ishellextinit (void *p, REFIID iid, LPVOID FAR *pointer)
{
    struct seaf_IShellExtInit *s = p;
    SeafMenu *seaf_menu = s->seaf_menu;
    return query_interface_seaf_menu (seaf_menu, iid, pointer);
}

static STDMETHODIMP
initialize_seaf_ishellextinit(void *p, LPCITEMIDLIST folder, LPDATAOBJECT data, HKEY id)
{
    struct seaf_IShellExtInit *s = p;
    SeafMenu *seaf_menu = s->seaf_menu;
    
    FORMATETC format = {CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL};
    STGMEDIUM stg = {TYMED_HGLOBAL};
    HDROP drop;
    UINT count;
    HRESULT result = S_OK;

    /* 'folder' param is not null only when clicking at the foler background;
       When right click on a file, it's NULL */
    if (folder)
        SHGetPathFromIDList(folder, seaf_menu->name);

    /* if 'data' is NULL, then it's a background click, we have set
     * this_->name to folder's name above, and the Init work is done */
    if (!data)
        return S_OK;

    /* 'data' is no null, which means we are operating on a file. the
     * following lines until the end of the function is used to
     * extract the filename of the current file. */
    if (FAILED(data->lpVtbl->GetData(data, &format, &stg)))
        return E_INVALIDARG;

    drop = (HDROP)GlobalLock(stg.hGlobal);
    if (!drop)
        return E_INVALIDARG;

    count = DragQueryFile(drop, 0xFFFFFFFF, NULL, 0);
    if (count == 0)
        result = E_INVALIDARG;
    else if (!DragQueryFile(drop, 0, seaf_menu->name, sizeof(seaf_menu->name)))
        result = E_INVALIDARG;

    GlobalUnlock(stg.hGlobal);
    ReleaseStgMedium(&stg);

    return result;
}

/*
 * These are the functions for handling the context menu.
 */
static char *get_menu_item_text(SeafMenu *seaf_menu, UINT id);
static int handle_menu_item(SeafMenu *seaf_menu, UINT id);

static bool
insert_main_menu (SeafMenu *seaf_menu)
{
    bool status;
    /* Two menu seperators with seafile menu between them  */
    status = InsertMenu
        (seaf_menu->main_menu, seaf_menu->index++,
         MF_BYPOSITION |MF_SEPARATOR, 0, "");

    if (!status)
        return FALSE;

    char *name = "Seafile";
    MENUITEMINFO menuiteminfo;

    ZeroMemory(&menuiteminfo, sizeof(menuiteminfo));
    menuiteminfo.cbSize = sizeof(menuiteminfo);
    menuiteminfo.fMask = MIIM_FTYPE | MIIM_SUBMENU | MIIM_BITMAP | MIIM_STRING | MIIM_ID;
    menuiteminfo.fType = MFT_STRING;
    menuiteminfo.dwTypeData = name;
    menuiteminfo.cch = strlen(name);
    menuiteminfo.hbmpItem = HBMMENU_CALLBACK;
    menuiteminfo.hSubMenu = seaf_menu->sub_menu;
    menuiteminfo.wID = seaf_menu->first;

    status = InsertMenuItem
        (seaf_menu->main_menu,  /* menu */
         seaf_menu->index++,    /* position */
         TRUE,                  /* by position */
         &menuiteminfo);
    if (!status)
        return FALSE;
    
    status = InsertMenu (seaf_menu->main_menu, seaf_menu->index++,
                         MF_BYPOSITION |MF_SEPARATOR, 0, "");
    
    if (!status)
        return FALSE;

    /* Set menu styles of submenu */
    MENUINFO MenuInfo;
    ZeroMemory(&MenuInfo, sizeof(MenuInfo));
    MenuInfo.cbSize  = sizeof(MenuInfo);
    MenuInfo.fMask   = MIM_STYLE | MIM_APPLYTOSUBMENUS;
    MenuInfo.dwStyle = MNS_CHECKORBMP;

    SetMenuInfo(seaf_menu->main_menu, &MenuInfo);
    
    return TRUE;
}

static bool
should_ignore (SeafMenu *seaf_menu) {
    /* Show no menu for drive root, such as C: D: */
    if (strlen(seaf_menu->name) <= 3) {
        return TRUE;
    }

    char drive[4];
    memcpy (drive, seaf_menu->name, 3);
    drive[3] = '\0';

    /* Ignore flash disk, network mounted drive, etc. */
    if (GetDriveType(drive) != DRIVE_FIXED) {
        return TRUE;
    }

    return FALSE;
}

static STDMETHODIMP
query_context_menu(void *p, HMENU menu, UINT index,
                   UINT first_command, UINT last_command, UINT flags)
{
    /* do nothing when user is double clicking */
    if (flags & CMF_DEFAULTONLY)
        return MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_NULL, 0);

    SeafMenu *seaf_menu = p;

    if (should_ignore(seaf_menu)) {
        return MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_NULL, 0);
    }

    seaf_menu->main_menu = menu;
    seaf_menu->first = first_command;
    seaf_menu->last = last_command;
    seaf_menu->index = 0;

    build_seafile_menu (seaf_menu);
    
    if (seaf_menu->next_active_item > 0) {
        if (!insert_main_menu (seaf_menu))
            return S_FALSE;
    }

    return MAKE_HRESULT(SEVERITY_SUCCESS, FACILITY_NULL,
                        3 + seaf_menu->next_active_item);
}

static STDMETHODIMP
invoke_command(void *p, LPCMINVOKECOMMANDINFO info)
{
    SeafMenu *seaf_menu = p;
    
    UINT id = LOWORD(info->lpVerb);

    if (HIWORD(info->lpVerb))
        return E_INVALIDARG;

    if (id == 0)
        return S_OK;

    id--;
    handle_menu_item(seaf_menu, id);

    return S_OK;
}

static STDMETHODIMP
get_command_string(void *p, UINT id, UINT flags, UINT *reserved,
                   LPSTR name, UINT size)
{
    if (!(flags & GCS_HELPTEXT))
        return E_INVALIDARG;

    SeafMenu *seaf_menu = p;

    char *text = NULL;

    if (id == 0) {
        text = "Seafile";
    } else {
        id--;
        text = get_menu_item_text(seaf_menu, id);
    }

    if (!text)
        return E_INVALIDARG;

    if (flags & GCS_UNICODE) {
        wchar_t *wtext = char_to_wchar (text);
        if (!wtext)
            return S_FALSE;
        lstrcpynW ((LPWSTR)name, wtext, size);
        free (wtext);
    } else
        lstrcpynA(name, text, size);

    return S_OK;
}

extern char *seaf_ext_ico;
static HICON menu_icons_cache[SEAF_OP_MAX];

static HICON
load_menu_item_icon (SeafMenu *seaf_menu, UINT itemID)
{
    UINT index = 0;
    char *icon_file = NULL;
    
    if (itemID == seaf_menu->first) {
        /* main menu bar item */
        index = 0;
        icon_file = seaf_ext_ico;
    } else {
        /* sub menu bar item */
        itemID -= seaf_menu->first + 1;
        if (itemID > seaf_menu->next_active_item) {
            seaf_ext_log ("itemID too large, %u(%d)",
                          itemID, seaf_menu->next_active_item);
            return NULL;
        }
        struct menu_item *mi = &seaf_menu->active_menu[itemID];
        index = mi->op;
        icon_file = mi->icon;
    }

    if (menu_icons_cache[index]) { 
        /* Icon for this menu item has been cached. */
        return menu_icons_cache[index];
    } else {
        if (!icon_file)
            return NULL;
        if (access(icon_file, F_OK) < 0) {
            seaf_ext_log ("icon file doesn't found, %s", icon_file);
            return NULL;
        }
        HICON hIcon = LoadImage
            (NULL,
             (LPCTSTR)icon_file,
             IMAGE_ICON,
             16,16,
             LR_LOADFROMFILE);
        if (!hIcon) {
            seaf_ext_log ("failed to load %s", icon_file); 
            return NULL;
        }
        /* Cache the loaded icon. */
        menu_icons_cache[index] = hIcon;
        return hIcon;
    }
}


/* Handles the WM_MEASUREITEM and WM_DRAWITEM messages, so we can draw icons
 * for menu items
 */
static STDMETHODIMP
HandleMenuMsg2(void *p, UINT uMsg, WPARAM wParam, LPARAM lParam, LRESULT *plResult)
{
    SeafMenu *seaf_menu = p;
    /* we use a 16*16 icon for each menu item */
    int icon_size = 16; 

    if (uMsg == WM_INITMENUPOPUP) {

    } else if (uMsg == WM_MEASUREITEM) {
        MEASUREITEMSTRUCT* lpmis = (MEASUREITEMSTRUCT*)lParam;
        if (!lpmis)
            return S_OK;

        lpmis->itemWidth = icon_size;
        lpmis->itemHeight = icon_size;

    } else if (uMsg == WM_DRAWITEM) {
        DRAWITEMSTRUCT* lpdis = (DRAWITEMSTRUCT*)lParam;
        if (!lpdis || (lpdis->CtlType != ODT_MENU))
            return S_OK; // not for a menu

        HICON hIcon = load_menu_item_icon(seaf_menu, lpdis->itemID);
        if (hIcon == NULL)
            return S_OK;

        RECT *rect = &lpdis->rcItem;
        int left = rect->left;
        int right = rect->right;
        int top = rect->top;
        int bottom = rect->bottom;

        DrawIconEx(lpdis->hDC,
                   left + (right - left - icon_size) / 2,
                   bottom + (top - bottom - icon_size)/2,
                   hIcon, icon_size, icon_size,
                   0, NULL, DI_NORMAL);
    } else {
        seaf_ext_log ("[MSG] UNKNOWN MSG");
        return S_FALSE;
    }
    if (plResult)
        *plResult = TRUE;
    return S_OK;
}


static STDMETHODIMP
HandleMenuMsg(void *p, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    return HandleMenuMsg2(p, uMsg, wParam, lParam, NULL);
}


/* Menu operations */

/* Clears the list every time a new menu is displayed */
void reset_active_menu(SeafMenu *seaf_menu)
{
    if (seaf_menu->active_menu)
        free(seaf_menu->active_menu);
    seaf_menu->active_menu = NULL;
    seaf_menu->next_active_item = 0;
    seaf_menu->selection = SEAF_MI_ALWAYS;
}

/* Append all activited menu items into a list  */
void
append_active_menu(SeafMenu *seaf_menu, const struct menu_item *item)
{
    seaf_menu->active_menu = realloc
        (seaf_menu->active_menu,
         (seaf_menu->next_active_item + 1) * sizeof(struct menu_item));

    seaf_menu->active_menu[seaf_menu->next_active_item] = *item;
    seaf_menu->next_active_item++;
}

static char *
get_menu_item_text(SeafMenu *seaf_menu, UINT id)
{
    if (id > (UINT)seaf_menu->next_active_item) {
        seaf_ext_log ("invalid menu id %u", id);
        return NULL;
    } else {
        return seaf_menu->active_menu[id].helptext;
    }
}

static int
handle_menu_item(SeafMenu *seaf_menu, UINT id)
{
    if (id > seaf_menu->next_active_item) {
        seaf_ext_log ("invalid menu id %u", id);
        return 0;
    }
    
    dispatch_menu_command (seaf_menu, &seaf_menu->active_menu[id].op);
    return 0;
}

/* Fill a MENUITEMINFO struct with info of a seafile menu item */
static void
menu_item_to_info (SeafMenu *seaf_menu, const struct menu_item *mi,
                   MENUITEMINFO *minfo)
{
    minfo->cbSize = sizeof(MENUITEMINFO);
    minfo->fMask = MIIM_FTYPE | MIIM_BITMAP | MIIM_STRING | MIIM_ID;
    minfo->fType = MFT_STRING;
    minfo->dwTypeData = mi->string;
    minfo->cch = strlen(mi->string);
    minfo->hbmpItem = HBMMENU_CALLBACK;
    
    /* menu->first is used by main menu item "seafile"   */
    minfo->wID = seaf_menu->first + 1 + seaf_menu->next_active_item;
}

static void
set_menu_item_checked (SeafMenu *seaf_menu, const struct menu_item *mi,
                       MENUITEMINFO *minfo)
{
    minfo->fMask = MIIM_FTYPE | MIIM_STRING | MIIM_ID | MIIM_STATE | MIIM_CHECKMARKS;
    minfo->fType = MFT_STRING | MFT_RADIOCHECK;
    minfo->hbmpChecked = NULL;
    minfo->hbmpUnchecked = NULL;

    if (mi->op == SEAF_TURN_ON_AUTO) {
        if (seaf_menu->selection & SEAF_MI_TURN_ON_AUTO)
            minfo->fState = MFS_UNCHECKED;
        else
            minfo->fState = MFS_CHECKED;
    } else {            /* mi->op == TURN_OFF_AUTO */
        if (seaf_menu->selection & SEAF_MI_TURN_ON_AUTO)
            minfo->fState = MFS_CHECKED;
        else
            minfo->fState = MFS_UNCHECKED;
    }
}

/* Insert a new menu item according to its type.

   When the menu item is a menu seperator, don't add it directly because we
   don't know whethter it would be the last menu item, in which case it would
   be redundant. We set the `add_sep' flag, and every time we add a new menu
   item, we check this flag to decide whether a menu seperator should be added
   before this current menu item.
 */
bool
build_menu_item(SeafMenu *seaf_menu, const struct menu_item *mi)
{
    if (seaf_menu->last < seaf_menu->first + seaf_menu->next_active_item)
        return FALSE;

    /* Check whether a menu seperator is pending  */
    if (mi->op != SEAF_NONE && seaf_menu->add_sep) {
        InsertMenu (seaf_menu->sub_menu, seaf_menu->index++,
                    MF_SEPARATOR | MF_BYPOSITION, 0, "");
        seaf_menu->add_sep = FALSE;
    }

    if (mi->op == SEAF_NONE ) {
        seaf_menu->add_sep = TRUE;
    } else {
        MENUITEMINFO menuiteminfo = {0};
        menu_item_to_info (seaf_menu, mi, &menuiteminfo);

        if (mi->op == SEAF_TURN_ON_AUTO || mi->op == SEAF_TURN_OFF_AUTO) {
            set_menu_item_checked (seaf_menu, mi, &menuiteminfo);
        }

        InsertMenuItem (seaf_menu->sub_menu, /* menu */
                        seaf_menu->index++,  /* position */
                        TRUE,                /* by position */
                        &menuiteminfo);
    }

    return TRUE;
}


/* The vtable of IShellExInit */
struct IShellExtInit_vtbl IShellExtInit_vtbl = {
    query_interface_seaf_ishellextinit,
    add_ref_seaf_ishellextinit,
    release_seaf_ishellextinit,
    initialize_seaf_ishellextinit
};

/**
 * The vtable of IContextMenu 
 *
 * Note: Pay attention to the order of the last three methods. IN MSDN docs,
 * they are listed in alphabetic order, which is not their order in the
 * Vtable! Google `IContextMenu Vtable order', you can get the right
 * information
 */
struct IContextMenu_vtbl IContextMenu_vtbl = {
    query_interface_seaf_menu,
    add_ref_seaf_menu,
    release_seaf_menu,
    query_context_menu,
    invoke_command,
    get_command_string,
    HandleMenuMsg,
    HandleMenuMsg2
};

SeafMenu *seaf_menu_new ()
{
    SeafMenu *seaf_menu;
    
    seaf_menu = (SeafMenu *)malloc (sizeof(SeafMenu));
    ZeroMemory (seaf_menu, sizeof(SeafMenu));
    seaf_menu->virtual_table = &IContextMenu_vtbl;
    seaf_menu->sub_menu = CreateMenu();
    
    seaf_menu->ishellextinit.virtual_table = &IShellExtInit_vtbl;
    seaf_menu->ishellextinit.seaf_menu = seaf_menu;

    seaf_menu->count = 1;
    
    return seaf_menu;
}

void seaf_menu_free (SeafMenu *seaf_menu)
{
    if (!seaf_menu)
        return;

    if (seaf_menu->active_menu) {
        free (seaf_menu->active_menu);
    }
        
    free (seaf_menu);

}
