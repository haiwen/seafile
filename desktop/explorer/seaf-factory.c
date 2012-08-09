/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "platform.h"

#include <shlobj.h>
#include "seaf-factory.h"
#include "seaf-dll.h"
#include "seaf-menu.h"
#include "seaf-icon.h"
#include "seaf-ext-log.h"

/*
 * Since COM objects cannot be constructed like your traditional object (i.e.
 * with a proper constructor), they have to be constructed by another object,
 * the class factory.
 *
 * The class factory is an object which exists exactly once, and it cannot
 * be constructed or destroyed.  Its sole purpose is to construct objects
 * given an interface.
 */

STDMETHODIMP
class_factory_query_interface(IClassFactory *this, REFIID guid, void **pointer)
{
    if (!IsEqualIID(guid, &IID_IUnknown) &&
        !IsEqualIID(guid, &IID_IClassFactory)) {
        
        *pointer = 0;
        return E_NOINTERFACE;
    }

    *pointer = this;
    return S_OK;
}

static ULONG STDMETHODCALLTYPE
return_one(IClassFactory *this)
{
    return(1);
}

static STDMETHODIMP
create_instance(IClassFactory *this_, IUnknown *outer, REFIID guid, void **pointer)
{
    *pointer = 0;

    if (outer)
        return CLASS_E_NOAGGREGATION;

    if (IsEqualIID(guid, &IID_IShellIconOverlayIdentifier)) {

        *pointer = seaf_icon_overlay_new ();
        
    } else if (IsEqualIID(guid, &IID_IContextMenu) ||
               IsEqualIID(guid, &IID_IContextMenu2) ||
               IsEqualIID(guid, &IID_IContextMenu3) ) {

        *pointer = seaf_menu_new ();

    } else if (IsEqualIID(guid, &IID_IShellExtInit)) {
        
        SeafMenu *seaf_menu = seaf_menu_new ();
        *pointer = &seaf_menu->ishellextinit;
        
    } else {
        char *s = "XXXX";
        
        if (IsEqualIID (guid, &IID_IUnknown)) {
            s = "IUnknown";
        } else if (IsEqualIID (guid, &CLSID_seaf_shell_ext)) {
            s = "CLSID_seaf_shell_ext";
        }
            
        seaf_ext_log ("No such interface : %s", s);
        
        return E_NOINTERFACE;
    }
    
    InterlockedIncrement(&object_count);
    
    return S_OK;
}

static STDMETHODIMP
lock_server(IClassFactory *this, BOOL lock)
{
    if (lock)
        InterlockedIncrement(&lock_count);
    else
        InterlockedDecrement(&lock_count);

    return S_OK;
}

IClassFactoryVtbl factory_virtual_table = {
    class_factory_query_interface,
    return_one,
    return_one,
    create_instance,
    lock_server
};

IClassFactory factory = {
    &factory_virtual_table
};
