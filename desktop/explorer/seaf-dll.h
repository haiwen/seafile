/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SEAF_DLL_H
#define SEAF_DLL_H

static const CLSID CLSID_seaf_shell_ext = {
    0x84f93460, 0x1d70, 0x11e1,
    {0x99,0x91,0x00, 0x1e, 0x68, 0x03, 0x1d, 0xc7}};

/* Path of info stored in registry   */

extern const char *program_name;
extern const char *program_version;
extern const char *program_id;

extern volatile long lock_count;
extern volatile long object_count;

extern HINSTANCE dll_hInst;

HRESULT PASCAL
DllGetClassObject(REFCLSID obj_guid, REFIID factory_guid, void **factory_handle);

HRESULT PASCAL
DllCanUnloadNow(void);

HRESULT PASCAL
DllRegisterServer(void);

HRESULT PASCAL
DllUnregisterServer(void);

BOOL WINAPI
DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved);

#endif /* SEAF_DLL_H */
