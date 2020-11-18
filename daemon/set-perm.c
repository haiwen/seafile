/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include "utils.h"
#define DEBUG_FLAG SEAFILE_DEBUG_SYNC
#include "log.h"

#include "set-perm.h"

#ifdef WIN32

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x501
#endif

#include <windows.h>
#include <AccCtrl.h>
#include <AclApi.h>

#define WIN32_WRITE_ACCESS_MASK (FILE_WRITE_DATA | FILE_APPEND_DATA | \
                                 FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | DELETE)

// Remove explicit ACEs set by us.
static int
unset_permissions (PACL dacl)
{
    ACL_SIZE_INFORMATION size_info;

    if (!dacl)
        return 0;

    if (!GetAclInformation (dacl, &size_info,
                            sizeof(size_info), AclSizeInformation)) {
        seaf_warning ("GetAclInformation Error: %lu\n", GetLastError());
        return -1;
    }

    DWORD i;
    ACE_HEADER *ace;
    ACCESS_DENIED_ACE *deny_ace;
    ACCESS_ALLOWED_ACE *allowed_ace;
    for (i = 0; i < size_info.AceCount; ++i) {
        if (!GetAce(dacl, i, (void**)&ace)) {
            seaf_warning ("GetAce Error: %lu\n", GetLastError());
            return -1;
        }

        // Skip inherited ACEs.
        if (ace->AceFlags & INHERITED_ACE)
            continue;

        if (ace->AceType == ACCESS_DENIED_ACE_TYPE) {
            deny_ace = (ACCESS_DENIED_ACE *)ace;
            if (deny_ace->Mask == WIN32_WRITE_ACCESS_MASK) {
                DeleteAce(dacl, i);
                break;
            }
        } else if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            allowed_ace = (ACCESS_ALLOWED_ACE *)ace;
            if (allowed_ace->Mask == WIN32_WRITE_ACCESS_MASK) {
                DeleteAce(dacl, i);
                break;
            }
        }
    }

    return 0;
}

int
seaf_set_path_permission (const char *path, SeafPathPerm perm, gboolean recursive)
{
    wchar_t *wpath = NULL;
    int ret = 0;
    DWORD res = 0;
    PACL old_dacl = NULL, new_dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    EXPLICIT_ACCESS ea;

    g_return_val_if_fail (perm == SEAF_PATH_PERM_RO || perm == SEAF_PATH_PERM_RW, -1);

    seaf_debug ("set permission for %s, perm: %d, recursive: %d\n",
                path, perm, recursive);

    wpath = win32_long_path (path);
    if (!wpath)
        return -1;

    res = GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, &old_dacl, NULL, &sd);
    if (ERROR_SUCCESS != res) {
        seaf_warning( "GetNamedSecurityInfo Error for path %s: %lu\n", path, res );
        ret = -1;
        goto cleanup;
    }

    unset_permissions (old_dacl);

    // Initialize an EXPLICIT_ACCESS structure for the new ACE. 

    memset (&ea, 0, sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = WIN32_WRITE_ACCESS_MASK;
    ea.grfAccessMode = ((perm == SEAF_PATH_PERM_RO)?DENY_ACCESS:GRANT_ACCESS);
    ea.grfInheritance = (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE);
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.TrusteeType = TRUSTEE_IS_USER;
    ea.Trustee.ptstrName = L"CURRENT_USER";

    // Create a new ACL that merges the new ACE
    // into the existing DACL.

    res = SetEntriesInAcl(1, &ea, old_dacl, &new_dacl);
    if (ERROR_SUCCESS != res)  {
        seaf_warning( "SetEntriesInAcl Error %lu\n", res );
        ret = -1;
        goto cleanup;
    }  

    // Attach the new ACL as the object's DACL.

    if (recursive) {
        res = SetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                    DACL_SECURITY_INFORMATION,
                                    NULL, NULL, new_dacl, NULL);
        if (ERROR_SUCCESS != res)  {
            seaf_warning( "SetNamedSecurityInfo Error %lu\n", res );
            ret = -1;
            goto cleanup;
        }
    } else {
        SECURITY_DESCRIPTOR new_sd;

        InitializeSecurityDescriptor (&new_sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl (&new_sd, TRUE, new_dacl, FALSE);

        if (!SetFileSecurityW (wpath, DACL_SECURITY_INFORMATION, &new_sd)) {
            seaf_warning ("SetFileSecurity Error %lu\n", GetLastError());
            ret = -1;
            goto cleanup;
        }
    }

 cleanup:
    g_free (wpath);
    if(sd != NULL) 
        LocalFree((HLOCAL) sd);
    if(new_dacl != NULL) 
        LocalFree((HLOCAL) new_dacl);
    return ret;
}

int
seaf_unset_path_permission (const char *path, gboolean recursive)
{
    wchar_t *wpath = NULL;
    int ret = 0;
    DWORD res = 0;
    PACL old_dacl = NULL, new_dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;

    seaf_debug ("unset permission for %s, recursive: %d\n",
                path, recursive);

    wpath = win32_long_path (path);
    if (!wpath)
        return -1;

    res = GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, &old_dacl, NULL, &sd);
    if (ERROR_SUCCESS != res) {
        seaf_warning( "GetNamedSecurityInfo Error %lu\n", res );
        ret = -1;
        goto cleanup;
    }

    // Create a new copy of the old ACL

    res = SetEntriesInAcl(0, NULL, old_dacl, &new_dacl);
    if (ERROR_SUCCESS != res)  {
        seaf_warning( "SetEntriesInAcl Error %lu\n", res );
        ret = -1;
        goto cleanup;
    }

    if (!new_dacl) {
        goto cleanup;
    }

    unset_permissions (new_dacl);

    // Update path's ACL

    if (recursive) {
        res = SetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                    DACL_SECURITY_INFORMATION,
                                    NULL, NULL, new_dacl, NULL);
        if (ERROR_SUCCESS != res)  {
            seaf_warning( "SetNamedSecurityInfo Error %lu\n", res );
            ret = -1;
            goto cleanup;
        }
    } else {
        SECURITY_DESCRIPTOR new_sd;

        InitializeSecurityDescriptor (&new_sd, SECURITY_DESCRIPTOR_REVISION);
        SetSecurityDescriptorDacl (&new_sd, TRUE, new_dacl, FALSE);

        if (!SetFileSecurityW (wpath, DACL_SECURITY_INFORMATION, &new_sd)) {
            seaf_warning ("SetFileSecurity Error %lu\n", GetLastError());
            ret = -1;
            goto cleanup;
        }
    }

 cleanup:
    g_free (wpath);
    if(sd != NULL) 
        LocalFree((HLOCAL) sd);
    if(new_dacl != NULL) 
        LocalFree((HLOCAL) new_dacl);
    return ret;
}

SeafPathPerm
seaf_get_path_permission (const char *path)
{
    wchar_t *wpath = NULL;
    SeafPathPerm ret = SEAF_PATH_PERM_UNKNOWN;
    DWORD res = 0;
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;

    wpath = win32_long_path (path);
    if (!wpath)
        return ret;

    res = GetNamedSecurityInfoW(wpath, SE_FILE_OBJECT, 
                                DACL_SECURITY_INFORMATION,
                                NULL, NULL, &dacl, NULL, &sd);
    if (ERROR_SUCCESS != res) {
        seaf_warning( "GetNamedSecurityInfo Error %lu\n", res );
        goto cleanup;
    }

    ACL_SIZE_INFORMATION size_info;

    if (!GetAclInformation (dacl, &size_info,
                            sizeof(size_info), AclSizeInformation)) {
        seaf_warning ("GetAclInformation Error: %lu\n", GetLastError());
        goto cleanup;
    }

    DWORD i;
    ACE_HEADER *ace;
    ACCESS_DENIED_ACE *deny_ace;
    ACCESS_ALLOWED_ACE *allowed_ace;
    for (i = 0; i < size_info.AceCount; ++i) {
        if (!GetAce(dacl, i, (void**)&ace)) {
            seaf_warning ("GetAce Error: %lu\n", GetLastError());
            goto cleanup;
        }

        // Skip inherited ACEs.
        if (ace->AceFlags & INHERITED_ACE)
            continue;

        if (ace->AceType == ACCESS_DENIED_ACE_TYPE) {
            deny_ace = (ACCESS_DENIED_ACE *)ace;
            if (deny_ace->Mask == WIN32_WRITE_ACCESS_MASK) {
                ret = SEAF_PATH_PERM_RO;
                break;
            }
        } else if (ace->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            allowed_ace = (ACCESS_ALLOWED_ACE *)ace;
            if (allowed_ace->Mask == WIN32_WRITE_ACCESS_MASK) {
                ret = SEAF_PATH_PERM_RW;
                break;
            }
        }
    }

cleanup:
    g_free (wpath);
    if(sd != NULL) 
        LocalFree((HLOCAL) sd);
    return ret;
}

#else

#include <sys/stat.h>

int
seaf_set_path_permission (const char *path, SeafPathPerm perm, gboolean recursive)
{
    struct stat st;
    mode_t new_mode;

    if (stat (path, &st) < 0) {
        seaf_warning ("Failed to stat %s: %s\n", path, strerror(errno));
        return -1;
    }

    new_mode = st.st_mode;
    if (perm == SEAF_PATH_PERM_RO)
        new_mode &= ~(S_IWUSR);
    else if (perm == SEAF_PATH_PERM_RW)
        new_mode |= S_IWUSR;

    if (chmod (path, new_mode) < 0) {
        seaf_warning ("Failed to chmod %s to %d: %s\n", path, new_mode, strerror(errno));
        return -1;
    }

    return 0;
}

int
seaf_unset_path_permission (const char *path, gboolean recursive)
{
    return 0;
}

SeafPathPerm
seaf_get_path_permission (const char *path)
{
    return SEAF_PATH_PERM_UNKNOWN;
}

#endif  /* WIN32 */
