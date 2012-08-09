/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "platform.h"

#include <io.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <fcntl.h>
#include <psapi.h>
#include <ctype.h>
#include <userenv.h>

#include <stdarg.h>


#include "seaf-dll.h"
#include "seaf-menu.h"
#include "menu-engine.h"

#include "seaf-ext-log.h"
#include "strbuf.h"
#include "seaf-utils.h"


const char *get_home_dir()
{
    static char *home;

    if (home)
        return home;

    char buf[MAX_PATH] = {'\0'};

    if (!home) {
        /* Try env variable first. */
        GetEnvironmentVariable("HOME", buf, MAX_PATH);
        if (buf[0] != '\0')
            home = strdup(buf);
    }

    if (!home) {
        /* No `HOME' ENV; Try user profile */
        HANDLE hToken = NULL;
        DWORD len = MAX_PATH;
        if (OpenProcessToken (GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            GetUserProfileDirectory (hToken, buf, &len);
            CloseHandle(hToken);
            if (buf[0] != '\0')
                home = strdup(buf);
        }
    }

    if (home)
        regulate_path(home);

    return home;
}

static char*
seaf_iconv (const char *src, UINT from_encoding, UINT to_encoding)
{
    if (!src)
        return NULL;
    
    char *dst = NULL;
    int len, res;

    len = res = 0;
    /* first get wchar length of the src str */
    len = MultiByteToWideChar
        (from_encoding,         /* multibyte code page */
         0,                     /* flags */
         src,                   /* src */
         -1,                    /* src len, -1 for all including \0 */
         NULL,                  /* dst */
         0);                    /* dst buf len */

    if (len <= 0)
        return NULL;

    wchar_t *tmp_wchar = malloc (sizeof(wchar_t) * len);
    res = MultiByteToWideChar
        (from_encoding,         /* multibyte code page */
         0,                     /* flags */
         src,                   /* src */
         -1,                    /* src len, -1 for all includes \0 */
         tmp_wchar,             /* dst */
         len);                  /* dst buf len */

    if (res <= 0) {
        free (tmp_wchar);
        return NULL;
    }

    /* Now we have the widechar, we can convert it into dst */
    /* first get dst str length */
    len = WideCharToMultiByte
        (to_encoding,  /* multibyte code page */
         0,             /* flags */
         tmp_wchar,     /* src */
         -1,            /* src len, -1 for all includes \0 */
         NULL,          /* dst */
         0,             /* dst buf len */
         NULL,          /* default char */
         NULL);         /* BOOL flag indicates default char is used */

    if (len <= 0) {
        free (tmp_wchar);
        return NULL;
    }

    dst = malloc (sizeof(char) * len);
    res = WideCharToMultiByte
        (to_encoding,   /* multibyte code page */
         0,             /* flags */
         tmp_wchar,     /* src */
         -1,            /* src len, -1 for all includes \0 */
         dst,           /* dst */
         len,           /* dst buf len */
         NULL,          /* default char */
         NULL);         /* BOOL flag indicates default char is used */

    free (tmp_wchar);
    if (res <= 0) {
        free(dst);
        free(tmp_wchar);
        return NULL;
    }

    return dst;
}

inline char *locale_from_utf8 (const char *src)
{
    return seaf_iconv (src, CP_UTF8, CP_ACP);
}

inline char *locale_to_utf8 (const char *src)
{
    return seaf_iconv (src, CP_ACP, CP_UTF8);
}

char *wchar_to_char (const wchar_t *src)
{
    char dst[MAX_PATH];
    int len;

    len = WideCharToMultiByte
        (CP_ACP,        /* multibyte code page */
         0,             /* flags */
         src,           /* src */
         -1,            /* src len, -1 for all includes \0 */
         dst,           /* dst */
         MAX_PATH,      /* dst buf len */
         NULL,          /* default char */
         NULL);         /* BOOL flag indicates default char is used */

    if (len <= 0) {
        return NULL;
    }

    return strdup(dst);
}

wchar_t *char_to_wchar (const char *src)
{
    wchar_t dst[MAX_PATH];
    int len;

    len = MultiByteToWideChar
        (CP_ACP,                /* multibyte code page */
         0,                     /* flags */
         src,                   /* src */
         -1,                    /* src len, -1 for all includes \0 */
         dst,                   /* dst */
         MAX_PATH);             /* dst buf len */

    if (len <= 0) {
        return NULL;
    }

    return wcsdup(dst);
}

char *get_folder_path (const char *path)
{
    if (!path || (access(path, F_OK) != 0))
        return NULL;
    
    if (GetFileAttributes(path) & FILE_ATTRIBUTE_DIRECTORY)
        return strdup(path);

    /* Note: here we are sure that the path would be regulated by
       regulate_path() sometime before, so we can test '/' only
    */
    const char *ptr = strrchr(path, '/');

    if (!ptr)
        return NULL;
    else {
        int len = ptr - path;
        char *s = malloc (len+2);
        memcpy (s, path, len+1);
        s[len+1] = '\0';
            
        return s;
    }

}

char *
get_base_name (const char *path_in)
{
    if (!path_in)
        return NULL;

    char path[MAX_PATH];
    memcpy (path, path_in, strlen(path_in) + 1);

    char *ptr = path;

    while (*ptr)
        ptr++;

    ptr--;
    while (*ptr == '/') {
        *ptr = '\0';
        ptr--;
    }
    
    while (ptr > path && *ptr != '/')
        ptr--;

    if (ptr == path) {
        return strdup(path);
    } else {
        char *s = strdup(ptr + 1);
        return s;
    }
}



void open_browser(char *url)
{
    ShellExecute (NULL, "open", url, NULL,
                  NULL, SW_SHOWNORMAL);

}

const char *get_this_dll_folder()
{
    static char *dll_folder;

    if (!dll_folder) {
        const char *dllpath = get_this_dll_filename();
        dll_folder = get_folder_path (dllpath);
    }
        
    return dll_folder;
}


const char *get_this_dll_filename()
{
    static char module_filename[MAX_PATH] = { '\0' };

    if (module_filename[0] == '\0') {
        DWORD module_size;

        module_size = GetModuleFileName(dll_hInst,
                module_filename, MAX_PATH);
        if (!module_size)
            return NULL;

        regulate_path(module_filename);
    }

    return module_filename;
}

/* Use a wrapper in case we need to extend it in the future */
static DWORD WINAPI job_thread_wrapper (void *vdata)
{
    SeafExtJob *job = vdata;

    int status = job->thread_func(job->data);

    free (job);

    ExitThread(status == 0);

}

int
seaf_ext_start_thread(SeafThreadFunc thread_func, void *data, void *p_handle)
{
    SeafExtJob *job = malloc (sizeof(SeafExtJob));

    memset(job, 0, sizeof(SeafExtJob));

    job->thread_func = thread_func;
    job->data = data;

    DWORD tid = 0;

    HANDLE hThread = CreateThread
        (NULL,                  /* security attr */
         0,                     /* stack size, 0 for default */
         (LPTHREAD_START_ROUTINE)job_thread_wrapper, /* start address */
         (void *)job,                                /* param*/
         0,                     /* creation flags */
         &tid);                 /* thread ID */

    if (!hThread) {
        seaf_ext_log ("failed to create thread");
        free(job);
        return -1;
    }
    
    HANDLE *p = p_handle;

    if (p) {
        *p = hThread;
    } else {
        /* Close the handle so that the thread object is destroyed by
         * system when it terminates
         */
        CloseHandle(hThread);
    }

    return 0;
}


/* Try to accuqire the `mutex', blocking if `blocking' param is TRUE.
 * When `blocking' is TRUE, this funciton won't return until the mutex
 * is accquired. When `blocking' is FALSE, return immediately with the
 * return value indicating whether the mutex is accquired or not.
 */
inline bool seaf_mutex_acquire(void *vmutex, bool blocking)
{
    if (!vmutex)
        return FALSE;

    HANDLE mutex = *(HANDLE *)vmutex;

    DWORD ret = 0;

    if (!blocking) {
        ret = WaitForSingleObject(mutex, 0);
        return (ret == WAIT_OBJECT_0);
    }
    
    /* blocking */
    while (1) {
        ret = WaitForSingleObject(mutex, INFINITE);

        if (ret == WAIT_OBJECT_0)
            return TRUE;
    }
}


inline bool seaf_mutex_release(void *vmutex)
{
    HANDLE mutex = *(HANDLE *)vmutex;
    ReleaseMutex(mutex);
    return TRUE;
}
    
bool seaf_mutex_init (void *vmutex)
{
    HANDLE mutex = NULL;

    mutex = CreateMutex
        (NULL,            /* securitry attr */
         FALSE,           /* own the mutex immediately after create */
         NULL);           /* name */

    if (!mutex) {
        seaf_ext_log ("create cache_mutex failed, error code %u",
                      (unsigned int)GetLastError());
        return FALSE;
    }

    HANDLE *p = vmutex;

    *p = mutex;

    return TRUE;
}

static char *
do_uri_escape (const char *input)
{
    if (!input)
        return NULL;

    char buf[MAX_PATH];
    int len = strlen(input);
    int i = 0;
    int pos = 0;

    for (i = 0; i < len; i++) {
        if (isascii(input[i])) {
            buf[pos++] = input[i];
        }
        else {
            int l = snprintf
                (buf + pos, MAX_PATH - pos,
                 "%%%02X", (unsigned int)(unsigned char)input[i]);
            pos += l;
        }
    }
    buf[pos] = '\0';

    return strdup(buf);
}

char *seaf_uri_escape(const char *path)
{
    char *u8_uri = locale_to_utf8(path);
    if (!u8_uri) return NULL;

    char *escaped = do_uri_escape (u8_uri);
    free (u8_uri);

    return escaped;
}

static bool ext_pipe_connected = FALSE;
static HANDLE ext_pipe = INVALID_HANDLE_VALUE;
static OVERLAPPED ol;

inline bool
ext_pipe_is_connected ()
{
    return ext_pipe_connected;
}

#define SEAF_EXT_PIPE_NAME "\\\\.\\pipe\\seafile_ext_pipe"

#define PIPE_BUFSIZE 1024
#define PIPE_WRITE_WAIT_TIME 1
#define PIPE_READ_WAIT_TIME 1

int
connect_ext_pipe ()
{
    if (ext_pipe != INVALID_HANDLE_VALUE) {
        CloseHandle (ext_pipe);
    }
    ext_pipe = CreateFile(
        SEAF_EXT_PIPE_NAME,     // pipe name 
        GENERIC_READ |          // read and write access 
        GENERIC_WRITE, 
        0,                      // no sharing 
        NULL,                   // default security attributes
        OPEN_EXISTING,          // opens existing pipe 
        FILE_FLAG_OVERLAPPED,   // default attributes 
        NULL);                  // no template file 

    if (ext_pipe == INVALID_HANDLE_VALUE) {
        /* seaf_ext_log ("Failed to create named pipe, GLE=%lu\n", GetLastError()); */
        ext_pipe_connected = FALSE;
        return -1;
    } 

    ext_pipe_connected = TRUE;
    seaf_ext_log ("[pipe] Ext pipe connected.");
    return 0;
}

int
seaf_ext_pipe_prepare()
{
    memset(&ol, 0, sizeof(ol));
    HANDLE h_ev = CreateEvent
        (NULL,                  /* security attribute */
         FALSE,                 /* manual reset */
         FALSE,                 /* initial state  */
         NULL);                 /* event name */

    if (!h_ev) {
        return -1;
    }
    ol.hEvent = h_ev;
    return 0;
}

static inline void
reset_overlapped()
{
    ol.Offset = ol.OffsetHigh = 0;
    ResetEvent(ol.hEvent);
}

/* Check error status after WriteFile/ReadFile */
static bool
check_last_error (BOOL ret)
{
    DWORD last_error = GetLastError();
    if (!ret && (last_error != ERROR_IO_PENDING && last_error != ERROR_SUCCESS)) {
        if (last_error == ERROR_BROKEN_PIPE || last_error == ERROR_NO_DATA
            || last_error == ERROR_PIPE_NOT_CONNECTED) {
            seaf_ext_log ("[ext pipe] pipe broken with error: %lu", last_error);
            ext_pipe_connected = FALSE;
        } else {
            seaf_ext_log ("[ext pipe] failed to WriteFile(), GLE=%lu", last_error);
        }
        return FALSE;
    }
    return TRUE;
}

/* Blocking waiting for ReadFile/WriteFile to finish with some timeout limit  */
static bool
do_pipe_wait (HANDLE hPipe, OVERLAPPED *ol, DWORD len)
{
    DWORD bytesRW, result;
    
    result = WaitForSingleObject (ol->hEvent, PIPE_WRITE_WAIT_TIME * 1000);
    
    if (result == WAIT_OBJECT_0) {
        if (GetLastError() == ERROR_IO_PENDING) {
            
            /* seaf_ext_log ("After WaitForSingleObject(), GLE = ERROR_IO_PENDING"); */
            
            if (!GetOverlappedResult(hPipe, ol, &bytesRW, FALSE)
                || bytesRW != len) {
                seaf_ext_log ("[pipe write ] GetOverlappedResult failed, GLE=%lu",
                              GetLastError());
                return FALSE;
            }
        }
        
    } else if (result == WAIT_TIMEOUT) {
        seaf_ext_log ("[ext pipe] timeout. GLE=%lu", GetLastError());
        return FALSE;
        
    } else {
        seaf_ext_log ("[ext pipe] WaitForSingleObject error, GLE=%lu",
                      GetLastError());
        return FALSE;
    }

    return TRUE;
}

static int
ext_pipe_writen (HANDLE hPipe, void *buf, uint32_t len)
{
    reset_overlapped();
    BOOL ret;
    DWORD bytesWritten;
    
    ret = WriteFile(
        hPipe,                  // handle to pipe
        buf,                    // buffer to write from
        (DWORD)len,             // number of bytes to write
        &bytesWritten,          // number of bytes written
        &ol);                   // overlapped IO

    if (!check_last_error(ret))
        return -1;

    if (!do_pipe_wait (hPipe, &ol, (DWORD)len))
        return -1;

    return 0;
}

static int
ext_pipe_readn (HANDLE hPipe, void *buf, uint32_t len)
{
    reset_overlapped();
    DWORD bytesRead;
    bool ret;
    ret= ReadFile(
        hPipe,                  // handle to pipe
        buf,                    // buffer to write from
        (DWORD)len,             // number of bytes to read
        &bytesRead,             // number of bytes read
        &ol);                   // overlapped IO

    if (!check_last_error(ret))
        return -1;

    if (!do_pipe_wait (hPipe, &ol, (DWORD)len))
        return -1;

    return 0;
}

/* Send a requset to ext pipe. Assume lock is hold by the caller. */
int
send_ext_pipe_request_wrapper (const char *request_in)
{
    char *request = locale_to_utf8 (request_in);
    uint32_t len = strlen(request) + 1;

    if (ext_pipe_writen(ext_pipe, &len, sizeof(len)) < 0) {
        free (request);
        return -1;
    }

    if (ext_pipe_writen(ext_pipe, request, len) < 0) {
        free (request);
        return -1;
    }

    free(request);
    return 0;
}

char *
read_ext_pipe_response ()
{
    uint32_t len; 
    if (ext_pipe_readn (ext_pipe, &len, sizeof(len)) < 0) {
        return NULL;
    }

    if (len == 0) {
        return NULL;
    }

    char *buf = (char *)malloc (len);

    if (ext_pipe_readn (ext_pipe, buf, len) < 0) {
        free (buf);
        return NULL;
    }

    /* Convert from utf8 to local encoding. */
    char *output = locale_from_utf8 (buf);
    free (buf);

    return output;
}

/* Get HANDLE to some process by name */
static HANDLE
get_process_handle (const char *process_name_in)
{
    char name[256];
    if (strstr(process_name_in, ".exe")) {
        snprintf (name, sizeof(name), "%s", process_name_in);
    } else {
        snprintf (name, sizeof(name), "%s.exe", process_name_in);
    }

    DWORD aProcesses[1024], cbNeeded, cProcesses;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
        return NULL;

    /* Calculate how many process identifiers were returned. */
    cProcesses = cbNeeded / sizeof(DWORD);

    HANDLE hProcess;
    HMODULE hMod;
    char process_name[MAX_PATH];
    unsigned int i;

    for (i = 0; i < cProcesses; i++) {
        if(aProcesses[i] == 0)
            continue;
        hProcess = OpenProcess (PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);
        if (!hProcess)
            continue;
            
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            GetModuleBaseName(hProcess, hMod, process_name, 
                              sizeof(process_name)/sizeof(char));
        }

        if (strcasecmp(process_name, name) == 0)
            return hProcess;
        else {
            CloseHandle(hProcess);
        }
    }
    /* Not found */
    return NULL;
}

/* Tell whether some process with given name is running */
BOOL
process_is_running (const char *process_name)
{
    HANDLE proc_handle = get_process_handle(process_name);

    if (proc_handle) {
        CloseHandle(proc_handle);
        return TRUE;
    } else {
        return FALSE;
    }
}

int
kill_process (const char *process_name)
{
    HANDLE proc_handle = get_process_handle(process_name);

    if (proc_handle) {
        TerminateProcess(proc_handle, 0);
        CloseHandle(proc_handle);
        return 0;
    } else {
        return -1;
    }
}

int
spawn_process (char *cmdline_in, char *working_directory)
{
    if (!cmdline_in)
        return -1;
    char *cmdline = strdup (cmdline_in);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    unsigned flags;
    BOOL success;

    /* we want to execute seafile without crreating a console window */
    flags = CREATE_NO_WINDOW;

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_FORCEOFFFEEDBACK | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_NORMAL;
        
    memset(&pi, 0, sizeof(pi));

    char old_wd[MAX_PATH];

    /* save previous wd */
    GetCurrentDirectory(sizeof(old_wd), old_wd);
    /* set seafile wd */
    SetCurrentDirectory (get_this_dll_folder());
    
    if (!working_directory) {
        working_directory = old_wd;
    }
    success = CreateProcess(NULL, cmdline, NULL, NULL, TRUE, flags,
                            NULL, working_directory, &si, &pi);
    /* restore previous wd */
    SetCurrentDirectory (old_wd);
    
    free (cmdline);
    if (!success) {
        seaf_ext_log ("failed to fork_process: GLE=%lu\n", GetLastError());
        return -1;
    }

    /* close the handle of thread so that the process object can be freed by
     * system
     */
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
