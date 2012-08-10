/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SEAF_PLATFORM_H
#define SEAF_PLATFORM_H

#ifndef WIN32
#define _GNU_SOURCE
#endif

/* platform dependent stuff */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>

#define SEAF_HTTP_ADDR "http://127.0.0.1:13420"

/* WIN32 is defined on both mingw-32 and mingw-64;
 * WIN64 is only defined on mingw-64
 */
#ifdef WIN32

#define sleep(x) Sleep(x * 1000)
#include <windows.h>
#include <shlwapi.h>    
#include <shlobj.h>
#include "seaf-lang-gbk.h"

#define str_case_str StrStrI
#define bool BOOL
#define SEAF_EXT_UI_DIR
#define ICON_EXT ".ico"

#ifndef WIN64
    /* this flag does not make sense on non-64 bit windows */
    #define KEY_WOW64_64KEY 0   
#endif 

#else  /* LINUX */

#include <unistd.h>
#include <gtk/gtk.h>
#include <libnautilus-extension/nautilus-menu-provider.h>
#include "seaf-lang.h"

#define bool gboolean
#define MAX_PATH PATH_MAX
#define str_case_str strcasestr    
#define ICON_EXT ".ico"

#endif

const char *get_home_dir();

/* escape a path to uri */
char *seaf_uri_escape(const char *path);

/* test whether a process with a given name is running */
bool process_is_running (const char *process_name);

/* Convert between utf-8 and current os locale. The returned string
 * should be freed after use.
 */
inline char *locale_to_utf8 (const char *src);
inline char *locale_from_utf8 (const char *src);

/* If `path' is a normal file, return the path of the folder containing
 * it(with the trailing '/'); If `path' is a folder, return strdup(path)
 */
char *get_folder_path (const char *path);

/* Get the base name of a path. */
char *get_base_name (const char *path);

struct menu_item;
struct SeafMenu;

/* Insert a new menu item according to its type */
bool build_menu_item(struct SeafMenu *menu, const struct menu_item *mi);

/* Open the url in default web browser */
void open_browser(char *url);

bool seaf_mutex_init (void *p_mutex);

/* Try to accuqire the `mutex', blocking if `blocking' param is TRUE.
 * When `blocking' is TRUE, this funciton won't return until the mutex
 * is accquired. When `blocking' is FALSE, return immediately with the
 * return value indicating whether the mutex is accquired or not.
 */
inline bool seaf_mutex_acquire(void *vmutex, bool blocking);

/* Release a lock held by me. */
inline bool seaf_mutex_release(void *vmutex);

/* use threads to handle menu commands asynchronously */
typedef int (*SeafThreadFunc)(void *);

typedef struct seaf_ext_job {
    SeafThreadFunc          thread_func;
    void                    *data;
} SeafExtJob;

/* Start a new thread to run a menu command; If p_handle is not null, then its
 * value is set to the handle of the created thread; Otherwise the new thread
 * handle is closed(in windows).
 */
int seaf_ext_start_thread(SeafThreadFunc thread_func, void *data, void *p_handle);

/* Note: Acquire the pipe_mutex before call any of these three functions, or
 * r/w the value of `ext_pipe_connected' */
int send_ext_pipe_request_wrapper (const char *request);

char *read_ext_pipe_response ();

int connect_ext_pipe ();

inline bool ext_pipe_is_connected ();

int spawn_process (char *cmdline_in, char *working_directory);

#ifdef WIN32

/**
 * ---------------------------------
 * WIN32 Specific functions
 * ---------------------------------
 */

/* Get the path to this dll */
const char *get_this_dll_filename();
/* Get the folder containing this dll */
const char *get_this_dll_folder();

/* Convert from wchar_t string to multi-byte char string */
char *wchar_to_char (const wchar_t *src);
wchar_t *char_to_wchar (const char *src);

int kill_process (const char *process_name);

int seaf_ext_pipe_prepare();

#else

/* Linux specific functions */

bool is_main_thread();

#endif

#endif /* SEAF_PLATFORM_H */

