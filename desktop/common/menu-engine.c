/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "platform.h"

#include <ctype.h>

#include "strbuf.h"
#include "seaf-utils.h"
#include "seaf-dlgs.h"

#ifdef WIN32
    #include "../explorer/seaf-menu.h"
#else
    #include "../nautilus/seaf-menu.h"
#endif

#include "seaf-ext-log.h"

#include "menu-engine.h"


#ifndef WIN32

extern void send_refresh_menu_signal();
#define UPDATE_MENU                                         \
    do {                                                    \
        send_refresh_menu_signal(seaf_menu->menu_provider); \
    } while (0)

#else

#define UPDATE_MENU
extern void append_active_menu(SeafMenu *seaf_menu, const struct menu_item *item);

#endif

extern void reset_active_menu(SeafMenu *seaf_menu);

/**
   We use the following struct to contain all possible menu items.

   When query_context_menu is called, we first build a mask, i.e. the
   'selection' variable, according to the file/folder current being clicked
   on, and build a customized menu by matching the selection mask with every
   menu item's flags field.

   For win32:

   At the same time, every selected menu item is added to the active_menu[]
   list, so later when the Shell calls "get_command_string" or
   "invoke_command", we can provide what he wants by referring to this list.

   Strings are all kept in `seaf-lang.h'.
**/

static struct menu_item seafile_menu[] = {
    { SEAF_MI_NODAEMON,
      SEAF_RUN_APPLET,
      MENU_STRING_START_SEAFILE,
      MENU_HELPTEXT_START_SEAFILE,
      SEAF_EXT_UI_DIR "seaf_ext_start" ICON_EXT},
    
    /*
    { SEAF_MI_DAEMON,
      SEAF_REFRESH_CACHE,
      MENU_STRING_REFRESH,
      MENU_HELPTEXT_REFRESH,
      SEAF_EXT_UI_DIR "seaf_ext_refresh" ICON_EXT},
    */

    /* { SEAF_MI_DAEMON | SEAF_MI_NOREPO, */
    /*   SEAF_INIT, */
    /*   MENU_STRING_INIT_REPO, */
    /*   MENU_HELPTEXT_INIT_REPO, */
    /*   SEAF_EXT_UI_DIR "seaf_ext_create" ICON_EXT}, */

    { SEAF_MI_DAEMON | SEAF_MI_REPO,
      SEAF_OPEN_WEB,
      MENU_STRING_OPEN_WEB,
      MENU_HELPTEXT_OPEN_WEB,
#ifdef WIN32
      SEAF_EXT_UI_DIR "seaf_ext_web_ie" ICON_EXT,
#else
      SEAF_EXT_UI_DIR "seaf_ext_web_fx" ICON_EXT,
#endif
    },

#ifdef WIN32
    { SEAF_MI_DAEMON | SEAF_MI_REPO, SEAF_NONE, NULL, NULL, NULL},
#endif
    
#ifdef WIN32    
#define _MI_AUTO 0
#define _MI_MANUAL 0
#else
#define _MI_AUTO SEAF_MI_TURN_ON_AUTO    
#define _MI_MANUAL SEAF_MI_TURN_OFF_AUTO    
#endif

    { SEAF_MI_DAEMON | SEAF_MI_REPO | _MI_AUTO,
      SEAF_TURN_ON_AUTO,
      MENU_STRING_AUTO, 
      MENU_HELPTEXT_AUTO,
      SEAF_EXT_UI_DIR "seaf_ext_auto" ICON_EXT},

    { SEAF_MI_DAEMON | SEAF_MI_REPO | _MI_MANUAL,
      SEAF_TURN_OFF_AUTO,
      MENU_STRING_MANUAL, 
      MENU_HELPTEXT_MANUAL,
      SEAF_EXT_UI_DIR "seaf_ext_manual" ICON_EXT},
    
};

char *seaf_ext_ico;
char *seaf_repo_ico;

void translate_icon_paths()
{
    static bool done = FALSE;
    if (done)
        return;

    const char *folder;

    char *icon_subdir;
    
#ifdef WIN32
    folder = get_this_dll_folder();
    icon_subdir = "icons/";
#else    
    folder = SEAF_EXT_UI_DIR;
    icon_subdir = "";
#endif

#define DO_TRANSLATE(icon, name)                        \
    do {                                                \
        struct strbuf sb = STRBUF_INIT;                 \
        strbuf_addstr(&sb, folder);                     \
        strbuf_addstr(&sb, icon_subdir);                \
        strbuf_addstr(&sb, name);                       \
        icon = strbuf_detach(&sb, NULL);                \
    } while (0)

    int n = sizeof(seafile_menu) / sizeof(struct menu_item);
    for (n--; n >= 0; n--) {
        char *icon = seafile_menu[n].icon;
        if (icon) {
            DO_TRANSLATE (seafile_menu[n].icon, icon);
        }
    }
    
    DO_TRANSLATE (seaf_ext_ico, "seaf_ext" ICON_EXT);
    DO_TRANSLATE (seaf_repo_ico, "seaf_repo" ICON_EXT);

    done = TRUE;
    seaf_ext_log ("icon path caculated");
}

static inline void
start_thread(SeafThreadFunc func, void *data)
{
    seaf_ext_start_thread(func, data, NULL);
}

static inline bool
ccnet_applet_is_running ()
{
    return process_is_running ("seafile-applet");
}

static int
do_open_browser (SeafMenu *seaf_menu)
{
    char *repo_id = seaf_menu->repo_id;
    char *url = NULL;
    char *s = SEAF_HTTP_ADDR "/repo/?repo=";

    url = do_str_add (s, repo_id);
    open_browser(url);
    free(url);

    return 0;
}

static int
start_ccnet_applet (SeafMenu *seaf_menu)
{
    if (ccnet_applet_is_running())
        return 0;

    if (spawn_process("seafile-applet", NULL) < 0) {
        msgbox_warning (MSG_FAIL_TO_START_SEAFILE);
        return -1;
    }

    return 0;
}


static int
set_repo_auto (SeafMenu *seaf_menu, bool on)
{
    char *repo_id = seaf_menu->repo_id;
    char *cmd = on ? "set-auto" : "set-manual";

    char request[128];
    snprintf (request, sizeof(request), "%s\t%s", cmd, repo_id);
    
    int status = send_ext_pipe_request(request);
    if (status < 0) {
        msgbox_warning (MSG_OPERATION_FAILED);
    }
    
    UPDATE_MENU;
    return status;
}


static int set_repo_auto_on(SeafMenu *seaf_menu)
{
    return set_repo_auto(seaf_menu, TRUE);
}


static int set_repo_auto_off(SeafMenu *seaf_menu)
{
    return set_repo_auto(seaf_menu, FALSE);
}


/* Main command handler  */
void
dispatch_menu_command (void *arg1, void *arg2)
{
    SeafMenu *seaf_menu = NULL;
    seafile_op op = *(seafile_op *)arg2;

#ifdef WIN32    
    seaf_menu = arg1;
#else    
    NautilusMenuItem *item = arg1;
    seaf_menu = g_object_get_data((GObject *)item, "seaf_menu");
#endif    

    if (!seaf_menu)
        return;
    /* No daemon detected */
    if (op == SEAF_RUN_APPLET) {
        start_thread((SeafThreadFunc)start_ccnet_applet, seaf_menu);

    } else {
        switch (op) {
        case SEAF_OPEN_WEB:
            start_thread((SeafThreadFunc)do_open_browser, seaf_menu);
            break;

        case SEAF_TURN_OFF_AUTO:
            start_thread((SeafThreadFunc)set_repo_auto_off, seaf_menu);
            break;

        case SEAF_TURN_ON_AUTO:
            start_thread((SeafThreadFunc)set_repo_auto_on, seaf_menu);
            break;

        default:
            break;
        }
    }
}

static bool
repo_is_auto (const char *repo_id)
{
    char request[128];
    bool result = FALSE;
    snprintf (request, sizeof(request), "%s\t%s", "query-auto", repo_id);
    char *response = get_ext_pipe_response(request);
    if (response && strcmp(response, "true") == 0) {
        result = TRUE;
    } else {
        result = FALSE;
    }
    
    if (response) {
        free (response);
    }
    else 
        seaf_ext_log ("query-auto returned NULL!");
    
    return result;
}

static void
build_menu_mask(SeafMenu *seaf_menu)
{
    /* Don't show seafile menu when seafile-applet is not running */
    if (!ext_pipe_is_connected() && connect_ext_pipe() < 0) {
        /* seaf_menu->selection = SEAF_MI_ALWAYS | SEAF_MI_NODAEMON; */
        return;
    }

    seaf_menu->selection |= SEAF_MI_DAEMON;
    get_repo_id_wt (seaf_menu);
    if (!ext_pipe_is_connected())
        goto out;
    if (seaf_menu->repo_id[0] == '\0') {
        /* Not in a seaf repo */
        seaf_menu->selection |= SEAF_MI_NOREPO;
        
    } else {
        seaf_menu->selection |= SEAF_MI_REPO;
        if (repo_is_auto(seaf_menu->repo_id)) {
            seaf_menu->selection |= SEAF_MI_TURN_OFF_AUTO;
        } else {
            seaf_menu->selection |= SEAF_MI_TURN_ON_AUTO;
        }
    }

out:
    if (!ext_pipe_is_connected())
        seaf_menu->selection = SEAF_MI_ALWAYS | SEAF_MI_NODAEMON;
}

static void
build_menu_by_mask (SeafMenu *seaf_menu)
{
    int i;
    int n = sizeof(seafile_menu) / sizeof(struct menu_item);
    
    /* Build menu according to 'selection' mask */
    for (i = 0; i < n; i++) {
        unsigned int flags = seafile_menu[i].flags;
        if ((flags & seaf_menu->selection) == flags) {
            if (!build_menu_item (seaf_menu, &seafile_menu[i]))
                break;
#ifdef WIN32
            append_active_menu(seaf_menu, &seafile_menu[i]);
#endif
        }
    }
}
    
/* The main function in this module. */
int build_seafile_menu(SeafMenu *seaf_menu)
{
    reset_active_menu(seaf_menu);
    build_menu_mask (seaf_menu);
    build_menu_by_mask (seaf_menu);

    return 0;
}
