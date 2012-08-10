/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef MENU_ENGINE_H
#define MENU_ENGINE_H

/* Menu item flags */

#define     SEAF_MI_ALWAYS        (1 << 0)
#define     SEAF_MI_NOREPO        (1 << 1) /* not in a seaf repo */
#define     SEAF_MI_REPO          (1 << 2)
#define     SEAF_MI_WORKTREE_CHANGED         (1 << 3)
#define     SEAF_MI_WORKTREE_NOT_CHANGED     (1 << 4)
#define     SEAF_MI_TURN_ON_AUTO             (1 << 5)
#define     SEAF_MI_TURN_OFF_AUTO            (1 << 6)
#define     SEAF_MI_REPO_STATUS              (1 << 7)

#define     SEAF_MI_NODAEMON      (1 << 30) 
#define     SEAF_MI_DAEMON        (1 << 31) /* indicates need daemon or not */

typedef enum {
    SEAF_NONE = 0,                  /* for menu separator */
    SEAF_RUN_APPLET,
    SEAF_REFRESH_CACHE,
    SEAF_OPEN_WEB,
    SEAF_TURN_ON_AUTO,
    SEAF_TURN_OFF_AUTO,
    SEAF_OP_MAX,
} seafile_op;

struct menu_item {
    unsigned int flags;
    seafile_op op;
    char *string;               /* displayed in the menu */
    char *helptext;             /* displayed in the status bar */
    char *icon;                 /* icon file path */
};

struct SeafMenu;
/* called in query_context_menu, build a customized menu according to
 * the file current operated on.
 */
int build_seafile_menu(struct SeafMenu *data);

void dispatch_menu_command (void *arg1, void *arg2);

/* Translate path to menu item icon according to the user's installation path */
void translate_icon_paths();

#endif  /* MENU_ENGINE_H */
