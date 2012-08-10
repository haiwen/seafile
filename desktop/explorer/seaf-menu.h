/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SEAF_MENU_H
#define SEAF_MENU_H

typedef struct SeafMenu SeafMenu;

/* IShellExInit interface */
struct seaf_IShellExtInit {
    void *virtual_table;
    SeafMenu *seaf_menu;
};

/* IContextMenu interface */
struct SeafMenu {
    void *virtual_table;
    struct seaf_IShellExtInit ishellextinit;

    HMENU main_menu;            /* the main menu */
    HMENU sub_menu;             /* the popup seafile submenu */
    UINT index;
    UINT first;
    UINT last;
    struct menu_item *active_menu;
    unsigned int next_active_item;
    bool add_sep;
    
    unsigned int count;
    unsigned int selection;
    char name[MAX_PATH];      /* the file/dir current clicked on */
    char repo_id[37];         /* set if in a repo dir */
    char repo_wt[MAX_PATH];   /* repo top wt, set if in a repo dir */
};

SeafMenu *seaf_menu_new ();
void seaf_menu_free (SeafMenu *seaf_menu);

#endif /* SEAF_MENU_H */
