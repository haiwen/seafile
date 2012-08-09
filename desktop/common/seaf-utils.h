/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#ifndef SEAF_UTILS_H
#define SEAF_UTILS_H

#include "platform.h"

struct SeafMenu;

/* void seaf_menu_ref(struct SeafMenu *seaf_menu); */
/* void seaf_menu_unref(struct SeafMenu *seaf_menu); */

/* s = s1 + s2, free s when not using it anymore. */
char *do_str_add (const char *s1, const char *s2);

/* Make all `path' in the shell extension use consistent style, such
 * as path seperator, captalized C/D/E for win32, etc.
 */
char* regulate_path(char *path);


/* Analyse the current direcotry by querying the daemon. If its in a
 * repo dir, get the repo id and worktree path.
 */
void get_repo_id_wt (struct SeafMenu *seaf_menu);

/* Test whether dirname `dir' is a top repo dir */
bool is_repo_top_dir(char *dir);

/* Initialize mutex for repo info cache */
bool seaf_ext_mutex_init();

int update_repo_cache();

/* Send a request to ext pipe, but does not need the response */
int send_ext_pipe_request (const char *request);

/* Send a request to ext pipe, and get the response back. The response has
 * already been converted to local encoding (GBK on windows). On error, NULL
 * is returned. Free the response string when done.
 */
char *get_ext_pipe_response(const char *request);


#endif  /* SEAF_UTILS_H */
