#ifndef SEAF_DLGS_H
#define SEAF_DLGS_H

#include "platform.h"

#ifdef WIN32
typedef enum
{
  GTK_MESSAGE_INFO,
  GTK_MESSAGE_WARNING,
  GTK_MESSAGE_QUESTION,
  GTK_MESSAGE_ERROR,
  GTK_MESSAGE_OTHER
} GtkMessageType;
#endif 

void msgbox_full(char *msg_in, GtkMessageType type, void *user_data);

#define msgbox(msg) msgbox_full((msg), GTK_MESSAGE_INFO, NULL)

#define msgbox_warning(msg) msgbox_full((msg), GTK_MESSAGE_WARNING, NULL)

bool msgbox_yes_or_no(char *question_in, void *user_data);

void prompt_create_repo_dlg (const char *worktree);


#endif  /* SEAF_DLGS_H */
