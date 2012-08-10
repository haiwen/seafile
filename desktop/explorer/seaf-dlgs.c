#include "platform.h"

#include "seaf-ext-log.h"
#include "seaf-dlgs.h"
#include "seaf-dll.h"
#include "seaf-utils.h"
#include "strbuf.h"

void msgbox_full(char *msg, GtkMessageType type, void *user_data)
{
    UINT mtype = MB_OK;
    if (type == GTK_MESSAGE_WARNING)
        mtype |= MB_ICONWARNING;

    MessageBox(NULL, msg, "Seafile", mtype);
}


bool msgbox_yes_or_no(char *question, void *user_data)
{
    if (!question)
        return FALSE;

    int res = MessageBox(NULL, question, "Seafile",
                         MB_ICONQUESTION | MB_YESNO); 

    return (res == IDYES);
}

