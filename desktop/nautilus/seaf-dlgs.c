#include "platform.h"

#include "seaf-dlgs.h"
#include "seaf-ext-log.h"
#include <pthread.h>
#include <unistd.h>

#define SEAF_PRIORITY_IDLE ((G_PRIORITY_DEFAULT_IDLE + G_PRIORITY_HIGH_IDLE) /2 )

typedef struct SeafExtMsg SeafExtMsg;
typedef struct SeafExtQuestion SeafExtQuestion;

struct SeafExtMsg {
    char *message;
    GtkMessageType type;
    void *user_data;
};

struct SeafExtQuestion {
    char *question;
    void *user_data;
    bool yes_no;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
};


SeafExtMsg *
seaf_ext_msg_new(char *msg_in, GtkMessageType type, void *user_data)
{
    if (!msg_in)
        return NULL;

    SeafExtMsg *msg = g_new0(SeafExtMsg, 1);

    msg->message = g_strdup(msg_in);
    msg->type = type;
    msg->user_data = user_data;

    return msg;
}

SeafExtQuestion *
seaf_ext_question_new (char *question_in, void *user_data)
{
    if (!question_in)
        return NULL;

    SeafExtQuestion *q = g_new0(SeafExtQuestion, 1);

    q->question = g_strdup(question_in);
    q->user_data = user_data;

    return q;
}


static bool msgbox_wrapper(SeafExtMsg *msg)
{
    GtkWidget *dialog = gtk_message_dialog_new
        ((GtkWindow *)msg->user_data,
         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
         msg->type,
         GTK_BUTTONS_OK,
         "%s",
         msg->message);

    if (dialog) {
        gtk_window_set_title(GTK_WINDOW(dialog), "Seafile");
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
    }

    g_free(msg);

    return FALSE;
}

void msgbox_full(char *msg_in, GtkMessageType type, void *user_data)
{
    SeafExtMsg *msg = seaf_ext_msg_new(msg_in, type, user_data);

    if(!msg)
        return;

    /* If this function is called from main thread, then just show the dialog.
     * If it's called from another thread, wee need to use g_idle_add_full()
     * to add this show-dialog action to the main thread
     */
    if (is_main_thread())
        msgbox_wrapper(msg);
    else {
        g_idle_add_full
            (SEAF_PRIORITY_IDLE, (GSourceFunc)msgbox_wrapper,
             msg, NULL);
    }
}


static bool msgbox_yes_or_no_wrapper(SeafExtQuestion *q)
{

    GtkWidget *dialog = gtk_message_dialog_new
        ((GtkWindow *)q->user_data,
         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
         GTK_MESSAGE_QUESTION,
         GTK_BUTTONS_YES_NO,
         "%s",
         q->question);

    pthread_mutex_lock(&q->mutex);

    int result = 0;

    if (dialog) {
        gtk_window_set_title(GTK_WINDOW(dialog), "Seafile");
        result = gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
    }

    q->yes_no = (result == GTK_RESPONSE_YES);

    pthread_cond_signal(&q->cond);
    pthread_mutex_unlock(&q->mutex);

    return FALSE;
}

bool msgbox_yes_or_no(char *question_in, void *user_data)
{
    SeafExtQuestion *q = seaf_ext_question_new(question_in, user_data);

    if (!q)
        return FALSE;

    if (is_main_thread()) {
        /* in main thread */
        GtkWidget *dialog = gtk_message_dialog_new
            ((GtkWindow *)q->user_data,
             GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
             GTK_MESSAGE_QUESTION,
             GTK_BUTTONS_YES_NO,
             "%s",
             q->question);

        g_free(q->question);
        g_free(q);

        int result = 0;

        if (dialog) {
            gtk_window_set_title(GTK_WINDOW(dialog), "Seafile");
            result = gtk_dialog_run(GTK_DIALOG(dialog));
            gtk_widget_destroy(dialog);
        }

        return (result == GTK_RESPONSE_YES);

    } else {
        /* Not in main thread. */
        bool yes_no = FALSE;
        if (pthread_mutex_init(&q->mutex, NULL) != 0) {
            goto on_error;
        }

        if (pthread_cond_init(&q->cond, NULL) != 0) {
            goto on_error;
        }

        pthread_mutex_lock(&q->mutex);

        g_idle_add_full (SEAF_PRIORITY_IDLE,
                         (GSourceFunc)msgbox_yes_or_no_wrapper,
                         q,
                         NULL);

        pthread_cond_wait(&q->cond, &q->mutex);

        yes_no = q->yes_no;

        /* clean up */

        pthread_mutex_unlock(&q->mutex);
        pthread_mutex_destroy(&q->mutex);
        pthread_cond_destroy(&q->cond);

    on_error:
        g_free(q->question);
        g_free(q);

        return yes_no;
    }
}

