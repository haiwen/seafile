#include "common.h"

#include <ccnet.h>
#include <ccnet/cevent.h>

#include "seaf-ext.h"
#include "seafile-session.h"
#define DEBUG_FLAG SEAFILE_DEBUG_OTHER
#include "log.h"
#include "repo-mgr.h"
#include "utils.h"
#include "seafile-rpc.h"
#include "seafile-session.h"
#include "mq-mgr.h"

static void *ext_pipe_job (void *vpipe);
static char *ext_handle_input (const char *input);
static void *seaf_extension_pipe_listen (void *data);

#define PIPE_BUFSIZE 1024

#ifdef WIN32
    #include <windows.h>
    #define SEAF_EXT_PIPE_NAME "\\\\.\\pipe\\seafile_ext_pipe"
#else
    #include <sys/socket.h>
    #include <sys/un.h>
    #define SEAF_EXT_UNIX_SOCKET "/tmp/seafile-ext.socket"
#endif

int
seaf_extension_pipe_start (SeafileSession *session)
{
    ccnet_job_manager_schedule_job (session->job_mgr,
                                    seaf_extension_pipe_listen,
                                    NULL, NULL);

    return 0;
}


#ifdef WIN32

/* Here we create the named pipe to communicate with the explorer extension.
 * In the explorer extension, we try to connect to this named pipe every five
 * seconds if it's not connected yet, or the connected pipe was shutdown
 * because of the quit of seafile daemon. Once we establish the connection,
 * the extension can obtain information from seafile daemon.
 */
static void *
seaf_extension_pipe_listen (void *data)
{
    while (1) {
        HANDLE hPipe = INVALID_HANDLE_VALUE;
        BOOL connected = FALSE;

        hPipe = CreateNamedPipe( 
            SEAF_EXT_PIPE_NAME,       // pipe name 
            PIPE_ACCESS_DUPLEX,       // read/write access 
            PIPE_TYPE_MESSAGE |       // message type pipe 
            PIPE_READMODE_MESSAGE |   // message-read mode 
            PIPE_WAIT,                // blocking mode 
            PIPE_UNLIMITED_INSTANCES, // max. instances  
            PIPE_BUFSIZE,             // output buffer size 
            PIPE_BUFSIZE,             // input buffer size 
            0,                        // client time-out 
            NULL);                    // default security attribute 

        if (hPipe == INVALID_HANDLE_VALUE) {
            seaf_warning ("Failed to create named pipe, GLE=%lu\n", GetLastError());
            return NULL;
        }
        
        /* listening on this pipe */
        connected = ConnectNamedPipe(hPipe, NULL) ? 
            TRUE : (GetLastError() == ERROR_PIPE_CONNECTED); 

        if (!connected) {
            seaf_warning ("Failed on ConnectNamedPipe(), GLE=%lu\n",
                          GetLastError());
            CloseHandle(hPipe);
            return NULL;
        }

        seaf_debug ("[ext pipe] Accepted an extension pipe client\n");
        /* We use a seperate thread to communicate with this pipe client  */
        ccnet_job_manager_schedule_job (seaf->job_mgr, ext_pipe_job, NULL, hPipe);
    }
    return NULL;
}

static int
ext_pipe_readn (void *vpipe, void *buf, size_t len)
{
    HANDLE hPipe = (HANDLE)vpipe;
    BOOL success;
    DWORD bytesRead;

    success = ReadFile(
        hPipe,                 // handle to pipe 
        buf,                   // buffer to receive data 
        (DWORD)len,            // size of buffer 
        &bytesRead,            // number of bytes read 
        NULL);                 // not overlapped I/O
    
    if (!success || bytesRead != (DWORD)len) {
        DWORD error = GetLastError();
        if (error == ERROR_BROKEN_PIPE) {
            seaf_debug ("[ext pipe] the other end of ext pipe is closed\n");
        } else {
            seaf_warning ("[ext pipe] Failed to ReadFile(), GLE=%lu\n", error);
        }

        return -1;
    }

    return 0;
}

static int
ext_pipe_writen (void *vpipe, void *buf, size_t len)
{
    HANDLE hPipe = (HANDLE)vpipe;
    BOOL success;
    DWORD bytesWritten;
    success = WriteFile(
        hPipe,                  // handle to pipe
        buf,                    // buffer to write from
        (DWORD)len,             // number of bytes to write
        &bytesWritten,          // number of bytes written
        NULL);                  // not overlapped I/O

    if (!success || bytesWritten != (DWORD)len) {
        DWORD error = GetLastError();
        if (error == ERROR_BROKEN_PIPE) {
            seaf_debug ("[ext pipe] the other end of ext pipe is closed\n");
        } else {
            seaf_warning ("[ext pipe] Failed to ReadFile(), GLE=%lu\n", error);
        }
        return -1;
    }
    
    FlushFileBuffers(hPipe);
    return 0;
}

static void
ext_pipe_on_exit(void *vpipe)
{
    HANDLE hPipe = (HANDLE)vpipe;
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    seaf_warning ("An extension pipe thread now quit : GLE=%lu\n",
                  GetLastError());
}

#else  /* ifdef WIN32 */

void *
seaf_extension_pipe_listen (void *data)
{
    int ext_serv_fd = socket (AF_UNIX, SOCK_STREAM, 0);
    if (ext_serv_fd < 0) {
        seaf_warning ("Failed to create extension unix socket fd : %s\n",
                      strerror(errno));
        goto failed;
    }

    struct sockaddr_un saddr;
    saddr.sun_family = AF_UNIX;
    const char *un_path = SEAF_EXT_UNIX_SOCKET;
    if (g_file_test (un_path, G_FILE_TEST_EXISTS)) {
        seaf_warning ("socket file exists, delete it anyway\n");
        if (g_unlink (un_path) < 0) {
            seaf_warning ("delete socket file failed : %s\n", strerror(errno));
            goto failed;
        }
    }
    memcpy(saddr.sun_path, un_path, strlen(un_path) + 1);
    if (bind(ext_serv_fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        seaf_warning ("failed to bind unix socket fd to %s : %s\n",
                      un_path, strerror(errno));
        goto failed;
    }

    if (listen(ext_serv_fd, 3) < 0) {
        seaf_warning ("failed to listen: %s\n", strerror(errno));
        goto failed;
    }

    while (1) {
        int connfd = accept(ext_serv_fd, NULL, NULL);
        if (connfd < 0) {
            seaf_warning ("failed to accept: %s\n", strerror(errno));
            goto failed;
        }
        seaf_debug ("Accepted an extension pipe client\n");
        ccnet_job_manager_schedule_job (seaf->job_mgr, ext_pipe_job,
                                        NULL, (void *)(long)connfd);
    }
        
 failed:
    return NULL;
}

static int
ext_pipe_readn (void *vpipe, void *buf, size_t len)
{
    int connfd = (int)(long)vpipe;
    if (readn (connfd, buf, len) != len) {
        seaf_warning ("Failed to read: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static int
ext_pipe_writen (void *vpipe, void *buf, size_t len)
{
    int connfd = (int)(long)vpipe;
    if (writen (connfd, buf, len) != len) {
        seaf_warning ("Failed to write: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static void
ext_pipe_on_exit(void *vpipe)
{
    int connfd = (int)(long)vpipe;
    close (connfd);
    seaf_warning ("An extension pipe thread now quit : %s\n",
                  strerror(errno));
}

#endif

static void *
ext_pipe_job (void *vpipe)
{
    uint32_t len;
    char *buf;
    char *reply;
    
    while (1) {
        if (ext_pipe_readn (vpipe, &len, sizeof(len)) < 0) 
            break;

        if (len == 0)
            break;
            
        buf = g_malloc (len);
        
        if (ext_pipe_readn (vpipe, buf, len) < 0)
            break;

        reply = ext_handle_input (buf);
        g_free (buf);
        if (!reply)
            continue;
        
        len = strlen(reply) + 1;
        
        if (ext_pipe_writen(vpipe, &len, sizeof(len)) < 0) {
            g_free (reply);
            break;
        }

        if (ext_pipe_writen(vpipe, reply, len) < 0) {
            g_free (reply);
            break;
        }

        g_free (reply);
    }

    ext_pipe_on_exit(vpipe);
    return NULL;
}

struct ext_cmd
{
    char    *name;
    char    *(*func) (int argc, char **argv);
    
    /* extension dll expects feedback for this command */
    gboolean need_feedback;      
};

static char *ext_list_worktree      (int,  char **);
static char *ext_set_auto           (int,  char **);
static char *ext_set_manual         (int,  char **);
static char *ext_query_auto         (int,  char **);

static struct ext_cmd ext_cmdtab[] = {
    { "list-worktree",      ext_list_worktree,  1 },
    { "set-auto",           ext_set_auto,       0 },
    { "set-manual",         ext_set_manual,     0 },
    { "query-auto",         ext_query_auto,     1 },
    { NULL, NULL, 0 },
};

/**
 * Note: Some commands should return something, while others need not. For
 * those which are expected to return something, We must return something even
 * if the commands failed internally. Or the extension would get a wait
 * timeout on this pipe, and behave incorrectly.
 */
static char *
ext_handle_input (const char *input)
{
    if (!input || strlen(input) == 0)
        return 0;
    /* parse argc & argv */
    char **argv = g_strsplit (input, "\t", 100);
    char **ptr = argv;
    int argc = 0;
    char *result = NULL;
    while (*ptr) {
        argc++;
        ptr++;
    }

    /* find the cmd handler  */
    struct ext_cmd *cmd;
    for (cmd = ext_cmdtab; cmd->name; cmd++) {
        if (g_strcmp0(cmd->name, argv[0]) == 0)
            break;
    }

    if (!cmd->func) {
        seaf_warning ("Unknown ext cmd : %s\n", argv[0]); 
        goto out;
    }

    /* run the handler */
    result =  cmd->func (argc - 1, argv + 1);

    if (!result && cmd->need_feedback) {
        result = g_strdup("");
    }
out:
    g_strfreev(argv);
    return result;
}

static char *
ext_list_worktree (int argc, char **argv)
{
    GString *result = g_string_new(NULL);
    char *str;
    if (argc != 0) {
        seaf_warning ("Wrong number of args: %d:%d\n", argc, 0); 
        goto norepo;
    }

    GList *repo_list, *ptr;
    repo_list = seaf_repo_manager_get_repo_list (seaf->repo_mgr, -1, -1);
    if (!repo_list)
        goto norepo;
    
    for (ptr = repo_list; ptr; ptr = ptr->next) {
        SeafRepo *repo = ptr->data;
        if (!repo->worktree)
            /* Not checked out yet. */
            continue;
        g_string_append_printf (result, "%s\t%s\n", repo->id, repo->worktree);
    }
        
    g_list_free (repo_list);

norepo:
    str = result->str;
    g_string_free (result, FALSE);
    return str;
}
    
static char *
ext_set_auto_common (char *repo_id, char *value)
{
    SeafRepoManager *repo_mgr = seaf->repo_mgr;
    
    if (seaf_repo_manager_set_repo_property
        (repo_mgr, repo_id, REPO_AUTO_SYNC, value) < 0)
        goto failed;

failed:
    return NULL;
}
        
static char *
ext_set_auto (int argc, char **argv)
{
    if (argc != 1) {
        seaf_warning ("Wrong number of args: %d:%d\n", argc, 1); 
        return NULL;
    }
    char *repo_id = argv[0];
    return ext_set_auto_common (repo_id, "true");
}

static char *
ext_set_manual (int argc, char **argv)
{
    if (argc != 1) {
        seaf_warning ("Wrong number of args: %d:%d\n", argc, 1); 
        return NULL;
    }
    char *repo_id = argv[0];
    return ext_set_auto_common (repo_id, "false");
}

static char *
ext_query_auto (int argc, char **argv)
{
    if (argc != 1) {
        seaf_warning ("Wrong number of args: %d:%d\n", argc, 0); 
        goto error;
    }

    char *repo_id = argv[0];
    SeafRepo *repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        seaf_warning ("[ext pipe] no repo %.10s exits\n", repo_id);
        goto error;
    }
    
    if (repo->auto_sync) {
        return g_strdup("true");
    } else {
        return g_strdup("false");
    }
error:
    return NULL;
}
