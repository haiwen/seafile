#include "platform.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/select.h>
#include <pthread.h>
#include <dirent.h>
#include <libnautilus-extension/nautilus-menu-provider.h>

#include "seaf-utils.h"
#include "seaf-dlgs.h"
#include "seaf-ext-log.h"
#include "menu-engine.h"


const char *
get_home_dir()
{
    static char *home;
    if (!home) {
        home = strdup(getenv("HOME"));
        regulate_path(home);
    }

    return home;
}

bool
seaf_mutex_init (void *vmutex)
{
    pthread_mutex_t *p_mutex = vmutex;

    int ret = pthread_mutex_init(p_mutex, NULL);
    if (ret != 0) {
        seaf_ext_log ("failed to init pthread mutex, "
                      "error code %d", ret);
        return FALSE;
    }

    return TRUE;
}

inline bool
seaf_mutex_acquire(void *vmutex, bool blocking)
{
    pthread_mutex_t *p_mutex = vmutex;

    int ret = 0;

    if (blocking)
        ret = pthread_mutex_lock(p_mutex);
    else
        ret = pthread_mutex_trylock(p_mutex);

    return (ret == 0);
}

inline bool
seaf_mutex_release(void *vmutex)
{
    pthread_mutex_t *p_mutex = vmutex;

    int ret = pthread_mutex_unlock(p_mutex);

    return (ret == 0);
}

/* Read "n" bytes from a descriptor. */
static ssize_t
readn(int fd, void *vptr, size_t n)
{
	size_t	nleft;
	ssize_t	nread;
	char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nread = read(fd, ptr, nleft)) < 0) {
			if (errno == EINTR)
				nread = 0;		/* and call read() again */
			else
				return(-1);
		} else if (nread == 0)
			break;				/* EOF */

		nleft -= nread;
		ptr   += nread;
	}
	return(n - nleft);		/* return >= 0 */
}

/* Write "n" bytes to a descriptor. */
static ssize_t
writen(int fd, const void *vptr, size_t n)
{
	size_t		nleft;
	ssize_t		nwritten;
	const char	*ptr;

	ptr = vptr;
	nleft = n;
	while (nleft > 0) {
		if ( (nwritten = write(fd, ptr, nleft)) <= 0) {
			if (nwritten < 0 && errno == EINTR)
				nwritten = 0;		/* and call write() again */
			else
				return(-1);			/* error */
		}

		nleft -= nwritten;
		ptr   += nwritten;
	}
	return(n);
}

/* Use a wrapper in case we need to extend it in the future */
static void *
job_thread_wrapper (void *vdata)
{
    SeafExtJob *job = vdata;

    int status = job->thread_func(job->data);

    free (job);

    return (void *)(long)status;
}

int
seaf_ext_start_thread(SeafThreadFunc thread_func, void *data, void *p_handle)
{
    SeafExtJob *job = g_new0(SeafExtJob, 1);
    job->thread_func = thread_func;
    job->data = data;

    pthread_t pt;
    int ret = pthread_create
        (&pt,
         NULL,                  /* pthread_attr_t */
         job_thread_wrapper,    /* start routine */
         job);                  /* start routine data */

    if (ret != 0) {
        seaf_ext_log ("failed to create pthread, error code %d", ret);
        g_free(job);
        return -1;
    }
    
    if (p_handle)
        *(pthread_t *)p_handle = pt;

    return 0;
}


/* read the link of /proc/123/exe and compare with `process_name' */
static int
find_process_in_dirent(struct dirent *dir, char *process_name)
{
    char path[512];
    /* fisrst construct a path like /proc/123/exe */
    if (sprintf (path, "/proc/%s/exe", dir->d_name) < 0) {
        return -1;
    }
    char buf[MAX_PATH];
    /* get the full path of exe */
    ssize_t l = readlink(path, buf, MAX_PATH);

    if (l<0)
        return -1;
    buf[l] = '\0';
    /* get the base name of exe */
    char *base = g_path_get_basename(buf);
    int ret = strcmp(base, process_name);
    g_free(base);
    if (ret == 0)
        return atoi(dir->d_name);
    else
        return -1;
}

/* read the /proc fs to determine whether some process is running */
bool
process_is_running (const char *process_name)
{
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        seaf_ext_log("Error: failed to open /proc dir: %s",
                     strerror(errno));
        return FALSE;
    }

    struct dirent *subdir = NULL;
    while ((subdir = readdir(proc_dir))) {
        char first = subdir->d_name[0];
        /* /proc/[1-9][0-9]* */
        if (first > '9' || first < '1')
            continue;
        int pid = find_process_in_dirent(subdir, (char*)process_name);
        if (pid > 0) {
            closedir(proc_dir);
            return TRUE;
        }
    }
    closedir(proc_dir);
    /* seaf_ext_log("No %s running", process_name); */
    return FALSE;
}

bool
is_main_thread()
{
    GMainContext *main_context = g_main_context_default();

    if (g_main_context_is_owner(main_context)) {
        /* seaf_ext_log ("You are the owner of main context\n"); */
        return TRUE;
    } else {
        /* seaf_ext_log ("You are not the owner of main context\n"); */
        return FALSE;
    }
}


char *get_folder_path (const char *path)
{
    if (!path)
        return NULL;
    
    if (g_file_test(path, G_FILE_TEST_IS_DIR))
        return g_strdup(path);

    return g_path_get_dirname(path);
}

char *
get_base_name(const char *path)
{
    if (!path)
        return NULL;

    return g_path_get_basename (path);
}
    
static char browser_path[MAX_PATH] = {'\0'};

static void find_browser()
{
    static char *browser_table[] =
        {"x-www-browser", "firefox", "chromium-browser", NULL};

    char *path = NULL;
    int i = 0;
    while (browser_table[i] && !path) {
        path = g_find_program_in_path(browser_table[i]);
        i++;
    }

    if (path) {
        memcpy (browser_path, path, strlen(path) + 1);
        seaf_ext_log("find web browser, %s", path);
        g_free (path);
    }

}

void open_browser(char *url)
{
    if (browser_path[0] == '\0')
        find_browser();

    /* still not found */
    if (browser_path[0] == '\0') {

        GString *gstr = g_string_new(MSG_BROWSER_NOT_FOUND);
        g_string_append_printf(gstr, MSG_OPEN_URL_YOURSELF ":\n%s", url);

        msgbox (gstr->str);
        g_string_free (gstr, TRUE);
        return;
    }

    seaf_ext_log("URL: %s", url);

    GString *gs = g_string_new (NULL);
    g_string_append_printf (gs, "%s %s", browser_path, url);
    if (spawn_process (gs->str, NULL) < 0) {
        msgbox_warning ("Failed to open browser");
    }
    g_string_free (gs, TRUE);
}


char *seaf_uri_escape(const char *path)
{
    char *uri = g_uri_escape_string(path, NULL, TRUE);
    return uri;
}

static bool ext_pipe_connected = FALSE;
static int ext_pipe = -1;

inline bool
ext_pipe_is_connected ()
{
    return ext_pipe_connected;
}

#define SEAF_EXT_UNIX_SOCKET "/tmp/seafile-ext.socket"

#define PIPE_WRITE_WAIT_TIME 1
#define PIPE_READ_WAIT_TIME 1

int
connect_ext_pipe ()
{
    ext_pipe = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ext_pipe < 0) {
        seaf_ext_log ("failed to create ext pipe : %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_un saddr;
    saddr.sun_family = AF_UNIX;
    const char *un_path = SEAF_EXT_UNIX_SOCKET;
    memcpy(saddr.sun_path, un_path, strlen(un_path) + 1);
    if (connect(ext_pipe, (struct sockaddr *)&saddr, (socklen_t)sizeof(saddr)) < 0) {
        /* seaf_ext_log ("Failed to connect : %s\n", strerror(errno)); */
        ext_pipe_connected = FALSE;
        return -1;
    }
    ext_pipe_connected = TRUE;
    seaf_ext_log ("ext pipe now connected");
    return 0;
}

int spawn_process (char *cmdline_in, char *working_directory)
{
    GError *error = NULL;
    gboolean result;

    result = g_spawn_command_line_async((const char*)cmdline_in, &error);

    if (!result) {
        seaf_ext_log ("Failed to spawn [%s] : %s", error->message);
        return -1;
    }
    return 0;
}

int
send_ext_pipe_request_wrapper (const char *request)
{
    uint32_t len = strlen(request) + 1;
    if (writen (ext_pipe, &len, sizeof(len)) != sizeof(len)) {
        seaf_ext_log ("[pipe write] Failed to write: %s", strerror(errno));
        goto failed;
    }
    if (writen (ext_pipe, request, len) != len) {
        seaf_ext_log ("[pipe write] Failed to write: %s", strerror(errno));
        goto failed;
    }

    return 0;
failed:
    ext_pipe_connected = FALSE;
    return -1;
}

char *
read_ext_pipe_response ()
{
    char *buf = NULL;
    uint32_t len = 0;
    fd_set read_fds;
    FD_ZERO (&read_fds);
    FD_SET(ext_pipe, &read_fds);
    struct timeval tv;
    tv.tv_sec = PIPE_READ_WAIT_TIME;
    tv.tv_usec = 0;
    int result = select(ext_pipe + 1, &read_fds, NULL, NULL, &tv);
    if (result < 0) {
        seaf_ext_log ("Failed to select: %s", strerror(errno));
        goto failed;
    } else if (result == 0) {
        seaf_ext_log ("Failed to select: timeout");
        goto failed;
    } else if (!FD_ISSET(ext_pipe, &read_fds)) {
        seaf_ext_log ("FD_ISSET() failes!");
        goto failed;
    }
        
    if (readn (ext_pipe, &len, sizeof(len)) != sizeof(len)
        || len <= 0) {
        seaf_ext_log ("Failed to read: %s", strerror(errno));
        goto failed;
    }
    
    buf = (char *)g_malloc (len);
    
    if (readn (ext_pipe, buf, len) != len) {
        seaf_ext_log ("Failed to read: %s", strerror(errno));
        goto failed;
    }
    return buf;

failed:
    ext_pipe_connected = FALSE;
    if (buf)
        g_free (buf);
    return NULL;
}

