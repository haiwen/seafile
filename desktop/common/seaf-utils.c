/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */


#include "platform.h"

#include <stdarg.h>

#include <ctype.h>
#include <time.h>

#include "strbuf.h"
#include "seaf-utils.h"
#include "seaf-ext-log.h"

#ifdef WIN32
    #include "../explorer/seaf-menu.h"
#else
    #include "../nautilus/seaf-menu.h"
#endif


#ifndef WIN32
extern void send_refresh_menu_signal(NautilusMenuProvider *);
#endif

typedef struct RepoInfo {
    char repo_id[37];
    char repo_wt[MAX_PATH];
} RepoInfo;

struct repo_cache {
    RepoInfo *info;
    int n_repo;
} ;

struct repo_cache repo_cache;

/* Mutex for repo cache r/w, and extension pipe r/w synchronization */
#ifdef WIN32
    HANDLE cache_mutex;
    HANDLE pipe_mutex;
#else
    #include <pthread.h>
    pthread_mutex_t cache_mutex;
    pthread_mutex_t pipe_mutex;
#endif


char *
do_str_add (const char *s1, const char *s2)
{
    if (!s1 && !s2)
        return NULL;
    
    if (!s1)
        return strdup(s2);

    if (!s2)
        return strdup(s1);
    
    struct strbuf sb = STRBUF_INIT;

    strbuf_addstr (&sb, s1);
    strbuf_addstr (&sb, s2);

    return strbuf_detach (&sb, NULL);
}

char*
regulate_path(char *p)
{
    if (!p)
        return NULL;

    char *s = p;
    /* Use capitalized C/D/E, etc. */
    if (s[0] >= 'a') 
        s[0] = toupper(s[0]);

    /* Use / instead of \ */
    while (*s) {
        if (*s == '\\')
            *s = '/';
        s++;
    }

    s--;
    /* strip trailing white spaces and path seperator */
    while (isspace(*s) || *s == '/') {
        *s = '\0';
        s--;
    }

    return p;
}

/* Tell if a dir is a subdir of an worktree path, we can't rely only on
 * strstr. For example, if /opt/my-repo is a worktree path, strstr will say
 * yes to /opt/my-repoxxx .
 */
static bool
dir_worktree_match (char *dir, char *worktree)
{
    if (str_case_str(dir, worktree) != dir)
        return FALSE;

    int len = strlen(worktree);

    if (dir[len] != '/' && dir[len] != '\0') {
        return FALSE;
    }

    return TRUE;
    
}

void
get_repo_id_wt (SeafMenu *seaf_menu)
{
    if (!seaf_menu) {
        return;
    }

    regulate_path(seaf_menu->name);
    update_repo_cache();

    seaf_mutex_acquire(&cache_mutex, TRUE);

    int i = 0;
    for (i = 0; i < repo_cache.n_repo; i++) {
        RepoInfo *p_info = &repo_cache.info[i];
        if (dir_worktree_match (seaf_menu->name, p_info->repo_wt)) {
            memcpy (seaf_menu->repo_id, p_info->repo_id, 37);
            memcpy (seaf_menu->repo_wt, p_info->repo_wt,
                    strlen(p_info->repo_wt) + 1);
            break;
        } else {
            /* seaf_ext_log("Not match:\n[%s] [%s]", */
            /*              seaf_menu->name, p_info->repo_wt); */
        }
    }

    seaf_mutex_release(&cache_mutex);
}

#ifdef WIN32
#define REPO_CACHE_REFRESH_INTERVAL 3 

static inline bool
need_fresh (SYSTEMTIME *last_refresh, SYSTEMTIME *now)
{
    if (now->wHour > last_refresh->wHour)
        return TRUE;

    if (now->wMinute > last_refresh->wMinute)
        return TRUE;

    if ((now->wSecond - last_refresh->wSecond) >= REPO_CACHE_REFRESH_INTERVAL)
        return TRUE;

    return FALSE;
}

#endif

bool
is_repo_top_dir(char *dir)
{
    bool ret = FALSE;

    regulate_path(dir);

#ifdef WIN32    
    static SYSTEMTIME last_refresh = { 0 };
    SYSTEMTIME now;
    GetLocalTime(&now);

    if (need_fresh (&last_refresh, &now)) {
        update_repo_cache();
        last_refresh = now;
    }
#else
    update_repo_cache();
#endif        
    seaf_mutex_acquire(&cache_mutex, TRUE);

    int i = 0;

    for (i = 0; i < repo_cache.n_repo; i++) {
        char *wt = repo_cache.info[i].repo_wt;
        if (strcmp (dir, wt) == 0) {
            ret = TRUE;
            break;
        }
    }

    seaf_mutex_release(&cache_mutex);

    return ret;
}


static bool
parse_id_worktree (char *line_in, char **repo_id, char **worktree)
{
    char *line = strdup(line_in);
    char *ptr = line;
    char *orig = line;

    /* skip spaces */
    while(isspace(*orig))
        orig++;

    if (!orig)
        return FALSE;

    /* The output of `seafile query' is "repo_id\tworktree", so we find the
     * first tab char and turn it to a NULL byte
     */
    while (*ptr != '\t' && *ptr != '\0')
        ptr++;

    if (*ptr == '\0')
        return FALSE;
    
    *ptr = '\0';

    *repo_id = strdup (orig);

    if (strlen(*repo_id) != 36) {
        seaf_ext_log ("invalid length(%d) of repo_id : %s",
                      strlen(*repo_id), *repo_id);
        free (*repo_id);
        return FALSE;
    }

    ptr++;

    *worktree = strdup (ptr);

    regulate_path (*worktree);

    free(line);

    return TRUE;
}

int
update_repo_cache()
{
    static const char *request = "list-worktree";
    char *output = get_ext_pipe_response(request);

    if (!output) {
        seaf_ext_log ("list-worktree returned NULL");
        return -1;
        
    } else {
        /* split output into lines */
        struct strbuf sb = STRBUF_INIT;
        strbuf_addstr (&sb, output);
        struct strbuf **line_v = strbuf_split (&sb, '\n');
        strbuf_release (&sb);

        /* first count repo numbers */
        int n_repo = 0;

        struct strbuf **ptr = line_v;

        while (*ptr) {n_repo++; ptr++;}

        RepoInfo *rinfo = NULL;
        /* valid repo count */
        int n_valid = 0;

        /* no repo */
        if (n_repo == 0) {
            seaf_ext_log ("No repos");
            if (repo_cache.n_repo != 0) {
                goto do_update;
            } else {
                goto out;
            }
        }

        rinfo = malloc(n_repo * (sizeof(RepoInfo)));

        ptr = line_v;

        while (*ptr) {

            char *repo_id = NULL;
            char *repo_wt = NULL;

            struct strbuf *line = *ptr;
            ptr++;

            if (!parse_id_worktree (line->buf, &repo_id, &repo_wt))
                continue;

            char *id = rinfo[n_valid].repo_id;
            char *wt = rinfo[n_valid].repo_wt;

            memcpy (id, repo_id, 37);
            memcpy (wt, repo_wt, strlen(repo_wt) + 1);

            n_valid++;

            free(repo_id);
            free(repo_wt);
        }

    do_update:
        /* accuqire the cache mutex, blocking */
        seaf_mutex_acquire(&cache_mutex, TRUE);

        free (repo_cache.info);

        repo_cache.info = rinfo;
        repo_cache.n_repo = n_valid;

        seaf_mutex_release(&cache_mutex);

        strbuf_list_free(line_v);

        seaf_ext_log ("%d repos now", repo_cache.n_repo); 
    }

out:
    free (output);
    return 0;
}


bool seaf_ext_mutex_init()
{
    bool ret = seaf_mutex_init(&cache_mutex);
    if (ret) {
        ret = seaf_mutex_init(&pipe_mutex);
    }
    return ret;
}


static void *
ext_pipe_common(const char *request, bool need_response)
{
    seaf_mutex_acquire (&pipe_mutex, TRUE);
    int status = -1;
    char *result = NULL;
    if (ext_pipe_is_connected()) {
        status = send_ext_pipe_request_wrapper(request);
        if (status < 0 && !ext_pipe_is_connected()) {
            connect_ext_pipe();
            if (ext_pipe_is_connected()) {
                seaf_ext_log ("pipe reconnected OK");
                status = send_ext_pipe_request_wrapper(request);
            }
        }
    } else {
        connect_ext_pipe();
        if (ext_pipe_is_connected()) {
            status = send_ext_pipe_request_wrapper(request);
        }
    }

    if (!need_response) {
        /* TODO: on mingw64 gcc would think sizeof(long)=4 */
        seaf_mutex_release (&pipe_mutex);
        return (void *)(long)status;
    }

    if (status < 0)
        goto failed;

    result = read_ext_pipe_response();

failed:
    seaf_mutex_release (&pipe_mutex);
    return result;
}

char *
get_ext_pipe_response(const char *request)
{
    if (!request)
        return NULL;
    return (char *)ext_pipe_common (request, TRUE);
}

int
send_ext_pipe_request (const char *request)
{
    if (!request)
        return -1;
    return (int)(long)ext_pipe_common (request, FALSE);
}

