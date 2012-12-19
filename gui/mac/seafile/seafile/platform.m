//
//  platform.m
//  seafile
//
//  Created by Wei Wang on 5/16/12.
//  Copyright (c) 2012 tsinghua. All rights reserved.
//

#import <signal.h>
#import <sys/sysctl.h>
#import <stdio.h>
#import <stdarg.h>
#import <ccnet.h>

#import <CoreServices/CoreServices.h>

#import "AppDelegate.h"
#import "applet-common.h"
#import "applet-log.h"
#import "seafile-applet.h"
#import "platform.h"
#import "rpc-wrapper.h"


SeafileApplet *applet = NULL;

void start_trayicon_rotate_timer (int timeout_ms, void *data);

void show_warning (const char *title, const char *fmt, ...)
{
    va_list params;
    char buf[2048];

    va_start (params, fmt);
    vsnprintf (buf, sizeof(buf), fmt, params);
    va_end (params);

    NSString *t = [[NSString alloc] initWithUTF8String: title?title: APP_NAME];
    NSString *msg = [[NSString alloc] initWithUTF8String: buf];
    NSAlert *alert= [NSAlert alertWithMessageText: t defaultButton: @"OK" alternateButton: nil otherButton: nil informativeTextWithFormat: @"%@", msg];
    [alert runModal];
    [t release];
    [msg release];
}

int msgbox_yes_or_no (char *format, ...)
{
    NSInteger ret;
    va_list params;
    char buf[2048];

    va_start (params, format);
    vsnprintf (buf, sizeof(buf), format, params);
    va_end (params);
    NSString *msg = [[NSString alloc] initWithUTF8String: buf];

    NSAlert *alert= [NSAlert alertWithMessageText: @"Seafile" defaultButton: @"YES" alternateButton: @"NO" otherButton: nil informativeTextWithFormat: @"%@", msg];

    ret = [alert runModal];
    if (ret == NSAlertDefaultReturn) {
        [msg release];
        return YES;
    }
    [msg release];
    return NO;
}

int spawn_ccnet_daemon (void)
{
    NSBundle *bundle = [NSBundle mainBundle];

    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath: [bundle pathForResource: @"ccnet" ofType: nil]];

    NSMutableArray *args = [NSMutableArray array];
    NSString *str = [[NSString alloc] initWithUTF8String: applet->config_dir];
    [args addObject: @"-c" ];
    [args addObject: str ];
    [args addObject: @"--no-multicast" ];
    [args addObject: @"-D"];
#ifdef DEBUG
    [args addObject: @"ALL"];
#else
    [args addObject: @"Peer,Message,Connection,Other"];
#endif
    [task setArguments: args];
    [task launch];
    [str release];

    if (![task isRunning])
        return -1;

    return 0;
}

int start_seafile_daemon (void)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    NSBundle *bundle = [NSBundle mainBundle];

    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath: [bundle pathForResource: @"seaf-daemon" ofType: nil]];

    NSMutableArray *args = [NSMutableArray array];
    NSString *ccnet_conf = [[NSString alloc] initWithUTF8String: applet->config_dir];
    NSString *seaf_conf = [[NSString alloc] initWithUTF8String: applet->seafile_dir];
    NSString *wtree =  [[NSString alloc] initWithUTF8String: applet->seafile_worktree];

    applet_message ("Starting seaf-daemon ...\n");
    applet_message ("data dir:      %s\n", applet->seafile_dir);
    applet_message ("worktree dir:  %s\n", applet->seafile_worktree);

    [args addObject: @"-c" ];
    [args addObject: ccnet_conf];
    [args addObject: @"-d"];
    [args addObject: seaf_conf];
    [args addObject: @"-w"];
    [args addObject: wtree];

#ifdef DEBUG
    [args addObject: @"-D"];
    [args addObject: @"All"];
    [args addObject: @"-g"];
    [args addObject: @"debug"];
    [args addObject: @"-G"];
    [args addObject: @"debug"];
#endif
    [task setArguments: args];
    [task launch];

    [ccnet_conf release];
    [seaf_conf release];
    [wtree release];

    if (![task isRunning]) {
        [delegate setTask: NULL];
        return -1;
    }
    [delegate setTask: task];
    return 0;
}

int start_web_server (void)
{
#ifdef DEBUG
    system ("/usr/local/bin/ccnet-web.sh start");
#else
    NSLog (@" start web server ...\n");
    NSString *path = [[NSBundle mainBundle] pathForResource: @"seafileweb.app" ofType: nil];
    if ([[NSWorkspace sharedWorkspace] respondsToSelector: @selector(launchApplicationAtURL: options: configuration: error: )]) {
        // As recommended for OS X >= 10.6.
        NSURL *url = [NSURL fileURLWithPath: path isDirectory: NO];
        NSMutableDictionary *confs = [NSMutableDictionary dictionary];
        NSMutableArray *args = [NSArray arrayWithObjects: NS_SEAF_HTTP_ADDR, nil];
        [confs setObject: args forKey: NSWorkspaceLaunchConfigurationArguments];
        [[NSWorkspace sharedWorkspace] launchApplicationAtURL: url options: NSWorkspaceLaunchDefault configuration: confs error: NULL];
    } else {
        // For older systems.
        NSString *path = [[NSBundle mainBundle] resourcePath];
        NSTask *task = [[NSTask alloc] init];
        NSMutableArray *args = [NSArray arrayWithObjects: path,
                                @"--args", @"127.0.0.1:13420", nil];
        [task setLaunchPath: @"/usr/bin/open"];
        [task setArguments: args];
        [task launch];
        [task release];
    }
#endif

    applet->web_status = WEB_STARTED;
    return 0;
}

typedef struct kinfo_proc kinfo_proc;

static int GetBSDProcessList (kinfo_proc **procList, size_t *procCount)
{
    int                 err;
    kinfo_proc *        result;
    bool                done;
    static const int    name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    // Declaring name as const requires us to cast it when passing it to
    // sysctl because the prototype doesn't include the const modifier.
    size_t              length;

    assert ( procList != NULL);
    assert (*procList == NULL);
    assert (procCount != NULL);

    *procCount = 0;

    // We start by calling sysctl with result == NULL and length == 0.
    // That will succeed, and set length to the appropriate length.
    // We then allocate a buffer of that size and call sysctl again
    // with that buffer.  If that succeeds, we're done.  If that fails
    // with ENOMEM, we have to throw away our buffer and loop.  Note
    // that the loop causes use to call sysctl with NULL again; this
    // is necessary because the ENOMEM failure case sets length to
    // the amount of data returned, not the amount of data that
    // could have been returned.

    result = NULL;
    done = false;
    do {
        assert (result == NULL);
        // Call sysctl with a NULL buffer.

        length = 0;
        err = sysctl ((int *) name, (sizeof(name) / sizeof(*name)) - 1,
                     NULL, &length,
                     NULL, 0);
        if (err == -1) {
            err = errno;
        }

        // Allocate an appropriately sized buffer based on the results
        // from the previous call.

        if (err == 0) {
            result = malloc (length);
            if (result == NULL) {
                err = ENOMEM;
            }
        }

        // Call sysctl again with the new buffer.  If we get an ENOMEM
        // error, toss away our buffer and start again.

        if (err == 0) {
            err = sysctl ((int *) name, (sizeof(name) / sizeof(*name)) - 1,
                         result, &length,
                         NULL, 0);
            if (err == -1) {
                err = errno;
            }
            if (err == 0) {
                done = true;
            } else if (err == ENOMEM) {
                assert(result != NULL);
                free (result);
                result = NULL;
                err = 0;
            }
        }
    } while (err == 0 && ! done);

    // Clean up and establish post conditions.

    if (err != 0 && result != NULL) {
        free (result);
        result = NULL;
    }
    *procList = result;
    if (err == 0) {
        *procCount = length / sizeof(kinfo_proc);
    }

    assert ( (err == 0) == (*procList != NULL) );

    return err;
}

static int getBSDProcessPid (const char *name, int except_pid)
{
    int pid = 0;
    struct kinfo_proc *mylist = NULL;
    size_t mycount = 0;
    GetBSDProcessList (&mylist, &mycount);
    for (int k = 0; k < mycount; k++) {
        kinfo_proc *proc =  &mylist[k];
        if (proc->kp_proc.p_pid != except_pid
            && strcmp (proc->kp_proc.p_comm, name) == 0){
            pid = proc->kp_proc.p_pid;
            break;
        }
    }
    free (mylist);
    return pid;
}

void shutdown_process (const char *name)
{
    struct kinfo_proc *mylist = NULL;
    size_t mycount = 0;
    GetBSDProcessList (&mylist, &mycount);
    for (int k = 0; k < mycount; k++) {
        kinfo_proc *proc =  &mylist[k];
        if (strcmp (proc->kp_proc.p_comm, name) == 0){
            kill (proc->kp_proc.p_pid, SIGKILL);
        }
    }
    free (mylist);
}

int is_process_already_running (const char *name)
{
    int pid = getBSDProcessPid (name, getpid ());
    if (pid)
        return YES;
    return NO;
}

int stop_web_server (void)
{
#ifdef DEBUG
    system ("/usr/local/bin/ccnet-web.sh stop");
    applet->web_status = WEB_NOT_STARTED;
#else
    shutdown_process ("seafileweb");
    applet->web_status = WEB_NOT_STARTED;
#endif

    return 0;
}

void trayicon_notify (char *title, char *buf)
{
    if (buf == NULL)
        return;
    if (title == NULL)
        title = "Seafile";
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    [delegate popup_bubble: title message: buf];
}

void trayicon_set_tip (char *tip)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    [[delegate statusItem] setToolTip: [[NSString alloc] initWithUTF8String: tip]];
}


void trayicon_set_ccnet_state (int state)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];

    if ((state == CCNET_STATE_UP) || (state == CCNET_STATE_DOWN)
        || (state == CCNET_STATE_AUTOSYNC_DISABLED)) {
        [[delegate statusItem] setImage: delegate->statusImage[state]];
    } else {
        applet_warning ("Error set unknown state %d\n", state);
    }
}

int show_init_seafile_window (void)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    return [delegate show_initseafile_window];
}

int ccnet_open_dir (const char *path)
{
    NSString *spath = [[NSString alloc] initWithUTF8String: path];
    NSURL *pathURL = [NSURL fileURLWithPath: spath];
    int ret = [[NSWorkspace sharedWorkspace] openURL: pathURL];

    [spath release];
    return ret;
}


int open_web_browser (const char *url)
{
    NSString *surl = [[NSString alloc] initWithUTF8String: url];
#if 0
    NSArray* urls = [NSArray arrayWithObject: [NSURL URLWithString: surl]];
    [[NSWorkspace sharedWorkspace] openURLs: urls withAppBundleIdentifier: nil options: NSWorkspaceLaunchWithoutActivation additionalEventParamDescriptor: nil launchIdentifiers: nil];
#else
    [[NSWorkspace sharedWorkspace] openURL: [NSURL URLWithString: surl]];
#endif
    [surl release];
    return 0;
}

void start_conn_daemon_timer (int timeout_ms, void *data)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    [delegate add_conn_server_timer: timeout_ms];
}

void start_open_browser_timer (int timeout_ms, void *data)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    [delegate add_open_browser_timer: timeout_ms];
}

void stop_open_browser_timer (void)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    [delegate del_open_browser_timer];
}

void start_trayicon_rotate_timer (int timeout_ms, void *data)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    [delegate add_trayicon_rotate_timer: timeout_ms];
}

void start_heartbeat_monitor_timer (int timeout_ms, void *data)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    [delegate add_heartbeat_monitor_timer: timeout_ms];
}


static void readCB (CFSocketRef child, CFSocketCallBackType type,
                   CFDataRef address, const void *data, void *info)
{
    if (CFSocketIsValid (child) && (type & kCFSocketReadCallBack) ) {
        if (ccnet_client_read_input (applet->client) <= 0) {
            on_ccnet_daemon_down ();
            CFRelease (child);
        }
    } else {
        on_ccnet_daemon_down ();
        CFRelease (child);
    }
}

void add_client_fd_to_mainloop (void)
{
    CFSocketRef child = CFSocketCreateWithNative (NULL,
                                                 applet->client->connfd,
                                                 kCFSocketReadCallBack,
                                                 readCB,
                                                 NULL);
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];

    CFRunLoopSourceRef childSource = CFSocketCreateRunLoopSource (NULL, child, 0);
    delegate->loop = CFRunLoopGetCurrent ();
    CFRunLoopAddSource (delegate->loop, childSource, kCFRunLoopDefaultMode);
    [delegate setSock: childSource];
}

void rm_client_fd_from_mainloop (void)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    if (delegate.sock) {
        CFRunLoopRemoveSource (delegate->loop, delegate.sock, kCFRunLoopDefaultMode);
        CFRelease ([delegate sock]);
        delegate.sock = nil;
    }
}

void on_quit (void) {
    stop_ccnet ();
    stop_web_server ();
    [[NSApplication sharedApplication] terminate: [[NSApplication sharedApplication] delegate]];

}

static int nth_trayicon = 0;
static int rotate_counter = 0;
static gboolean trayicon_is_rotating = FALSE;

gboolean trayicon_do_rotate (void)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];

    if (rotate_counter > 8 || !trayicon_is_rotating || applet->auto_sync_disabled) {
        trayicon_is_rotating = FALSE;
        reset_trayicon_and_tip ();
        return FALSE;
    }

    [[delegate statusItem] setImage: delegate->transferImage[nth_trayicon%4]];
    nth_trayicon++;
    rotate_counter++;
    return TRUE;
}

void trayicon_rotate (gboolean start)
{
    if (start) {
        rotate_counter = 0;
        if (!trayicon_is_rotating) {
            nth_trayicon = 0;
            trayicon_is_rotating = TRUE;
            AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
            [delegate add_trayicon_rotate_timer: 500];
        }
    } else {
        trayicon_is_rotating = FALSE;
    }
}

int is_seafile_daemon_running (void)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    NSTask *task = [delegate task];
    BOOL is_running = (task != NULL && [task isRunning]);
    return is_running;
}

static int set_folder_image (const char *path, NSImage *iconImage)
{
    if (!path) {
        return 0;
    }
    NSString *nspath =  [[NSString alloc] initWithUTF8String: path];
    NSURL* directoryURL = [NSURL fileURLWithPath: nspath isDirectory: YES];
    return [[NSWorkspace sharedWorkspace] setIcon: iconImage forFile: [directoryURL path] options: 0];
}

void seafile_set_seafilefolder_icns (void)
{
    // AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    //set_folder_image (applet->seafile_worktree, delegate->wktreeImage);
}

void seafile_set_repofolder_icns (const char *path)
{
    if (!path)
        return;
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    set_folder_image (path, delegate->repoImage);
}

void seafile_unset_repofolder_icns (const char *path)
{
    if (!path)
        return;
    set_folder_image (path, [NSImage imageNamed: @"NSFolder"]);
}

int set_visibility_for_file (const char *cpath, int isDirectory, int visible)
{
    int ret = 0;
    NSString *filename = [[NSString alloc] initWithUTF8String: cpath];
    NSURL *url = [NSURL fileURLWithPath: filename];
    ret = [url setResourceValue: [NSNumber numberWithBool: !visible] forKey: NSURLIsHiddenKey error: NULL];
    [filename release];
    return ret;
}

int set_seafile_auto_start (const int on)
{
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    if (on)
        [delegate add_app_as_login_item: [[NSBundle mainBundle] bundlePath]];
    else
        [delegate del_app_from_login_item: [[NSBundle mainBundle] bundlePath]];

    return YES;
}


void reset_trayicon_and_tip (void)
{
    char *tip = "Seafile";

    if (!applet->client->connected) {
        trayicon_set_ccnet_state (CCNET_STATE_DOWN);
    } else {
        if (applet->auto_sync_disabled) {
            trayicon_set_ccnet_state (CCNET_STATE_AUTOSYNC_DISABLED);
            tip = "Seafile auto sync paused";
        } else {
            trayicon_set_ccnet_state (CCNET_STATE_UP);
        }
    }
    trayicon_set_tip (tip);
}

void set_auto_sync_cb (void *result, void *data, GError *error)
{
    AppDelegate *appdelegate = [[NSApplication sharedApplication] delegate];
    SetAutoSyncData *sdata = data;
    gboolean disable = sdata->disable;

    if (error) {
        applet_warning ("failed to %s sync: %s\n",
                        disable ? "disable" : "enable",
                        error->message);
        [appdelegate.enableAutoSyncItem setEnabled:YES];
        [appdelegate.disableAutoSyncItem setEnabled:YES];
    } else {
        if (disable) {
            /* auto sync is disabled */
            [appdelegate.enableAutoSyncItem setHidden:NO];
            [appdelegate.enableAutoSyncItem setEnabled:YES];
            [appdelegate.disableAutoSyncItem setHidden:YES];
        } else {
            /* auto sync is enabled */
            [appdelegate.disableAutoSyncItem setHidden:NO];
            [appdelegate.disableAutoSyncItem setEnabled:YES];
            [appdelegate.enableAutoSyncItem setHidden:YES];
        }

        applet->auto_sync_disabled = disable;
        reset_trayicon_and_tip ();
    }

    g_free (sdata);

}
