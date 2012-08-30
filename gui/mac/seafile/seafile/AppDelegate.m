//
//  AppDelegate.m
//  seafile
//
//  Created by Wei Wang on 5/15/12.
//  Copyright (c) 2012 tsinghua. All rights reserved.
//

#import <glib.h>

#import "AppDelegate.h"
#import "MAAttachedWindow.h"
#import "ccnet-init.h"
#import "applet-common.h"
#import "seafile-applet.h"
#import "ccnet.h"
#import "rpc-wrapper.h"
#import "platform.h"
#import "applet-log.h"
#import "utils.h"

enum {
    RESPONSE_OK = 0,
    RESPONSE_CANCEL,
};

@interface AppDelegate()
@property (retain) NSTimer *openBrowserTimer;
@end

@implementation AppDelegate

@synthesize openBrowserTimer;
@synthesize task;
@synthesize sock;
@synthesize statusItem;
@synthesize bubbleTitle;
@synthesize bubbleView;
@synthesize bubbleText;

@synthesize initCcnetWindow = _initCcnetWindow;
@synthesize initSeafileWindow = _initSeafileWindow;
@synthesize logintWindow;
@synthesize nickNameTipLabel;
@synthesize nickNameWarnImg;
@synthesize nameTextField = _nameTextField;
@synthesize chooseDirField;
@synthesize chooseDirWarnImg;

@synthesize createRepoWindow;

@synthesize createRepoPath;
@synthesize createRepoChoosePathBt;
@synthesize createRepoDesc;
@synthesize createRepoServers;
@synthesize createRepoEncry;
@synthesize createRepoPassL;
@synthesize createRepoPassAL;
@synthesize createRepoPass;
@synthesize createRepoPassA;
@synthesize createRepoOKBt;
@synthesize createRepoCancelBt;
@synthesize createRepoDirWarnImg;
@synthesize createRepoPassWarnImg;
@synthesize createRepoPassWarnLabel;

@synthesize openBrowerItem;
@synthesize restartItem;
@synthesize createRepItem;

@synthesize loginNameFiled;
@synthesize loginPwFiled;
@synthesize loginBt;
@synthesize loginWarnLabel;


static void
create_repo_cb (void *vresult, void *vdata, GError *error) {
    char *result = vresult;
    char *path = vdata;
    if (!result || error) {
        applet_warning ("Failed to create repo in %s: %s\n", path, error->message);
        show_warning (APP_NAME, "Failed to create repo");
    } else {
        applet_debug ("Create repo in %s success\n", path);
        trayicon_notify("Seafile", "Create repo Success");
    }
    AppDelegate *delegate = [[NSApplication sharedApplication] delegate];
    [[delegate createRepoWindow] orderOut:nil];
}


- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    shutdown_process ("seafileweb");
    shutdown_process ("ccnet");

    g_type_init();
    applet = g_new0 (SeafileApplet, 1);
    applet->client = ccnet_client_new ();
    applet->sync_client = ccnet_client_new ();
    applet->web_status = WEB_NOT_STARTED;

    seafile_applet_start (0, NULL);

    seafile_set_seafilefolder_icns();
    NSString *path = [[NSString alloc] initWithUTF8String:applet->seafile_worktree];
    [self add_dir_to_sidebar:path];
    set_visibility_for_file (applet->seafile_dir, YES, NO);

    [path release];
}

- (IBAction)initccnet_cancel:(id)sender {
    [NSApp stopModalWithCode:RESPONSE_CANCEL];
}

- (IBAction)initccnet_generate:(id)sender {
    int res = 0;
    NSString *name = [_nameTextField stringValue];
    const char *nickname = [name UTF8String];
    if (is_valid_username(nickname, (int)strlen(nickname))) {
        res = create_new();
        if (res < 0) {
            show_warning (APP_NAME, "Failed to create user, please try again");
            return;
        } else
            [NSApp stopModalWithCode:RESPONSE_OK];
    } else {
        [nickNameWarnImg setHidden:NO];
        [nickNameWarnImg setImage:warningImage];
        [nickNameWarnImg setImageFrameStyle:NSImageFrameNone];
        [nickNameWarnImg setImageScaling:NSScaleProportionally];
        [nickNameTipLabel setTextColor:[NSColor redColor]];
        applet_warning("Invalid nickname");
        return;
    }
}

- (IBAction)initseafile_ok:(id)sender {
    BOOL isDir = NO;
    NSString *path = [chooseDirField stringValue];
    const char *cpath = [path UTF8String];
    if (is_valid_path(cpath, (int)strlen(cpath))
        && [[NSFileManager defaultManager] fileExistsAtPath:path isDirectory:&isDir]
        && isDir) {
        [NSApp stopModalWithCode:RESPONSE_OK];
    } else {
        [chooseDirWarnImg setHidden:NO];
        [chooseDirWarnImg setImage:warningImage];
        [chooseDirWarnImg setImageFrameStyle:NSImageFrameNone];
        [chooseDirWarnImg setImageScaling:NSScaleProportionally];
        return;
    }
    applet->seafile_worktree = g_build_filename (cpath, "seafile", NULL);
    applet->seafile_dir = g_build_filename(cpath, "seafile", "seafile-data", NULL);
}

- (IBAction)initseafile_cancel:(id)sender {
    [NSApp stopModalWithCode:RESPONSE_CANCEL];
}

- (IBAction)initseafile_choose_dir:(id)sender {
    [chooseDirWarnImg setHidden:YES];
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel setCanChooseDirectories:YES];
    [openPanel setCanCreateDirectories:YES];
    [openPanel setCanChooseFiles:NO];
    if ([openPanel runModal] == NSOKButton) {
        NSString *path = [[[openPanel URLs] objectAtIndex:0] path];
        [chooseDirField setStringValue:path];
    }
}

- (int) show_initccnet_window {
    NSInteger res = [NSApp runModalForWindow:_initCcnetWindow];
    [_initCcnetWindow close];
    if(res == RESPONSE_OK) {
        return 0;
    } else
        return -1;
}

- (int) show_initseafile_window {
    [chooseDirField setStringValue:NSHomeDirectory()];
    NSInteger res = [NSApp runModalForWindow:_initSeafileWindow];
    [_initSeafileWindow close];
    if(res == RESPONSE_OK) {
        return 0;
    } else
        return -1;
}

- (void) toggleLoginWnd:(BOOL) enabled {
    [loginNameFiled setEnabled:enabled];
    [loginPwFiled setEnabled:enabled];
    [loginBt setEnabled:enabled];
}

- (void) handle_login_timer: (NSTimer *) timer {
    char *errmsg = NULL;
    switch (applet->login_status) {
        case LOGIN_INIT:
            [logintWindow orderFrontRegardless];
            break;

        case LOGIN_START: {
            [logintWindow orderFrontRegardless];
            static int retry = 0;
            if (get_conn_relay_status () != 0) {
                /* not connected yet */
                /* Allow five seconds delay */
                if (++retry >= 5) {
                    errmsg = "Failed to login: connection timeout";
                    retry = 0;
                    break;
                }
            } else {
                /* relay connected */
                /* Login to relay. */
                NSString *username = [loginNameFiled stringValue];
                NSString *password = [loginPwFiled stringValue];
                do_login_relay ([username UTF8String], [password UTF8String]);
                applet->login_status = LOGIN_SENT;
                retry = 0;
            }
            break;
        }

        case LOGIN_SENT: {
            int status = get_login_status ();
            if (status < 0) {
                /* login error */
                errmsg =  "Failed to login: wrong username and password";
                break;
            } else if (status == 0) {
                /* login success */
                applet->login_status = LOGIN_SUCCESSFUL;
                ccnet_set_config (applet->ccnet_rpc_client, "login_finished", "true");
                break;
            }
            break;
        }

        case LOGIN_SUCCESSFUL:
            applet_message("Seafile Login Success");
            [timer invalidate];
            [logintWindow  orderOut:nil];
            trayicon_notify("Seafile", "Seafile Login Success");
            break;

        case LOGIN_SKIP:
            applet_message("Seafile Login Skip");
            [timer invalidate];
            [logintWindow orderOut:nil];
            break;

        default:
            break;
    }
    if (errmsg) {
        applet->login_status = LOGIN_INIT;
        NSString *msg = [[NSString alloc] initWithUTF8String:errmsg];
        [loginWarnLabel setStringValue:msg ];
        [loginWarnLabel setHidden:NO];
        [loginWarnLabel setTextColor:[NSColor redColor]];
        [self toggleLoginWnd:YES];
    }
}

- (void) add_login_timer:(int) timeout_ms {
    [NSTimer scheduledTimerWithTimeInterval: timeout_ms/1000.0f
                                     target: self
                                   selector: @selector(handle_login_timer:)
                                   userInfo: nil
                                    repeats: YES];
}

- (IBAction)loginSeafile:(id)sender {
    [loginWarnLabel setHidden:YES];
    NSString *username = [loginNameFiled stringValue];
    NSString *password = [loginPwFiled stringValue];

    if (username == NULL || username == nil || [username length] < 3) {
        [loginWarnLabel setStringValue:@"The username is empty or too short"];
        [loginWarnLabel setTextColor:[NSColor redColor]];
        [loginWarnLabel setHidden:NO];
        return;
    }
    if (password == NULL || password == nil || [password length] < 3) {
        [loginWarnLabel setStringValue:@"The password is empty or too short"];
        [loginWarnLabel setTextColor:[NSColor redColor]];
        [loginWarnLabel setHidden:NO];
        return;
    }
    [self toggleLoginWnd:NO];

    if (applet->login_status == LOGIN_INIT) {
        applet->login_status = LOGIN_START;
    }
}

- (IBAction)registerSeafile:(id)sender {
    open_web_browser (SEAHUB_OFFICIAL_REGISTER_ADDR);
}

- (IBAction)skipSeafile:(id)sender {
    if (msgbox_yes_or_no ("Are you sure to skip the login ?")) {
        applet->login_status = LOGIN_SKIP;
        ccnet_set_config (applet->ccnet_rpc_client, "login_finished", "true");
        [logintWindow orderOut:sender];
    }
}

- (int) show_login_window {
    applet->login_status = LOGIN_INIT;
    [logintWindow makeKeyAndOrderFront:nil];
    [logintWindow orderFrontRegardless];
    [self add_login_timer:1000];
    return 0;
}

- (void) clearCreateRepoWindow {
    [createRepoDirWarnImg setHidden:YES];
    [createRepoPath setStringValue:@""];
    [createRepoDesc setStringValue:@""];
    [createRepoPass setStringValue:@""];
    [createRepoPassA setStringValue:@""];
    [createRepoEncry setState:NSOffState];
}

- (void) toggleCreateRepoWnd:(BOOL) enabled {
    [createRepoPath setEnabled:enabled];
    [createRepoChoosePathBt setEnabled:enabled];
    [createRepoDesc setEnabled:enabled];
    [createRepoServers setEnabled:enabled];
    [createRepoEncry setEnabled:enabled];
    [createRepoPass setEnabled:enabled];
    [createRepoPassA setEnabled:enabled];
    [createRepoOKBt setEnabled:enabled];
    [createRepoCancelBt setEnabled:enabled];
}

- (IBAction)createRepoOK:(id)sender {
    GError *error = NULL;
    BOOL isDir = NO;
    char *passwd = NULL;
    NSString *pass = NULL, *pass2 = NULL;
    NSString *repoPath = [createRepoPath stringValue];
    [createRepoDirWarnImg setHidden:YES];
    [createRepoPassWarnImg setHidden:YES];
    [createRepoPassWarnLabel setHidden:YES];

    if (!repoPath
        || ![[NSFileManager defaultManager] fileExistsAtPath:repoPath isDirectory:&isDir]
        || !isDir) {
        [createRepoDirWarnImg setHidden:NO];
        [createRepoDirWarnImg setImage:warningImage];
        [createRepoDirWarnImg setImageFrameStyle:NSImageFrameNone];
        [createRepoDirWarnImg setImageScaling:NSScaleProportionally];
        return;
    }
    if (!is_repo_path_allowed([repoPath UTF8String])) {
        [createRepoDirWarnImg setHidden:NO];
        [createRepoDirWarnImg setImage:warningImage];
        [createRepoDirWarnImg setImageFrameStyle:NSImageFrameNone];
        [createRepoDirWarnImg setImageScaling:NSScaleProportionally];
        show_warning (APP_NAME, "%s can not bee set as sync-folder", [repoPath UTF8String]);
        return;
    }

    NSString *repoDesc = [createRepoDesc stringValue];
    NSInteger state = [createRepoEncry state];
    if (state == NSOnState) {
        pass = [createRepoPass stringValue];
        pass2 = [createRepoPassA stringValue];
        if (pass == NULL || pass2 == NULL || pass.length == 0 || pass2.length == 0) {
            [createRepoPassWarnLabel setStringValue:@"Password should not be empty"];
            [createRepoPassWarnLabel setHidden:NO];
            [createRepoPassWarnLabel setTextColor:[NSColor redColor]];

            [createRepoPassWarnImg setHidden:NO];
            [createRepoPassWarnImg setImage:warningImage];
            [createRepoPassWarnImg setImageFrameStyle:NSImageFrameNone];
            [createRepoPassWarnImg setImageScaling:NSScaleProportionally];
            return;
        }
        if ([pass length] < 3 || [pass2 length] < 3 ) {
            [createRepoPassWarnLabel setStringValue:@"The password is too short"];
            [createRepoPassWarnLabel setHidden:NO];
            [createRepoPassWarnLabel setTextColor:[NSColor redColor]];

            [createRepoPassWarnImg setHidden:NO];
            [createRepoPassWarnImg setImage:warningImage];
            [createRepoPassWarnImg setImageFrameStyle:NSImageFrameNone];
            [createRepoPassWarnImg setImageScaling:NSScaleProportionally];
            return;
        }
        if (![pass isEqualToString:pass2]) {
            [createRepoPassWarnLabel setStringValue:@"The entered password do not match"];
            [createRepoPassWarnLabel setHidden:NO];
            [createRepoPassWarnLabel setTextColor:[NSColor redColor]];

            [createRepoPassWarnImg setHidden:NO];
            [createRepoPassWarnImg setImage:warningImage];
            [createRepoPassWarnImg setImageFrameStyle:NSImageFrameNone];
            [createRepoPassWarnImg setImageScaling:NSScaleProportionally];
            return;
        }
        passwd = g_strdup ([pass UTF8String]);
    }

    const char *create_path = [repoPath UTF8String];
    gint64 dir_size64 = ccnet_calc_directory_size (create_path, &error);
    if (dir_size64 < 0) {
        applet_warning ("Failed to calc dir size of %s: %s\n",
                        create_path, error->message);
        show_warning (APP_NAME, "Failed to calculate the size of directory %s", create_path);
        return;
    }

    int dir_size = dir_size64 >> 20;

    /* default max base size, 1GB */
    int max_base_size = 1024;
    applet_message ("Try to create repo, path = %s, "
                    "dir_size = %d MB, max allowed %d MB\n",
                    create_path, dir_size, max_base_size);

    if (dir_size > max_base_size) {
        if (!msgbox_yes_or_no ("The directory %s is too large (over %d MB). Are you sure to continue ?", create_path, dir_size)) {
            applet_warning ("Failed to create: base size %d MB, max allowd %d MB\n",
                            dir_size, max_base_size);
            return;
        }
    }

    NSMenuItem *serverItem = [createRepoServers selectedItem];
    NSString *repoRelay = [serverItem title];
    char *path = g_strdup([repoPath UTF8String]);
    char *name = g_path_get_basename(path);

    GList *relays = get_relay_list();
    char *relay_id = relay_name_to_id(relays, [repoRelay UTF8String]);

    call_seafile_create_repo (name, [repoDesc UTF8String], path,
                              relay_id, passwd, 1, create_repo_cb, path);

    g_free(name);
    g_free(relay_id);
    if (passwd)
        g_free(passwd);
    if (relays != NULL)
        free_relay_list (relays);
    [self toggleCreateRepoWnd:NO];
}

- (IBAction)createRepoCancel:(id)sender {
    [createRepoWindow orderOut:sender];
}

- (IBAction)createRepoChoosePath:(id)sender {
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel setCanChooseDirectories:YES];
    [openPanel setCanCreateDirectories:YES];
    [openPanel setCanChooseFiles:NO];
    if ([openPanel runModal] == NSOKButton) {
        NSString *path = [[[openPanel URLs] objectAtIndex:0] path];
        [path retain];
        [createRepoPath setStringValue:path];
    }
}

- (IBAction)createRepoEncryToggle:(id)sender {
    NSInteger state = [createRepoEncry state];
    if (state == NSOnState) {
        [createRepoPassL setEnabled:YES];
        [createRepoPassAL setEnabled:YES];
        [createRepoPass setEnabled:YES];
        [createRepoPassA setEnabled:YES];
    } else {
        [createRepoPassL setEnabled:NO];
        [createRepoPassAL setEnabled:NO];
        [createRepoPass setEnabled:NO];
        [createRepoPassA setEnabled:NO];
    }
}

-(IBAction)open_browser:(id)sender {
    open_web_browser(SEAF_HTTP_ADDR);
}

-(IBAction)restart:(id)sender {
    [openBrowerItem setEnabled:NO];
    [restartItem setEnabled:NO];
    restart_all();
}

-(IBAction)quit:(id)sender {
    on_quit();
}

- (IBAction)preferences:(id)sender {
    printf ("#%d %s\n", __LINE__, __FUNCTION__);
}

- (IBAction) openSeafileSite:(id)sender {
    open_web_browser(SEAFILE_WEBSITE);
}

- (IBAction)createRepo:(id)sender {
    if ([createRepoWindow isVisible]) {
        [createRepoWindow orderFrontRegardless];
        return;
    }

    GList *ptr = NULL;
    [self toggleCreateRepoWnd:YES];
    [self createRepoEncryToggle:sender];
    [self clearCreateRepoWindow];
    GList *relays = get_relay_list();
    if (!relays) {
        show_warning (APP_NAME, "There is no relay");
        return;
    }
    [createRepoServers removeAllItems];
    for (ptr = relays; ptr; ptr = ptr->next) {
        CcnetPeer *relay = ptr->data;
        NSString *name = [[NSString alloc] initWithUTF8String:relay->name];
        [createRepoServers addItemWithTitle:name];
    }
    if (relays != NULL)
        free_relay_list (relays);
    [createRepoWindow makeKeyAndOrderFront:sender];
    [createRepoWindow orderFrontRegardless];
}

- (void) dealloc {
    [[NSStatusBar systemStatusBar] removeStatusItem:statusItem];
    [statusItem release];
    [statusImage[0] release];
    [statusImage[1] release];
    [super dealloc];
}

- (void) awakeFromNib{
    static int inited = 0;
    if (inited == 1) {
        return;
    }
    inited = 1;
    if (is_process_already_running("seafile")) {
        NSLog(@"seafile.app has already been running, just quit\n");
        [[NSApplication sharedApplication] terminate:[[NSApplication sharedApplication] delegate]];

    }
    statusItem = [[[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength] retain];

    NSBundle *bundle = [NSBundle mainBundle];
    statusImage[0] = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"network-up" ofType:@"png"]];
    statusImage[1] = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"network-down" ofType:@"png"]];

    for (int i = 0; i < 4; ++i) {
        NSString *image_name = [NSString stringWithFormat:@"network-rotate%d",i+1];
        transferImage[i] = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:image_name ofType:@"png"]];
    }
    warningImage = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"warning" ofType:@"png"]];
    wktreeImage = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"seafilefolder" ofType:@"icns"]];
    repoImage  = [[NSImage alloc] initWithContentsOfFile:[bundle pathForResource:@"seafilerepo" ofType:@"icns"]];

    [statusItem setImage:statusImage[0]];
    [statusItem setMenu:statusMenu];
    [statusItem setToolTip:@"Seafile"];
    [statusItem setHighlightMode:YES];

    [openBrowerItem setEnabled:NO];
    [createRepItem setEnabled:NO];
}

- (void) handle_bubble_timeout: (NSTimer *) timer {
    MAAttachedWindow *attachedWindow = [timer userInfo];
    [attachedWindow orderOut:self];
    [attachedWindow release];
}

- (void) popup_bubble :(const char *) title message:(const char *) msg {
    NSString *text = [[NSString alloc] initWithUTF8String:msg];
    NSString *stitle = [[NSString alloc] initWithUTF8String:title];

    NSRect frame = [[statusItem valueForKey:@"window"] frame];
    NSPoint pt = NSMakePoint(NSMidX(frame), NSMinY(frame));

    MAAttachedWindow *attachedWindow = [[MAAttachedWindow alloc]
                                        initWithView: bubbleView
                                        attachedToPoint:pt
                                        inWindow:nil
                                        onSide:MAPositionBottom
                                        atDistance:5.0];
    [bubbleText setTextColor:[attachedWindow borderColor]];
    [bubbleText setStringValue:text];
    [bubbleTitle setTitle:stitle];
    [attachedWindow makeKeyAndOrderFront:self];
    [attachedWindow setLevel:NSStatusWindowLevel];
    [stitle release];
    [text release];
    [NSTimer scheduledTimerWithTimeInterval: 3
                                     target: self
                                   selector: @selector(handle_bubble_timeout:)
                                   userInfo: attachedWindow
                                    repeats: NO];

}

- (void) handle_conn_server_timer: (NSTimer *) timer {
    int more = connect_to_server(NULL);
    if (!more) {
        [timer invalidate];
    }
    [restartItem setEnabled:YES];
}

- (void) add_conn_server_timer:(int) timeout_ms {
    [NSTimer scheduledTimerWithTimeInterval: timeout_ms/1000.0f
                                     target: self
                                   selector: @selector(handle_conn_server_timer:)
                                   userInfo: nil
                                    repeats: YES];
}

- (void) handle_heartbeat_moitor_timer: (NSTimer *) timer {
    int more = heartbeat_monitor(NULL);
    if (!more)
        [timer invalidate];
}

- (void) add_heartbeat_monitor_timer:(int) timeout_ms {
    [NSTimer scheduledTimerWithTimeInterval: timeout_ms/1000.0f
                                     target: self
                                   selector: @selector(handle_heartbeat_moitor_timer:)
                                   userInfo: nil
                                    repeats: YES];
}

- (void) handle_open_browser_timer: (NSTimer *) timer {
    int more = on_open_browser_timeout();
    if (!more) {
        [timer invalidate];
        [openBrowerItem setEnabled:YES];
    }
}

- (void) add_open_browser_timer:(int) timeout_ms {
    self.openBrowserTimer = [NSTimer scheduledTimerWithTimeInterval: timeout_ms/1000.0f
                                                             target: self
                                                           selector: @selector(handle_open_browser_timer:)
                                                           userInfo: nil
                                                            repeats: YES];
}

- (void) del_open_browser_timer
{
    [self.openBrowserTimer invalidate];
    self.openBrowserTimer = nil;
}


- (void) handle_trayicon_rotate_timer: (NSTimer *) timer {
    int more = trayicon_do_rotate();
    if (!more)
        [timer invalidate];
}

- (void) add_trayicon_rotate_timer:(int) timeout_ms{
    [NSTimer scheduledTimerWithTimeInterval: timeout_ms/1000.0f
                                     target: self
                                   selector: @selector(handle_trayicon_rotate_timer:)
                                   userInfo: nil
                                    repeats: YES];
}

- (void) add_app_as_login_item:(NSString *) appPath {
    CFURLRef url = (CFURLRef)[NSURL fileURLWithPath:appPath];

    // Create a reference to the shared file list.
    // We are adding it to the current user only.
    // If we want to add it all users, use
    // kLSSharedFileListGlobalLoginItems instead of
    //kLSSharedFileListSessionLoginItems
    LSSharedFileListRef loginItems = LSSharedFileListCreate(NULL,kLSSharedFileListSessionLoginItems, NULL);
    if (loginItems) {
        LSSharedFileListItemRef item = LSSharedFileListInsertItemURL(loginItems,kLSSharedFileListItemLast, NULL, NULL, url, NULL, NULL);
        if (item){
            CFRelease(item);
        }
    }

    CFRelease(loginItems);
}

- (void) del_app_from_login_item:(NSString *) appPath {
    CFURLRef url = (CFURLRef)[NSURL fileURLWithPath:appPath];

    // Create a reference to the shared file list.
    LSSharedFileListRef loginItems = LSSharedFileListCreate(NULL,kLSSharedFileListSessionLoginItems, NULL);

    if (loginItems) {
        UInt32 seedValue;
        //Retrieve the list of Login Items and cast them to
        // a NSArray so that it will be easier to iterate.
        NSArray  *loginItemsArray = (NSArray *)LSSharedFileListCopySnapshot(loginItems, &seedValue);
        int i = 0;
        for(i = 0 ; i< [loginItemsArray count]; i++){
            LSSharedFileListItemRef itemRef = (LSSharedFileListItemRef)[loginItemsArray objectAtIndex:i];
            //Resolve the item with URL
            if (LSSharedFileListItemResolve(itemRef, 0, (CFURLRef*) &url, NULL) == noErr) {
                NSString * urlPath = [(NSURL*)url path];
                if ([urlPath compare:appPath] == NSOrderedSame){
                    LSSharedFileListItemRemove(loginItems,itemRef);
                }
            }
        }
        [loginItemsArray release];
    }
}

- (void) add_dir_to_sidebar:(NSString *) appPath {
    CFURLRef url = (CFURLRef)[NSURL fileURLWithPath:appPath];

    // Create a reference to the shared file list.
    // We are adding it to the current user only.
    // If we want to add it all users, use
    // kLSSharedFileListGlobalLoginItems instead of
    //kLSSharedFileListSessionLoginItems
    LSSharedFileListRef favorItems = LSSharedFileListCreate(NULL,kLSSharedFileListFavoriteItems, NULL);
    if (favorItems) {
        LSSharedFileListItemRef item = LSSharedFileListInsertItemURL(favorItems,kLSSharedFileListItemLast, NULL, NULL, url, NULL, NULL);
        if (item){
            CFRelease(item);
        }
    }

    CFRelease(favorItems);
}

@end
