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

@synthesize initSeafileWindow = _initSeafileWindow;
@synthesize chooseDirField;
@synthesize chooseDirWarnImg;

@synthesize openBrowerItem;
@synthesize restartItem;
@synthesize enableAutoSyncItem;
@synthesize disableAutoSyncItem;


- (void)applicationDidFinishLaunching: (NSNotification *)aNotification
{
    shutdown_process ("seafileweb");
    shutdown_process ("ccnet");

    g_type_init();
    applet = g_new0 (SeafileApplet, 1);
    applet->client = ccnet_client_new ();
    applet->sync_client = ccnet_client_new ();
    applet->web_status = WEB_NOT_STARTED;

    seafile_applet_start (0, NULL);

    seafile_set_seafilefolder_icns ();
    NSString *path = [[NSString alloc] initWithUTF8String: applet->seafile_worktree];
    [self add_dir_to_sidebar: path];
    set_visibility_for_file (applet->seafile_dir, YES, NO);

    [path release];
}

- (void)applicationWillTerminate: (NSNotification *)aNotification
{
    NSLog (@"seafile will terminate\n");
    stop_ccnet ();
    stop_web_server();
}

- (IBAction)initseafile_ok: (id)sender
{
    BOOL isDir = NO;
    NSString *path = [chooseDirField stringValue];
    const char *cpath = [path UTF8String];
    if (is_valid_path (cpath, (int)strlen(cpath))
        && [[NSFileManager defaultManager] fileExistsAtPath: path isDirectory: &isDir]
        && isDir) {
        [NSApp stopModalWithCode: RESPONSE_OK];
    } else {
        [chooseDirWarnImg setHidden: NO];
        [chooseDirWarnImg setImage: warningImage];
        [chooseDirWarnImg setImageFrameStyle: NSImageFrameNone];
        [chooseDirWarnImg setImageScaling: NSScaleProportionally];
        return;
    }
    applet->seafile_worktree = g_build_filename (cpath, "seafile", NULL);
    applet->seafile_dir = g_build_filename (cpath, "seafile", "seafile-data", NULL);
}

- (IBAction)initseafile_cancel: (id)sender
{
    [NSApp stopModalWithCode: RESPONSE_CANCEL];
}

- (IBAction)initseafile_choose_dir: (id)sender
{
    [chooseDirWarnImg setHidden: YES];
    NSOpenPanel *openPanel = [NSOpenPanel openPanel];
    [openPanel setCanChooseDirectories: YES];
    [openPanel setCanCreateDirectories: YES];
    [openPanel setCanChooseFiles: NO];
    if ([openPanel runModal] == NSOKButton) {
        NSString *path = [[[openPanel URLs] objectAtIndex: 0] path];
        [chooseDirField setStringValue: path];
    }
}

- (int)show_initseafile_window
{
    [chooseDirField setStringValue: NSHomeDirectory()];
    NSInteger res = [NSApp runModalForWindow: _initSeafileWindow];
    [_initSeafileWindow close];
    if(res == RESPONSE_OK)
        return 0;
    else
        return -1;
}

- (IBAction)open_browser: (id)sender
{
    open_web_browser (SEAF_HTTP_ADDR);
}

- (IBAction)restart: (id)sender
{
    [openBrowerItem setEnabled: NO];
    [restartItem setEnabled: NO];
    reset_trayicon_and_tip ();
    restart_all ();
}

- (IBAction)quit: (id)sender
{
    on_quit ();
}

- (IBAction)openSeafileSite: (id)sender
{
    open_web_browser (SEAFILE_WEBSITE);
}


- (IBAction)enableAutoSync: (id)sender
{
    [enableAutoSyncItem setEnabled: NO];
    seafile_enable_auto_sync ();
}

- (IBAction)disableAutoSync: (id)sender
{
    [disableAutoSyncItem setEnabled: NO];
    seafile_disable_auto_sync ();
}

- (void)dealloc
{
    [[NSStatusBar systemStatusBar] removeStatusItem: statusItem];
    [statusItem release];
    [statusImage[0] release];
    [statusImage[1] release];
    [super dealloc];
}

- (void)awakeFromNib
{
    static int inited = 0;
    if (inited == 1) {
        return;
    }
    inited = 1;
    if (is_process_already_running ("seafile")) {
        NSLog (@"seafile.app has already been running, just quit %d\n", getpid ());
        exit (1);
    }
    statusItem = [[[NSStatusBar systemStatusBar] statusItemWithLength: NSSquareStatusItemLength] retain];

    NSBundle *bundle = [NSBundle mainBundle];
    statusImage[0] = [[NSImage alloc] initWithContentsOfFile: [bundle pathForResource: @"network-up" ofType: @"png"]];
    statusImage[1] = [[NSImage alloc] initWithContentsOfFile: [bundle pathForResource: @"network-down" ofType: @"png"]];
    statusImage[2] = [[NSImage alloc] initWithContentsOfFile: [bundle pathForResource: @"network-stop" ofType: @"png"]];

	NSSize imageSize;
	imageSize.width = 24;
	imageSize.height = 24;
	[statusImage[0] setSize:imageSize];
	[statusImage[1] setSize:imageSize];
	[statusImage[2] setSize:imageSize];

    for (int i = 0; i < 4; ++i) {
        NSString *image_name = [NSString stringWithFormat: @"network-rotate%d",i+1];
        transferImage[i] = [[NSImage alloc] initWithContentsOfFile: [bundle pathForResource: image_name ofType: @"png"]];
		
		[transferImage[i] setSize:imageSize];
	}
    warningImage = [[NSImage alloc] initWithContentsOfFile: [bundle pathForResource: @"warning" ofType: @"png"]];
    repoImage  = [[NSImage alloc] initWithContentsOfFile: [bundle pathForResource: @"seafilerepo" ofType: @"icns"]];

    [statusItem setImage: statusImage[0]];
    [statusItem setMenu: statusMenu];
    [statusItem setToolTip: @"Seafile"];
    [statusItem setHighlightMode: YES];

    [openBrowerItem setEnabled: NO];
    [enableAutoSyncItem setHidden: YES];
    [disableAutoSyncItem setHidden: NO];
}

- (void)handle_bubble_timeout: (NSTimer *)timer
{
    MAAttachedWindow *attachedWindow = [timer userInfo];
    [attachedWindow orderOut: self];
    [attachedWindow release];
}

- (void)popup_bubble: (const char *)title message: (const char *)msg
{
    NSString *text = [[NSString alloc] initWithUTF8String: msg];
    NSString *stitle = [[NSString alloc] initWithUTF8String: title];

    NSRect frame = [[statusItem valueForKey: @"window"] frame];
    NSPoint pt = NSMakePoint (NSMidX(frame), NSMinY(frame));

    MAAttachedWindow *attachedWindow = [[MAAttachedWindow alloc]
                                        initWithView: bubbleView
                                        attachedToPoint: pt
                                        inWindow: nil
                                        onSide: MAPositionBottom
                                        atDistance: 5.0];
    [bubbleText setTextColor: [attachedWindow borderColor]];
    [bubbleText setStringValue: text];
    [bubbleTitle setTitle: stitle];
    [attachedWindow makeKeyAndOrderFront: self];
    [attachedWindow setLevel: NSStatusWindowLevel];
    [stitle release];
    [text release];
    [NSTimer scheduledTimerWithTimeInterval: 3
                                     target: self
                                   selector: @selector(handle_bubble_timeout:)
                                   userInfo: attachedWindow
                                    repeats: NO];

}

- (void)handle_conn_server_timer: (NSTimer *)timer
{
    int more = connect_to_server (NULL);
    if (!more) {
        [timer invalidate];
    }
    [restartItem setEnabled: YES];
}

- (void)add_conn_server_timer: (int)timeout_ms
{
    [NSTimer scheduledTimerWithTimeInterval: timeout_ms/1000.0f
                                     target: self
                                   selector: @selector(handle_conn_server_timer:)
                                   userInfo: nil
                                    repeats: YES];
}

- (void)handle_heartbeat_moitor_timer: (NSTimer *)timer
{
    int more = heartbeat_monitor (NULL);
    if (!more)
        [timer invalidate];
}

- (void)add_heartbeat_monitor_timer: (int)timeout_ms
{
    [NSTimer scheduledTimerWithTimeInterval: timeout_ms/1000.0f
                                     target: self
                                   selector: @selector(handle_heartbeat_moitor_timer:)
                                   userInfo: nil
                                    repeats: YES];
}

- (void)handle_open_browser_timer: (NSTimer *)timer
{
    int more = on_open_browser_timeout ();
    if (!more) {
        [timer invalidate];
        self.openBrowserTimer = nil;
        [openBrowerItem setEnabled: YES];
    }
}

- (void)add_open_browser_timer: (int)timeout_ms
{
    self.openBrowserTimer = [NSTimer scheduledTimerWithTimeInterval: timeout_ms/1000.0f
                                                             target: self
                                                           selector: @selector(handle_open_browser_timer:)
                                                           userInfo: nil
                                                            repeats: YES];
}

- (void)del_open_browser_timer
{
    [self.openBrowserTimer invalidate];
    self.openBrowserTimer = nil;
}


- (void)handle_trayicon_rotate_timer: (NSTimer *)timer
{
    int more = trayicon_do_rotate ();
    if (!more)
        [timer invalidate];
}

- (void)add_trayicon_rotate_timer: (int)timeout_ms
{
    [NSTimer scheduledTimerWithTimeInterval: timeout_ms/1000.0f
                                     target: self
                                   selector: @selector(handle_trayicon_rotate_timer:)
                                   userInfo: nil
                                    repeats: YES];
}

- (void)add_app_as_login_item: (NSString *)appPath
{
    CFURLRef url = (CFURLRef)[NSURL fileURLWithPath: appPath];

    // Create a reference to the shared file list.
    // We are adding it to the current user only.
    // If we want to add it all users, use
    // kLSSharedFileListGlobalLoginItems instead of
    //kLSSharedFileListSessionLoginItems
    LSSharedFileListRef loginItems = LSSharedFileListCreate (NULL,kLSSharedFileListSessionLoginItems, NULL);
    if (loginItems) {
        LSSharedFileListItemRef item = LSSharedFileListInsertItemURL (loginItems,kLSSharedFileListItemLast, NULL, NULL, url, NULL, NULL);
        if (item) {
            CFRelease (item);
        }
    }

    CFRelease (loginItems);
}

- (void)del_app_from_login_item: (NSString *)appPath
{
    CFURLRef url = (CFURLRef)[NSURL fileURLWithPath: appPath];

    // Create a reference to the shared file list.
    LSSharedFileListRef loginItems = LSSharedFileListCreate (NULL,kLSSharedFileListSessionLoginItems, NULL);

    if (loginItems) {
        UInt32 seedValue;
        //Retrieve the list of Login Items and cast them to
        // a NSArray so that it will be easier to iterate.
        NSArray  *loginItemsArray = (NSArray *)LSSharedFileListCopySnapshot (loginItems, &seedValue);
        int i = 0;
        for(i = 0 ; i < [loginItemsArray count]; i++){
            LSSharedFileListItemRef itemRef = (LSSharedFileListItemRef)[loginItemsArray objectAtIndex: i];
            //Resolve the item with URL
            if (LSSharedFileListItemResolve (itemRef, 0, (CFURLRef*) &url, NULL) == noErr) {
                NSString * urlPath = [(NSURL*)url path];
                if ([urlPath compare: appPath] == NSOrderedSame) {
                    LSSharedFileListItemRemove(loginItems,itemRef);
                }
            }
        }
        [loginItemsArray release];
    }
}

- (void)add_dir_to_sidebar: (NSString *)appPath
{
    CFURLRef url = (CFURLRef)[NSURL fileURLWithPath: appPath];

    // Create a reference to the shared file list.
    // We are adding it to the current user only.
    // If we want to add it all users, use
    // kLSSharedFileListGlobalLoginItems instead of
    //kLSSharedFileListSessionLoginItems
    LSSharedFileListRef favorItems = LSSharedFileListCreate (NULL,kLSSharedFileListFavoriteItems, NULL);
    if (favorItems) {
        LSSharedFileListItemRef item = LSSharedFileListInsertItemURL (favorItems,kLSSharedFileListItemLast, NULL, NULL, url, NULL, NULL);
        if (item) {
            CFRelease (item);
        }
    }

    CFRelease(favorItems);
}

@end
