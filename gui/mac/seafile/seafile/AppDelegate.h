//
//  AppDelegate.h
//  seafile
//
//  Created by Wei Wang on 5/15/12.
//  Copyright (c) 2012 tsinghua. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface AppDelegate : NSObject <NSApplicationDelegate> {
    IBOutlet NSMenu *statusMenu;
    
    @public
    NSImage *statusImage[2];
    NSImage *transferImage[4];
    NSImage *warningImage;
    NSImage *wktreeImage;
    NSImage *repoImage;
}

@property (retain) NSTask *task;
@property (retain) NSTask *webtask;
@property CFSocketRef sock;
@property (retain) NSStatusItem *statusItem;

@property (assign) IBOutlet NSTextFieldCell *bubbleTitle;
@property (assign) IBOutlet NSView *bubbleView;
@property (assign) IBOutlet NSTextField *bubbleText;

@property (assign) IBOutlet NSWindow *initCcnetWindow;
@property (assign) IBOutlet NSWindow *initSeafileWindow;
@property (assign) IBOutlet NSWindow *logintWindow;

@property (assign) IBOutlet NSTextField *nickNameTipLabel;
@property (assign) IBOutlet NSImageView *nickNameWarnImg;
@property (retain) IBOutlet NSTextField *nameTextField;
@property (assign) IBOutlet NSTextField *chooseDirField;
@property (assign) IBOutlet NSImageView *chooseDirWarnImg;


@property (assign) IBOutlet NSMenuItem *openBrowerItem;
@property (assign) IBOutlet NSMenuItem *restartItem;
@property (assign) IBOutlet NSMenuItem *createRepItem;

@property (assign) IBOutlet NSTextField *loginNameFiled;
@property (assign) IBOutlet NSSecureTextFieldCell *loginPwFiled;
@property (assign) IBOutlet NSButtonCell *loginBt;
@property (assign) IBOutlet NSTextField *loginWarnLabel;


@property (assign) IBOutlet NSWindow *createRepoWindow;
@property (assign) IBOutlet NSTextField *createRepoPath;
@property (assign) IBOutlet NSButton *createRepoChoosePathBt;
@property (assign) IBOutlet NSTextFieldCell *createRepoDesc;
@property (assign) IBOutlet NSPopUpButtonCell *createRepoServers;
@property (assign) IBOutlet NSButton *createRepoEncry;
@property (assign) IBOutlet NSTextField *createRepoPassAL;
@property (assign) IBOutlet NSTextField *createRepoPassL;
@property (assign) IBOutlet NSSecureTextField *createRepoPass;
@property (assign) IBOutlet NSSecureTextField *createRepoPassA;
@property (assign) IBOutlet NSButton *createRepoOKBt;
@property (assign) IBOutlet NSButton *createRepoCancelBt;
@property (assign) IBOutlet NSImageView *createRepoDirWarnImg;
@property (assign) IBOutlet NSImageView *createRepoPassWarnImg;
@property (assign) IBOutlet NSTextField *createRepoPassWarnLabel;



- (IBAction)createRepoOK:(id)sender;
- (IBAction)createRepoCancel:(id)sender;
- (IBAction)createRepoChoosePath:(id)sender;
- (IBAction)createRepoEncryToggle:(id)sender;


- (IBAction)open_browser:(id)sender;
- (IBAction)restart:(id)sender;
- (IBAction)quit:(id)sender;
- (IBAction)preferences:(id)sender;
- (IBAction)createRepo:(id)sender;
- (IBAction)openSeafileSite:(id)sender;

- (IBAction)initccnet_cancel:(id)sender;
- (IBAction)initccnet_generate:(id)sender;
- (IBAction)initseafile_ok:(id)sender;
- (IBAction)initseafile_cancel:(id)sender;
- (IBAction)initseafile_choose_dir:(id)sender;
- (IBAction)loginSeafile:(id)sender;
- (IBAction)registerSeafile:(id)sender;
- (IBAction)skipSeafile:(id)sender;

- (void) popup_bubble :(const char *)title message:(const char *) msg;

- (int) show_initccnet_window;
- (int) show_initseafile_window;
- (int) show_login_window;

- (void) add_dir_to_sidebar:(NSString *) appPath;

- (void) add_conn_server_timer:(int) timeout_ms;
- (void) add_open_browser_timer:(int) timeout_ms;
- (void) add_trayicon_rotate_timer:(int) timeout_ms;
- (void) add_heartbeat_monitor_timer:(int) timeout_ms;
- (void) add_login_timer:(int) timeout_ms;
- (void) add_app_as_login_item:(NSString *) appPath;
- (void) del_app_from_login_item:(NSString *) appPath;

@end
