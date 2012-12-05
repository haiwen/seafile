//
//  platform.h
//  seafile
//
//  Created by Wei Wang on 6/9/12.
//  Copyright (c) 2012 tsinghua. All rights reserved.
//

#ifndef seafile_platform_h
#define seafile_platform_h

#define SEAFILEWEBBUNDLE @"seafile.seafileweb"
#define NS_SEAF_HTTP_ADDR @"127.0.0.1:13420"


void show_warning (const char *title, const char *fmt, ...);

void shutdown_process (const char *name);

int is_process_already_running (const char *name);


int msgbox_yes_or_no (char *format, ...);

gboolean trayicon_do_rotate (void);

void seafile_set_seafilefolder_icns (void);

void seafile_set_repofolder_icns (const char *path);

void seafile_unset_repofolder_icns (const char *path);

int set_visibility_for_file (const char *filename, int isDirectory, int visible);

void reset_trayicon_and_tip (void);

#endif
