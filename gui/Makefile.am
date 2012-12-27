if WIN32
SUBDIRS = win
DIST_SUBDIRS = win
endif

if MACOS
SUBDIRS = mac
DIST_SUBDIRS = mac
endif

if LINUX
SUBDIRS = gtk
DIST_SUBDIRS = gtk
endif

WIN_SRCS = $(addprefix win/, \
	seafile-applet.c trayicon.c init-ccnet.c )

WIN_ICONS = $(addprefix win/, \
	seafile.ico ccnet_daemon_up.ico ccnet_daemon_down.ico \
	seafile_transfer_3.ico seafile_transfer_4.ico \
	seafile_auto_sync_disabled.ico \
	window-head.bmp win7-trayicon-tip.bmp )

EXTRA_DIST = win
