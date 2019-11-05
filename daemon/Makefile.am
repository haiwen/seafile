
AM_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	-DSEAFILE_CLIENT \
	-D__USE_MINGW_ANSI_STDIO=1 \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib \
	-I$(top_builddir)/lib \
	-I$(top_srcdir)/common \
	@SEARPC_CFLAGS@ \
	@GLIB2_CFLAGS@ \
	@MSVC_CFLAGS@ \
	@CURL_CFLAGS@ \
	@BPWRAPPER_CFLAGS@ \
	@GNUTLS_CFLAGS@ \
	-Wall

bin_PROGRAMS = seaf-daemon

noinst_HEADERS = \
	job-mgr.h \
	timer.h \
	cevent.h \
	repo-mgr.h \
	sync-mgr.h  \
	wt-monitor.h \
	vc-utils.h seafile-session.h \
	clone-mgr.h \
	wt-monitor-structs.h \
	seafile-config.h \
	http-tx-mgr.h \
	sync-status-tree.h \
	filelock-mgr.h \
	set-perm.h \
	change-set.h \
	seafile-error-impl.h

if LINUX
wt_monitor_src = wt-monitor.c wt-monitor-linux.c wt-monitor-structs.c
endif

if WIN32
wt_monitor_src = wt-monitor.c wt-monitor-win32.c wt-monitor-structs.c
endif

if MACOS
wt_monitor_src = wt-monitor.c wt-monitor-macos.c wt-monitor-structs.c
endif

common_src = \
	job-mgr.c timer.c cevent.c \
	http-tx-mgr.c \
	vc-utils.c \
	sync-mgr.c seafile-session.c \
	../common/seafile-crypt.c ../common/diff-simple.c $(wt_monitor_src) \
	clone-mgr.c \
	seafile-config.c \
	seafile-error.c \
	../common/branch-mgr.c ../common/fs-mgr.c \
	repo-mgr.c ../common/commit-mgr.c \
	../common/log.c \
	../common/rpc-service.c \
	../common/vc-common.c \
	../common/obj-store.c \
	../common/obj-backend-fs.c \
	../common/block-mgr.c \
	../common/block-backend.c \
	../common/block-backend-fs.c \
	../common/mq-mgr.c \
	../common/curl-init.c \
	sync-status-tree.c \
	filelock-mgr.c \
	set-perm.c \
	change-set.c


seaf_daemon_SOURCES = seaf-daemon.c $(common_src)

seaf_daemon_LDADD = $(top_builddir)/lib/libseafile_common.la \
	@GLIB2_LIBS@  @GOBJECT_LIBS@ @SSL_LIBS@ @GNUTLS_LIBS@ @NETTLE_LIBS@ \
	@LIB_RT@ @LIB_UUID@ -lsqlite3 @LIBEVENT_LIBS@ @LIBEVENT_PTHREADS_LIBS@\
	$(top_builddir)/common/cdc/libcdc.la \
	$(top_builddir)/common/index/libindex.la @LIB_WS32@ @LIB_CRYPT32@ \
	@SEARPC_LIBS@ @JANSSON_LIBS@ @LIB_MAC@ @ZLIB_LIBS@ @CURL_LIBS@ @BPWRAPPER_LIBS@

seaf_daemon_LDFLAGS = @CONSOLE@
