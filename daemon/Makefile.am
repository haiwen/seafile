
AM_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	-DSEAFILE_CLIENT \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib \
	-I$(top_builddir)/lib \
	-I$(top_srcdir)/common \
	@CCNET_CFLAGS@ \
	@SEARPC_CFLAGS@ \
	@GLIB2_CFLAGS@ \
	@MSVC_CFLAGS@ \
	@CURL_CFLAGS@
	-Wall

bin_PROGRAMS = 
if !SERVER_ONLY
bin_PROGRAMS += seaf-daemon
endif

proc_headers = $(addprefix processors/, \
	check-tx-proc.h \
	check-tx-v2-proc.h \
	check-tx-v3-proc.h \
	sendfs-proc.h \
	getfs-proc.h \
	sendbranch-proc.h \
	getcs-proc.h \
	sync-repo-proc.h \
	check-tx-slave-proc.h \
	getcommit-v2-proc.h \
	sendcommit-v3-proc.h \
	sendcommit-v3-new-proc.h \
	getcs-v2-proc.h \
	checkbl-proc.h \
	getcommit-v3-proc.h \
	checkff-proc.h \
	getca-proc.h \
	check-protocol-proc.h \
	sendcommit-v4-proc.h \
	sendfs-v2-proc.h \
	getfs-v2-proc.h)

proc_headers += ../common/processors/objecttx-common.h \
				../common/processors/blocktx-common.h \
				../common/processors/blocktx-common-impl.h \
				../common/processors/blocktx-common-impl-v2.h

noinst_HEADERS = \
	repo-mgr.h \
	transfer-mgr.h \
	status.h sync-mgr.h  \
	wt-monitor.h \
	merge.h merge-recursive.h vc-utils.h seafile-session.h \
	clone-mgr.h \
	wt-monitor-structs.h \
	../common/sync-repo-common.h \
	block-tx-client.h \
	seafile-config.h \
	client-migrate.h \
	http-tx-mgr.h \
	sync-status-tree.h \
	filelock-mgr.h \
	set-perm.h \
	change-set.h \
	$(proc_headers)

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
	http-tx-mgr.c \
	transfer-mgr.c \
	../common/unpack-trees.c ../common/seaf-tree-walk.c \
	merge.c merge-recursive.c vc-utils.c \
	status.c sync-mgr.c seafile-session.c \
	../common/seafile-crypt.c ../common/diff-simple.c $(wt_monitor_src) \
	clone-mgr.c \
	seafile-config.c \
	../common/branch-mgr.c ../common/fs-mgr.c \
	repo-mgr.c ../common/commit-mgr.c \
	../common/log.c ../common/object-list.c \
	../common/rpc-service.c \
	../common/vc-common.c \
	../common/seaf-utils.c \
	../common/obj-store.c \
	../common/obj-backend-fs.c \
	../common/block-mgr.c \
	../common/block-backend.c \
	../common/block-backend-fs.c \
	../common/mq-mgr.c \
	block-tx-client.c \
	../common/block-tx-utils.c \
	client-migrate.c \
	sync-status-tree.c \
	filelock-mgr.c \
	set-perm.c \
	change-set.c \
	processors/check-tx-proc.c \
	processors/check-tx-v2-proc.c \
	processors/check-tx-v3-proc.c \
	processors/sendfs-proc.c \
	processors/getfs-proc.c \
	processors/sendbranch-proc.c \
	processors/getcs-proc.c \
	processors/sync-repo-proc.c \
	processors/check-tx-slave-proc.c \
	processors/getcommit-v2-proc.c \
	processors/sendcommit-v3-proc.c \
	processors/sendcommit-v3-new-proc.c \
	processors/getcs-v2-proc.c \
	processors/checkbl-proc.c \
	processors/getcommit-v3-proc.c \
	processors/checkff-proc.c \
	processors/getca-proc.c \
	processors/check-protocol-proc.c \
	processors/sendcommit-v4-proc.c \
	processors/sendfs-v2-proc.c \
	processors/getfs-v2-proc.c


seaf_daemon_SOURCES = seaf-daemon.c $(common_src)

seaf_daemon_LDADD = $(top_builddir)/lib/libseafile_common.la \
	@LIB_INTL@ \
	@GLIB2_LIBS@  @GOBJECT_LIBS@ @SSL_LIBS@ @LIB_RT@ @LIB_UUID@ -lsqlite3 @LIBEVENT_LIBS@ \
	$(top_builddir)/common/cdc/libcdc.la \
	$(top_builddir)/common/index/libindex.la @LIB_WS32@ @LIB_CRYPT32@ \
	@SEARPC_LIBS@ @CCNET_LIBS@ @GNOME_KEYRING_LIBS@ @JANSSON_LIBS@ @LIB_MAC@ @ZLIB_LIBS@ @CURL_LIBS@

seaf_daemon_LDFLAGS = @STATIC_COMPILE@ @CONSOLE@

# seaf_tool_CFLAGS = $(AM_CFLAGS) -DSEAF_TOOL

# seaf_tool_SOURCES = seaf-tool.c $(common_src) 

# seaf_tool_LDADD = $(seaf_daemon_LDADD)

# seaf_tool_LDFLAGS = @STATIC_COMPILE@ # @CONSOLE@

#check_PROGRAMS = seaf-test

#seaf_test_SOURCES = \
#	seaf-test.c transfer-mgr.c \
#	merge.c merge-recursive.c vc-utils.c \
#	status.c sync-mgr.c seafile-session.c \
#	../common/seafile-crypt.c ../common/diff-simple.c ${wt_monitor_src} \
#	../common/seafile-config.c ../common/bitfield.c clone-mgr.c \
#	../common/branch-mgr.c ../common/fs-mgr.c \
#	repo-mgr.c ../common/commit-mgr.c \
#	../common/log.c ../common/object-list.c \
#	../common/rpc-service.c \
#	../common/gc.c ../common/vc-common.c ../common/seaf-utils.c \
#	../common/unpack-trees.c ../common/seaf-tree-walk.c \
#	../common/mq-mgr.c \
#	../common/obj-store.c \
#	../common/obj-backend-fs.c \
#	../common/block-mgr.c \
#	../common/block-backend.c \
#	../common/block-backend-fs.c \
#	processors/check-tx-proc.c \
#	processors/getcommit-proc.c \
#	processors/sendcommit-proc.c \
#	processors/sendfs-proc.c \
#	processors/getfs-proc.c \
#	processors/getblock-proc.c \
#	processors/sendblock-proc.c \
#	processors/sendbranch-proc.c \
#	processors/getcs-proc.c \
#	processors/notifysync-proc.c \
#	processors/notifysync-slave-proc.c \
#	processors/sync-repo-proc.c \
#	processors/getcommit-v2-proc.c \
#	processors/sendcommit-v2-proc.c

#seaf_test_CPPFLAGS = -DDEBUG_UNPACK_TREES -DSEAF_TEST
#seaf_test_LDADD = @CCNET_LIBS@ \
#	@LIB_INTL@ \
#	$(top_builddir)/lib/libseafile_common.la \
#	@GLIB2_LIBS@  @GOBJECT_LIBS@ @SSL_LIBS@ @LIB_RT@ @LIB_UUID@ -lsqlite3 @LIBEVENT_LIBS@ \
#	$(top_builddir)/common/cdc/libcdc.la \
#	$(top_builddir)/common/index/libindex.la ${LIB_WS32} \
#	@SEARPC_LIBS@ @LIB_DIRWATCH@

#seaf_test_LDFLAGS = @STATIC_COMPILE@  @CONSOLE@

#TESTS = seaf-test
