SUBDIRS = gc

AM_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	-DSEAFILE_SERVER \
	-DFULL_FEATURE \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib \
	-I$(top_builddir)/lib \
	-I$(top_srcdir)/common \
	@CCNET_CFLAGS@ \
	@SEARPC_CFLAGS@ \
	@GLIB2_CFLAGS@ \
	@ZDB_CFLAGS@ \
	@MSVC_CFLAGS@ \
	@CURL_CFLAGS@ \
	@LIBARCHIVE_CFLAGS@
	-Wall

bin_PROGRAMS = seaf-server

proc_headers = $(addprefix processors/, \
	recvfs-proc.h \
	recvbranch-proc.h \
	putcs-proc.h \
	sync-repo-slave-proc.h \
	check-tx-slave-v2-proc.h \
	check-tx-slave-v3-proc.h \
	putfs-proc.h \
	putcommit-v2-proc.h \
	putcommit-v3-proc.h \
	recvcommit-v3-proc.h \
	putcs-v2-proc.h \
	checkbl-proc.h \
	checkff-proc.h \
	putca-proc.h \
	check-protocol-slave-proc.h \
	recvfs-v2-proc.h \
	recvbranch-v2-proc.h \
	putfs-v2-proc.h)

noinst_HEADERS = web-accesstoken-mgr.h chunkserv-mgr.h seafile-session.h \
	repo-mgr.h \
	share-mgr.h \
	token-mgr.h \
	passwd-mgr.h \
	quota-mgr.h \
	listen-mgr.h \
	monitor-rpc-wrappers.h \
	../common/mq-mgr.h \
	size-sched.h \
	block-tx-server.h \
	copy-mgr.h \
	http-server.h \
	upload-file.h \
	access-file.h \
	pack-dir.h \
	fileserver-config.h \
	http-status-codes.h \
	$(proc_headers)

seaf_server_SOURCES = \
	seaf-server.c \
	web-accesstoken-mgr.c chunkserv-mgr.c seafile-session.c \
	share-mgr.c \
	token-mgr.c \
	passwd-mgr.c \
	quota-mgr.c \
	listen-mgr.c \
	repo-op.c \
	repo-perm.c \
	size-sched.c \
	virtual-repo.c \
	copy-mgr.c \
	http-server.c \
	upload-file.c \
	access-file.c \
	pack-dir.c \
	fileserver-config.c \
	monitor-rpc-wrappers.c ../common/seaf-db.c \
	../common/branch-mgr.c ../common/fs-mgr.c \
	repo-mgr.c ../common/commit-mgr.c \
	../common/log.c ../common/object-list.c \
	../common/rpc-service.c \
	../common/vc-common.c \
	../common/seaf-utils.c \
	../common/obj-store.c \
	../common/obj-backend-fs.c \
	../common/seafile-crypt.c \
	../common/diff-simple.c \
	../common/mq-mgr.c \
	../common/block-mgr.c \
	../common/block-backend.c \
	../common/block-backend-fs.c \
	../common/merge-new.c \
	block-tx-server.c \
	../common/block-tx-utils.c \
	processors/recvfs-proc.c \
	processors/recvbranch-proc.c \
	processors/putcs-proc.c \
	processors/sync-repo-slave-proc.c \
	processors/check-tx-slave-v2-proc.c \
	processors/check-tx-slave-v3-proc.c \
	processors/putfs-proc.c \
	processors/putcommit-v2-proc.c \
	processors/putcommit-v3-proc.c \
	processors/recvcommit-v3-proc.c \
	processors/putcs-v2-proc.c \
	processors/checkbl-proc.c \
	processors/checkff-proc.c \
	processors/putca-proc.c \
	processors/check-protocol-slave-proc.c \
	processors/recvfs-v2-proc.c \
	processors/recvbranch-v2-proc.c \
	processors/putfs-v2-proc.c

seaf_server_LDADD = @CCNET_LIBS@ \
	$(top_builddir)/lib/libseafile_common.la \
	$(top_builddir)/common/index/libindex.la \
	@GLIB2_LIBS@ @GOBJECT_LIBS@ @SSL_LIBS@ @LIB_RT@ @LIB_UUID@ -lsqlite3 @LIBEVENT_LIBS@ -levhtp -levent_openssl \
	$(top_builddir)/common/cdc/libcdc.la \
	@SEARPC_LIBS@ @JANSSON_LIBS@ @ZDB_LIBS@ @CURL_LIBS@ ${LIB_WS32} @ZLIB_LIBS@ \
	@LIBARCHIVE_LIBS@

seaf_server_LDFLAGS = @STATIC_COMPILE@ @SERVER_PKG_RPATH@
