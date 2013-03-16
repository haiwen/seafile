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
	@MYSQL_CFLAGS@ \
	@ZDB_CFLAGS@ \
	@MSVC_CFLAGS@ \
	@CURL_CFLAGS@ \
	-Wall

bin_PROGRAMS = seaf-server

proc_headers = $(addprefix processors/, \
	recvfs-proc.h \
	recvbranch-proc.h \
	recvblock-v2-proc.h \
	putcs-proc.h \
	sync-repo-slave-proc.h \
	check-tx-slave-v2-proc.h \
	check-tx-slave-v3-proc.h \
	putfs-proc.h \
	putcommit-v2-proc.h \
	recvcommit-v3-proc.h)

proc_headers += ../common/processors/putblock-v2-proc.h

noinst_HEADERS = web-accesstoken-mgr.h chunkserv-mgr.h seafile-session.h \
	repo-mgr.h \
	share-mgr.h \
	token-mgr.h \
	passwd-mgr.h \
	quota-mgr.h \
	listen-mgr.h \
	monitor-rpc-wrappers.h \
	../common/mq-mgr.h \
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
	monitor-rpc-wrappers.c ../common/seaf-db.c \
	../common/seafile-config.c ../common/bitfield.c \
	../common/branch-mgr.c ../common/fs-mgr.c \
	repo-mgr.c ../common/commit-mgr.c \
	../common/log.c ../common/avl/avl.c ../common/object-list.c \
	../common/rpc-service.c \
	../common/vc-common.c \
	../common/seaf-utils.c \
	../common/obj-store.c \
	../common/obj-backend-fs.c \
	../common/obj-backend-riak.c \
	../common/riak-http-client.c \
	../common/seafile-crypt.c \
	../common/unpack-trees.c \
	../common/seaf-tree-walk.c \
	../common/diff-simple.c \
	../common/mq-mgr.c \
	../common/block-mgr.c \
	../common/block-backend.c \
	../common/block-backend-fs.c \
	../common/block-backend-ceph.c \
	../common/merge-new.c \
	processors/recvfs-proc.c \
	processors/recvblock-v2-proc.c \
	processors/recvbranch-proc.c \
	processors/putcs-proc.c \
	processors/sync-repo-slave-proc.c \
	processors/check-tx-slave-v2-proc.c \
	processors/check-tx-slave-v3-proc.c \
	processors/putfs-proc.c \
	../common/processors/putblock-v2-proc.c \
	processors/putcommit-v2-proc.c \
	processors/recvcommit-v3-proc.c

seaf_server_LDADD = @CCNET_LIBS@ \
	$(top_builddir)/lib/libseafile_common.la \
	$(top_builddir)/common/index/libindex.la \
	@GLIB2_LIBS@ @GOBJECT_LIBS@ -lssl @LIB_RT@ @LIB_UUID@ -lsqlite3 -levent \
	$(top_builddir)/common/cdc/libcdc.la \
	@MYSQL_LIBS@ @SEARPC_LIBS@ @ZDB_LIBS@ @RADOS_LIBS@ @CURL_LIBS@ ${LIB_WS32}

seaf_server_LDFLAGS = @STATIC_COMPILE@ @SERVER_PKG_RPATH@
