
AM_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	-DSEAFILE_SERVER \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib \
	-I$(top_builddir)/lib \
	-I$(top_srcdir)/common \
	-I$(includedir) \
	@CCNET_CFLAGS@ \
	@SEARPC_CFLAGS@ \
	@GLIB2_CFLAGS@ \
	@ZDB_CFLAGS@ \
	@CURL_CFLAGS@ \
	@LIBARCHIVE_CFLAGS@ \
	@MSVC_CFLAGS@ \
	-Wall

bin_PROGRAMS = fileserver

noinst_HEADERS = seafile-session.h repo-mgr.h \
	fileserver.h access-file.h upload-file.h pack-dir.h fileserver-config.h

fileserver_SOURCES = \
	fileserver.c \
	access-file.c \
	upload-file.c \
	seafile-session.c \
	repo-mgr.c \
	pack-dir.c \
	fileserver-config.c \
	../common/seaf-db.c \
	../common/bitfield.c \
	../common/branch-mgr.c \
	../common/fs-mgr.c \
	../common/block-mgr.c \
	../common/block-backend.c \
	../common/block-backend-fs.c \
	../common/commit-mgr.c \
	../common/log.c \
	../common/object-list.c \
	../common/seaf-utils.c \
	../common/obj-store.c \
	../common/obj-backend-fs.c \
	../common/seafile-crypt.c

# XXX: -levent_openssl must be behind in -levhtp
fileserver_LDADD = -levent -levhtp -lssl -levent_openssl \
	@GLIB2_LIBS@ @GOBJECT_LIBS@ @LIB_RT@ \
	@CCNET_LIBS@ \
	$(top_builddir)/lib/libseafile.la \
	$(top_builddir)/common/cdc/libcdc.la \
	@SEARPC_LIBS@ @JANSSON_LIBS@ @ZDB_LIBS@ @CURL_LIBS@ \
	@LIBARCHIVE_LIBS@ ${LIB_WS32} @ZLIB_LIBS@

fileserver_LDFLAGS = @STATIC_COMPILE@
