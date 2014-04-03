
AM_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	-DSEAFILE_SERVER \
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
	-Wall

bin_PROGRAMS = seafserv-gc seaf-fsck seaf-migrate

noinst_HEADERS = \
	seafile-session.h \
	repo-mgr.h \
	verify.h \
	fsck.h \
	gc-core.h

common_sources = \
	seafile-session.c \
	repo-mgr.c \
	../../common/seaf-db.c \
	../../common/bitfield.c \
	../../common/branch-mgr.c \
	../../common/fs-mgr.c \
	../../common/block-mgr.c \
	../../common/block-backend.c \
	../../common/block-backend-fs.c \
	../../common/commit-mgr.c \
	../../common/avl/avl.c \
	../../common/log.c \
	../../common/seaf-utils.c \
	../../common/obj-store.c \
	../../common/obj-backend-fs.c \
	../../common/seafile-crypt.c

seafserv_gc_SOURCES = \
	seafserv-gc.c \
	verify.c \
	gc-core.c \
	$(common_sources)

seafserv_gc_LDADD = @CCNET_LIBS@ \
	$(top_builddir)/common/cdc/libcdc.la \
	$(top_builddir)/lib/libseafile_common.la \
	@GLIB2_LIBS@ @GOBJECT_LIBS@ -lssl @LIB_RT@ @LIB_UUID@ -lsqlite3 -levent \
	@SEARPC_LIBS@ @ZDB_LIBS@ @CURL_LIBS@ ${LIB_WS32} @ZLIB_LIBS@

seafserv_gc_LDFLAGS = @STATIC_COMPILE@ @SERVER_PKG_RPATH@

seaf_fsck_SOURCES = \
	seaf-fsck.c \
	fsck.c \
	$(common_sources)

seaf_fsck_LDADD = @CCNET_LIBS@ \
	$(top_builddir)/common/cdc/libcdc.la \
	$(top_builddir)/lib/libseafile_common.la \
	@GLIB2_LIBS@ @GOBJECT_LIBS@ -lssl @LIB_RT@ @LIB_UUID@ -lsqlite3 -levent \
	@SEARPC_LIBS@ @ZDB_LIBS@ @CURL_LIBS@ ${LIB_WS32} @ZLIB_LIBS@

seaf_fsck_LDFLAGS = @STATIC_COMPILE@ @SERVER_PKG_RPATH@

seaf_migrate_SOURCES = \
	seaf-migrate.c \
	$(common_sources)

seaf_migrate_LDADD = @CCNET_LIBS@ \
	$(top_builddir)/common/cdc/libcdc.la \
	$(top_builddir)/lib/libseafile_common.la \
	@GLIB2_LIBS@ @GOBJECT_LIBS@ -lssl @LIB_RT@ @LIB_UUID@ -lsqlite3 -levent \
	@SEARPC_LIBS@ @ZDB_LIBS@ @CURL_LIBS@ ${LIB_WS32} @ZLIB_LIBS@

seaf_migrate_LDFLAGS = @STATIC_COMPILE@ @SERVER_PKG_RPATH@

seaf_migrate_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	-DSEAFILE_SERVER -DMIGRATION \
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
	-Wall
