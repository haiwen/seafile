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
	@FUSE_CFLAGS@ \
	-Wall

bin_PROGRAMS = seaf-fuse

noinst_HEADERS = seaf-fuse.h seafile-session.h repo-mgr.h

seaf_fuse_SOURCES = seaf-fuse.c \
                    seafile-session.c \
					file.c \
					getattr.c \
                    readdir.c \
                    repo-mgr.c \
                    ../common/bitfield.c \
                    ../common/block-mgr.c \
                    ../common/block-backend.c \
                    ../common/block-backend-fs.c \
                    ../common/block-backend-ceph.c \
                    ../common/branch-mgr.c \
                    ../common/commit-mgr.c \
                    ../common/fs-mgr.c \
                    ../common/log.c \
                    ../common/seaf-db.c \
                    ../common/seaf-utils.c \
                    ../common/avl/avl.c \
                    ../common/obj-store.c \
                    ../common/obj-backend-fs.c \
                    ../common/obj-backend-riak.c \
                    ../common/seafile-crypt.c

seaf_fuse_LDADD = @CCNET_LIBS@ \
				  $(top_builddir)/lib/libseafile.la \
				  @GLIB2_LIBS@ @GOBJECT_LIBS@ -lssl @LIB_RT@ @LIB_UUID@ \
                  -lsqlite3 -levent \
				  $(top_builddir)/common/cdc/libcdc.la \
				  @SEARPC_LIBS@ @ZDB_LIBS@ @FUSE_LIBS@

seaf_fuse_LDFLAGS = @STATIC_COMPILE@ @SERVER_PKG_RPATH@
