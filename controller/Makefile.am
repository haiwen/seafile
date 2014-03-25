bin_PROGRAMS = seafile-controller

AM_CFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib \
	-I$(top_builddir)/lib \
	-I$(top_srcdir)/common \
	@CCNET_CFLAGS@ \
	@SEARPC_CFLAGS@ \
	@GLIB2_CFLAGS@ \
	@ZDB_CFLAGS@ \
	-Wall

noinst_HEADERS = seafile-controller.h ../common/log.h

seafile_controller_SOURCES = seafile-controller.c ../common/log.c

seafile_controller_LDADD = @CCNET_LIBS@ \
	$(top_builddir)/lib/libseafile_common.la \
	@GLIB2_LIBS@  @GOBJECT_LIBS@ -lssl @LIB_RT@ @LIB_UUID@ -levent \
	@SEARPC_LIBS@ @ZLIB_LIBS@

seafile_controller_LDFLAGS = @STATIC_COMPILE@ @SERVER_PKG_RPATH@
