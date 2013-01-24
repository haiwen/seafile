AM_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	-I$(top_srcdir)/lib  \
	@CCNET_CFLAGS@ \
	@GLIB2_CFLAGS@ \
	@MSVC_CFLAGS@ \
	-Wall

bin_PROGRAMS = seafile
if COMPILE_SERVER
bin_PROGRAMS += seafserv-tool
endif

seafile_SOURCES = seafile.c
seafile_LDADD =  @CCNET_LIBS@ \
	$(top_builddir)/lib/libseafile.la \
	$(top_builddir)/lib/libseafile_common.la \
	@SEARPC_LIBS@ \
	@GLIB2_LIBS@  @GOBJECT_LIBS@ -lssl @LIB_RT@ @LIB_UUID@ -lsqlite3

seafile_LDFALGS = @STATIC_COMPILE@ @CONSOLE@

if COMPILE_SERVER
seafserv_tool_SOURCES = seafserv-tool.c
seafserv_tool_LDADD =  @CCNET_LIBS@ \
	$(top_builddir)/lib/libseafile.la @SEARPC_LIBS@ \
	@GLIB2_LIBS@  @GOBJECT_LIBS@ -lssl @LIB_RT@ @LIB_UUID@ -lsqlite3

seafserv_tool_LDFLAGS = @STATIC_COMPILE@ @CONSOLE@ @SERVER_PKG_RPATH@
endif

# monitor_tool_SOURCES = monitor-tool.c
# monitor_tool_LDADD = @CCNET_CFLAGS@ \
# 	-lsearpc \
# 	@GLIB2_LIBS@  @GOBJECT_LIBS@ -lssl -lrt -luuid -lsqlite3
