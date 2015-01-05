AM_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/common \
	-I$(top_srcdir)/lib  \
	@CCNET_CFLAGS@ \
	@GLIB2_CFLAGS@ \
	@MSVC_CFLAGS@ \
	-Wall

if COMPILE_CLIENT
bin_SCRIPTS = seaf-cli
endif

# monitor_tool_SOURCES = monitor-tool.c
# monitor_tool_LDADD = @CCNET_CFLAGS@ \
# 	-lsearpc \
# 	@GLIB2_LIBS@  @GOBJECT_LIBS@ @SSL_LIBS@ -lrt -luuid -lsqlite3

EXTRA_DIST = seaf-cli
