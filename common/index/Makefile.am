AM_CPPFLAGS = -Wall -I${top_srcdir}/common -I${top_srcdir}/lib \
	@MSVC_CFLAGS@

noinst_LTLIBRARIES = libindex.la

noinst_HEADERS = index.h cache-tree.h

libindex_la_SOURCES = index.c cache-tree.c

libindex_la_CFLAGS = @GLIB2_CFLAGS@
libindex_la_LDFLAGS = -Wl,-z -Wl,defs
libindex_la_LIBADD = @GLIB2_LIBS@ \
	$(top_builddir)/lib/libseafile_common.la
