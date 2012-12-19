AM_CPPFLAGS = -Wall -I${top_srcdir}/common

noinst_LTLIBRARIES = libindex.la

noinst_HEADERS = index.h hash.h cache-tree.h

libindex_la_SOURCES = index.c hash.c name-hash.c cache-tree.c

libindex_la_CFLAGS = @GLIB2_CFLAGS@
libindex_la_LDFLAGS = -Wl,-z -Wl,defs
libindex_la_LIBADD = -lssl @GLIB2_LIBS@
