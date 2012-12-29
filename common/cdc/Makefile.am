AM_CFLAGS = -I$(top_srcdir)/common -I$(top_srcdir)/lib \
	-Wall @GLIB2_CFLAGS@ @MSVC_CFLAGS@

noinst_LTLIBRARIES = libcdc.la

noinst_HEADERS = adler32.h  cdc.h  md5.h  rabin.h srabin.h msb.h

libcdc_la_SOURCES = adler32.c  cdc.c  md5.c  rabin.c srabin.c msb.c

libcdc_la_LDFLAGS = -Wl,-z -Wl,defs
libcdc_la_LIBADD = -lssl @GLIB2_LIBS@ \
	$(top_builddir)/lib/libseafile_common.la
