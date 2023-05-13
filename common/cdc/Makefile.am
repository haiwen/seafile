AM_CFLAGS = -I$(top_srcdir)/common -I$(top_srcdir)/lib \
	-Wall @GLIB2_CFLAGS@ @MSVC_CFLAGS@

if MACOS
if COMPILE_UNIVERSAL
AM_CFLAGS += -arch x86_64 -arch arm64
endif
endif

noinst_LTLIBRARIES = libcdc.la

noinst_HEADERS = cdc.h rabin-checksum.h

libcdc_la_SOURCES = cdc.c rabin-checksum.c

libcdc_la_LDFLAGS = -Wl,-z -Wl,defs
libcdc_la_LIBADD = @GLIB2_LIBS@ \
	$(top_builddir)/lib/libseafile_common.la
