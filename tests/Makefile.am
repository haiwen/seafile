
AM_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	@GLIB2_CFLAGS@

check_PROGRAMS = test-seafile-fmt test-cdc test-index


test_seafile_fmt_SOURCES = test-seafile-fmt.c
test_seafile_fmt_CFLAGS = -I$(top_srcdir)/seafile/daemon \
	-I$(top_srcdir)/lib @GLIB2_CFLAGS@
test_seafile_fmt_LDADD = $(top_builddir)/lib/libccnet.la -lssl -levent @GLIB2_LIBS@

test_cdc_SOURCES = test-cdc.c
test_cdc_CFLAGS = -I$(top_srcdir)/seafile/common/cdc @GLIB2_CFLAGS@
test_cdc_LDADD = $(top_builddir)/seafile/common/cdc/libcdc.la @GLIB2_LIBS@ -lcrypto
test_cdc_LDFLAGS = @STATIC_COMPILE@

test_index_SOURCES = test-index.c
test_index_CFLAGS = -I$(top_srcdir)/seafile/common/index
test_index_LDADD = $(top_builddir)/seafile/common/index/libindex.la -lcrypto
test_index_LDFLAGS = @STATIC_COMPILE@

TESTS =
