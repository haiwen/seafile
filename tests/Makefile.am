AM_CFLAGS = -DPKGDATADIR=\"$(pkgdatadir)\" \
	-DPACKAGE_DATA_DIR=\""$(pkgdatadir)"\" \
	@CCNET_CFLAGS@ \
	@GLIB2_CFLAGS@

check_PROGRAMS = test-seafile-fmt test-cdc test-index

test_seafile_fmt_SOURCES = test-seafile-fmt.c

test_seafile_fmt_CFLAGS = -I$(top_srcdir)/daemon \
	-I$(top_srcdir)/common \
	-I$(top_srcdir)/lib \
	@GLIB2_CFLAGS@

test_seafile_fmt_LDADD = @CCNET_LIBS@ \
	$(top_builddir)/lib/libseafile_common.la \
	-lssl -levent @GLIB2_LIBS@

test_cdc_SOURCES = test-cdc.c

test_cdc_CFLAGS = -I$(top_srcdir)/common/cdc \
	-I$(top_srcdir)/common \
	@GLIB2_CFLAGS@

test_cdc_LDADD = $(top_builddir)/common/cdc/libcdc.la \
	@GLIB2_LIBS@ \
	-lcrypto

test_cdc_LDFLAGS = @STATIC_COMPILE@

test_index_SOURCES = test-index.c

test_index_CFLAGS = -I$(top_srcdir)/common/index \
	-I$(top_srcdir)/common \
	-I$(top_srcdir)/lib \
	 @GLIB2_CFLAGS@

test_index_LDADD = $(top_builddir)/common/index/libindex.la \
	-lcrypto

test_index_LDFLAGS = @STATIC_COMPILE@

TESTS =