pcfiles = libseafile.pc
pkgconfig_DATA = $(pcfiles)
pkgconfigdir = $(libdir)/pkgconfig

AM_CPPFLAGS = @GLIB2_CFLAGS@ -I$(top_srcdir)/include \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/common \
	@SEARPC_CFLAGS@ \
	@MSVC_CFLAGS@ \
	-Wall

BUILT_SOURCES = gensource

## source file rules
seafile_object_define = repo.vala task.vala

seafile_object_gen = $(seafile_object_define:.vala=.c)

valac_gen = ${seafile_object_gen} seafile-object.h

EXTRA_DIST = ${seafile_object_define} rpc_table.py $(pcfiles) vala.stamp

utils_headers = net.h utils.h db.h

utils_srcs = $(utils_headers:.h=.c)

noinst_HEADERS = ${utils_headers} include.h \
		searpc-signature.h searpc-marshal.h

seafiledir = $(includedir)/seafile
seafile_HEADERS = seafile-object.h

seafile-rpc-wrapper.c: seafile-object.h

seafile-object.h: ${seafile_object_define}
	rm -f $@
	@VALAC@ --pkg posix ${seafile_object_define} -C -H seafile-object.h


## library rules
lib_LTLIBRARIES = libseafile.la

libseafile_la_SOURCES = ${seafile_object_gen} seafile-rpc-wrapper.c

libseafile_la_LDFLAGS = -no-undefined
libseafile_la_LIBADD = @GLIB2_LIBS@  @GOBJECT_LIBS@ @SEARPC_LIBS@

noinst_LTLIBRARIES = libseafile_common.la

libseafile_common_la_SOURCES = ${seafile_object_gen} ${utils_srcs}
libseafile_common_la_LDFLAGS = -no-undefined
libseafile_common_la_LIBADD = @GLIB2_LIBS@  @GOBJECT_LIBS@ @LIB_GDI32@ \
				     @LIB_UUID@ @LIB_WS32@ @LIB_PSAPI@ -lsqlite3 \
					 @LIBEVENT_LIBS@ @SEARPC_LIBS@ @LIB_SHELL32@ \
	@ZLIB_LIBS@

gensource: ${valac_gen}

vala.stamp: ${seafile_object_define}
	rm -f ${seafile_object_gen}
	@rm -f vala.tmp
	@touch vala.tmp
	@VALAC@ -C --pkg posix $^
	@mv -f vala.tmp $@

${seafile_object_gen}: vala.stamp

clean-local:
	rm -f vala.tmp vala.stamp ${valac_gen}

install-data-local:
if MACOS
	sed -i '' -e "s|(DESTDIR)|${DESTDIR}|g" $(pcfiles)
else
	${SED} -i "s|(DESTDIR)|${DESTDIR}|g" $(pcfiles)
endif
