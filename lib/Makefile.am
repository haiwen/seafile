pcfiles = libseafile.pc
pkgconfig_DATA = $(pcfiles)
pkgconfigdir = $(libdir)/pkgconfig

AM_CPPFLAGS = @GLIB2_CFLAGS@ -I$(top_srcdir)/include \
	-I$(top_srcdir)/lib \
	-I$(top_srcdir)/common \
	@CCNET_CFLAGS@ \
	@SEARPC_CFLAGS@ \
	@MSVC_CFLAGS@ \
	-Wall

BUILT_SOURCES = gensource

## source file rules
seafile_object_define = repo.vala commit.vala dirent.vala dir.vala \
	task.vala branch.vala crypt.vala webaccess.vala copy-task.vala

seafile_object_gen = $(seafile_object_define:.vala=.c)

valac_gen = ${seafile_object_gen} seafile-object.h

EXTRA_DIST = ${seafile_object_define} rpc_table.py $(pcfiles) vala.stamp

utils_headers = net.h bloom-filter.h utils.h db.h

utils_srcs = $(utils_headers:.h=.c)

noinst_HEADERS = ${utils_headers} include.h

seafiledir = $(includedir)/seafile
seafile_HEADERS = seafile-object.h

seafile-rpc-wrapper.c: seafile-object.h

seafile-object.h: ${seafile_object_define}
	rm -f $@
	valac --pkg posix ${seafile_object_define} -C -H seafile-object.h

DISTCLEANFILES = ${searpc_gen}

## library rules
lib_LTLIBRARIES = libseafile.la

libseafile_la_SOURCES = ${seafile_object_gen} seafile-rpc-wrapper.c

libseafile_la_LDFLAGS = -no-undefined
libseafile_la_LIBADD = @GLIB2_LIBS@  @GOBJECT_LIBS@ @SEARPC_LIBS@

noinst_LTLIBRARIES = libseafile_common.la

libseafile_common_la_SOURCES = ${seafile_object_gen} ${utils_srcs}
libseafile_common_la_LDFLAGS = -no-undefined
libseafile_common_la_LIBADD = @GLIB2_LIBS@  @GOBJECT_LIBS@ @SSL_LIBS@ -lcrypto @LIB_GDI32@ \
				     @LIB_UUID@ @LIB_WS32@ @LIB_PSAPI@ -lsqlite3 \
					 @LIBEVENT_LIBS@ @SEARPC_LIBS@ @LIB_SHELL32@ \
	@ZLIB_LIBS@

searpc_gen = searpc-signature.h searpc-marshal.h

gensource: ${searpc_gen} ${valac_gen}

rpc_table.stamp: ${top_srcdir}/lib/rpc_table.py
	@rm -f rpc_table.tmp
	@touch rpc_table.tmp
	@echo "[libsearpc]: generating rpc header files"
	@PYTHON@ `which searpc-codegen.py` ${top_srcdir}/lib/rpc_table.py
	@echo "[libsearpc]: done"
	@mv -f rpc_table.tmp $@

${searpc_gen}: rpc_table.stamp

vala.stamp: ${seafile_object_define}
	rm -f ${seafile_object_gen}
	@rm -f vala.tmp
	@touch vala.tmp
	valac -C --pkg posix $^
	@mv -f vala.tmp $@

${seafile_object_gen}: vala.stamp

clean-local:
	rm -f ${searpc_gen}
	rm -f rpc_table.pyc
	rm -f rpc_table.stamp
	rm -f rpc_table.tmp
	rm -f vala.tmp vala.stamp ${valac_gen}

install-data-local:
if MACOS
	sed -i '' -e "s|(DESTDIR)|${DESTDIR}|g" $(pcfiles)
else
	${SED} -i "s|(DESTDIR)|${DESTDIR}|g" $(pcfiles)
endif
