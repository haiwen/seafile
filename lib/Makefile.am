
AM_CPPFLAGS = @GLIB2_CFLAGS@ -I$(top_srcdir)/include \
	-I$(top_srcdir)/lib \
	-DG_LOG_DOMAIN=\"Seafile\" \
	@CCNET_CFLAGS@ \
	@SEARPC_CFLAGS@ \
	-Wall

BUILT_SOURCES = gensource

## source file rules
seafile_object_define = repo.vala commit.vala dirent.vala dir.vala \
	task.vala branch.vala crypt.vala webaccess.vala

seafile_object_gen = $(seafile_object_define:.vala=.c)

EXTRA_DIST = ${seafile_object_define}

utils_headers = async-rpc-proc.h net.h rsa.h threaded-rpcserver-proc.h \
	bloom-filter.h rpcserver-proc.h utils.h db.h ccnetrpc-transport.h

utils_srcs = $(utils_headers:.h=.c)

noinst_HEADERS = seafile-object.h ${utils_headers} rpc-common.h include.h

seafile-rpc-wrapper.c: seafile-object.h

.vala.c:
	rm -f $@
	valac -C --pkg posix ${seafile_object_define}

seafile-object.h: ${seafile_object_define}
	rm -f $@
	valac --pkg posix ${seafile_object_define} -C -H seafile-object.h

CLEANFILES = seafile-object.h ${seafile_object_gen} ${searpc_gen}

## library rules
lib_LTLIBRARIES = libseafile.la

libseafile_la_SOURCES = ${seafile_object_gen} seafile-rpc-wrapper.c

libseafile_la_LDFLAGS = -no-undefined
libseafile_la_LIBADD = @GLIB2_LIBS@  @GOBJECT_LIBS@ @SEARPC_LIBS@

noinst_LTLIBRARIES = libseafile_common.la

libseafile_common_la_SOURCES = ${seafile_object_gen} ${utils_srcs}
libseafile_common_la_LDFLAGS = -no-undefined
libseafile_common_la_LIBADD = @GLIB2_LIBS@  @GOBJECT_LIBS@ -lssl -lcrypto @LIB_GDI32@ \
				     @LIB_UUID@ @LIB_WS32@ @LIB_PSAPI@ -lsqlite3 \
					 -levent @SEARPC_LIBS@ @LIB_SHELL32@

searpc_gen = searpc-signature.h searpc-marshal.h

gensource: ${searpc_gen}

${searpc_gen}: rpc_table.py
	@echo "[libsearpc]: generating rpc header files"
	searpc-codegen.py rpc_table.py
	@echo "[libsearpc]: done"

clean-local:
	-rm ${searpc_gen} 
