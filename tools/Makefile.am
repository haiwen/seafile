
#AM_CPPFLAGS = @GLIB2_CFLAGS@

bin_PROGRAMS = seaf-server-init

seaf_server_init_SOURCES = seaf-server-init.c ../common/seaf-db.c

seaf_server_init_LDADD = @GLIB2_LIBS@ @MYSQL_LIBS@ @ZDB_LIBS@
seaf_server_init_LDFLAGS = @STATIC_COMPILE@ @SERVER_PKG_RPATH@

seaf_server_init_CPPFLAGS = @GLIB2_CFLAGS@ @MYSQL_CFLAGS@ @ZDB_CFLAGS@ @MSVC_CFLAGS@

EXTRA_DIST = seafile-admin

if COMPILE_SERVER
bin_SCRIPTS = seafile-admin
endif
