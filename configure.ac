dnl Process this file with autoconf to produce a configure script.


AC_PREREQ(2.61)
AC_INIT([seafile], [1.6.0], [freeplant@gmail.com])
AC_CONFIG_HEADER([config.h])

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.9 foreign])

AC_MINGW32

dnl enable the build of share library by default
AC_ENABLE_SHARED

AC_SUBST(LIBTOOL_DEPS)

# Checks for programs.
AC_PROG_CC
#AM_C_PROTOTYPES
AC_C_CONST
AC_PROG_MAKE_SET
# AC_PROG_RANLIB
AC_PROG_LIBTOOL

# Checks for headers.
#AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h libintl.h limits.h locale.h netdb.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h sys/time.h termios.h unistd.h utime.h utmp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_SYS_LARGEFILE

# Checks for library functions.
#AC_CHECK_FUNCS([alarm dup2 ftruncate getcwd gethostbyname gettimeofday memmove memset mkdir rmdir select setlocale socket strcasecmp strchr strdup strrchr strstr strtol uname utime strtok_r sendfile])

# check platform
AC_MSG_CHECKING(for WIN32)
if test "$MINGW32" = yes; then
  bwin32=true
  AC_MSG_RESULT(compile in mingw32)
else
  AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(for Mac)
if test "$TERM_PROGRAM" = "Apple_Terminal"; then
  bmac=true
  AC_MSG_RESULT(compile in mac)
else
  AC_MSG_RESULT(no)
fi

AC_MSG_CHECKING(for Linux)
if test "$bmac" != "true" -a "$bwin32" != "true"; then
  blinux=true
  AC_MSG_RESULT(compile in linux)
else
  AC_MSG_RESULT(no)
fi

# test which sub-component to compile

if test "$bwin32" = true; then
   compile_client=yes
   compile_gui=yes
   compile_cli=no
   compile_tools=no
   compile_server=no
   compile_httpserver=no
fi

if test "$bmac" = true; then
   compile_client=yes
   compile_gui=yes
   compile_cli=no
   compile_tools=no
   compile_server=no
   compile_httpserver=no

fi

if test "$blinux" = true; then
   compile_cli=yes
   compile_tools=yes

   compile_server=no
   compile_httpserver=no


   AC_ARG_ENABLE(client, AC_HELP_STRING([--enable-client], [enable client]),
      [compile_client=$enableval],[compile_client="yes"])

   AC_ARG_ENABLE(gui, AC_HELP_STRING([--enable-gui], [enable gui]),
      [compile_gui=$enableval],[compile_gui="yes"])

#   AC_ARG_ENABLE(seablock, AC_HELP_STRING([--enable-seablock],
#      [enable seablock]), [compile_seablock=$enableval],
#      [compile_seablock="no"])

   AC_ARG_ENABLE(riak, AC_HELP_STRING([--enable-riak], [enable riak backend]),
      [compile_riak=$enableval],[compile_riak="no"])

   AC_ARG_ENABLE(ceph, AC_HELP_STRING([--enable-ceph], [enable ceph backend]),
      [compile_ceph=$enableval],[compile_ceph="no"])

fi

AC_ARG_ENABLE(server, AC_HELP_STRING([--enable-server], [enable server]),
   [compile_server=$enableval],[compile_server="no"])

AC_ARG_ENABLE(httpserver, AC_HELP_STRING([--enable-httpserver], [enable httpserver]),
   [compile_httpserver=$enableval],[compile_httpserver="no"])


AC_ARG_ENABLE(python,
              AC_HELP_STRING([--enable-python],[build ccnet python binding]),
              [compile_python=$enableval],
              [compile_python=yes])


AC_ARG_ENABLE(server-pkg, AC_HELP_STRING([--enable-server-pkg], [enable static compile]),
    [server_pkg=$enableval],[server_pkg="no"])

AM_CONDITIONAL([SERVER_ONLY], [test "${server_pkg}" = "yes"])


AC_ARG_ENABLE(static-build, AC_HELP_STRING([--enable-static-build], [enable static compile]),
    [static_comp=$enableval],[static_comp="no"])

if test x${static_comp} = xyes; then
  STATIC_COMPILE=-static
fi
AC_SUBST(STATIC_COMPILE)


# If we're building server release package, set the run-time path
# for the executables. So that the loader will lookup shared libs
# in 'lib' dir of the release package.
# Read "man ld.so" for description of $ORIGIN.
# Refer to http://blog.linuxgamepublishing.com/2009/02/08/our-new-way-to-meet-the-lgpl/
if test x${server_pkg} = xyes; then
  compile_client=no
  compile_cli=yes
  compile_tools=yes
  compile_server=yes
  compile_httpserver=yes
  SERVER_PKG_RPATH=-Wl,-R,\'\$\$ORIGIN/../lib\'
  SERVER_PKG_PY_RPATH=-Wl,-R,\'\$\$ORIGIN/../../..\'
fi
AC_SUBST(SERVER_PKG_RPATH)
AC_SUBST(SERVER_PKG_PY_RPATH)


AM_CONDITIONAL([COMPILE_CLI], [test "${compile_cli}" = "yes"])
AM_CONDITIONAL([COMPILE_TOOLS], [test "${compile_tools}" = "yes"])
AM_CONDITIONAL([COMPILE_PYTHON], [test "${compile_python}" = "yes"])
AM_CONDITIONAL([COMPILE_CLIENT], [test "${compile_client}" = "yes"])
AM_CONDITIONAL([COMPILE_GUI], [test "${compile_client}" = "yes" -a "${compile_gui}" = "yes"])
AM_CONDITIONAL([COMPILE_SERVER], [test "${compile_server}" = "yes"])
AM_CONDITIONAL([COMPILE_HTTPSERVER], [test "${compile_httpserver}" = "yes"])
#AM_CONDITIONAL([COMPILE_SEABLOCK], [test "${compile_seablock}" = "yes"])
AM_CONDITIONAL([COMPILE_RIAK], [test "${compile_riak}" = "yes"])
AM_CONDITIONAL([COMPILE_CEPH], [test "${compile_ceph}" = "yes"])

AM_CONDITIONAL([WIN32], [test "$bwin32" = "true"])
AM_CONDITIONAL([MACOS], [test "$bmac" = "true"])
AM_CONDITIONAL([LINUX], [test "$blinux" = "true"])


# check libraries
if test "$bwin32" != true; then
  AC_CHECK_LIB(uuid, uuid_generate, [echo "found library uuid"],
      dnl - if failed, try uuid_create
      AC_CHECK_LIB(uuid, uuid_create,[echo "found library uuid"] ,
          AC_MSG_ERROR([*** Unable to find uuid library]), )
      , )

  AC_CHECK_LIB(event, event_init,[echo "found library event"] ,
    AC_MSG_ERROR([*** Unable to find libevent library]), )
else
  AC_CHECK_LIB(event, event_init, [echo "found library event"],
    AC_MSG_ERROR([*** Unable to find libevent library]), [-lwsock32])
fi

AC_CHECK_LIB(pthread, pthread_create, [echo "found library pthread"], AC_MSG_ERROR([*** Unable to find pthread library]), )
AC_CHECK_LIB(sqlite3, sqlite3_open,[echo "found library sqlite3"] , AC_MSG_ERROR([*** Unable to find sqlite3 library]), )
AC_CHECK_LIB(crypto, SHA1_Init, [echo "found library crypto"], AC_MSG_ERROR([*** Unable to find openssl crypto library]), )

dnl Do we need to use AX_LIB_SQLITE3 to check sqlite?
dnl AX_LIB_SQLITE3

CONSOLE=
if test "$bwin32" = "true"; then
  AC_ARG_ENABLE(console, AC_HELP_STRING([--enable-console], [enable console]),
      [console=$enableval],[console="yes"])
  if test x${console} != xyes ; then
    CONSOLE="-Wl,--subsystem,windows -Wl,--entry,_mainCRTStartup"
  fi
fi
AC_SUBST(CONSOLE)

if test "$bwin32" = true; then
  LIB_WS32=-lws2_32
  LIB_GDI32=-lgdi32
  LIB_RT=
  LIB_INTL=-lintl
  LIBS=
  LIB_RESOLV=
  LIB_UUID=-lRpcrt4
  LIB_IPHLPAPI=-liphlpapi
  LIB_SHELL32=-lshell32
  LIB_PSAPI=-lpsapi
  MSVC_CFLAGS="-D__MSVCRT__ -D__MSVCRT_VERSION__=0x0601"
elif test "$bmac" = true ; then
  LIB_WS32=
  LIB_GDI32=
  LIB_RT=
  LIB_INTL=
  LIB_RESOLV=-lresolv
  LIB_UUID=-luuid
  LIB_IPHLPAPI=
  LIB_SHELL32=
  LIB_PSAPI=
  MSVC_CFLAGS=
else
  LIB_WS32=
  LIB_GDI32=
  LIB_RT=
  LIB_INTL=
  LIB_RESOLV=-lresolv
  LIB_UUID=-luuid
  LIB_IPHLPAPI=
  LIB_SHELL32=
  LIB_PSAPI=
  MSVC_CFLAGS=
fi

AC_SUBST(LIB_WS32)
AC_SUBST(LIB_GDI32)
AC_SUBST(LIB_RT)
AC_SUBST(LIB_INTL)
AC_SUBST(LIB_RESOLV)
AC_SUBST(LIB_UUID)
AC_SUBST(LIB_IPHLPAPI)
AC_SUBST(LIB_SHELL32)
AC_SUBST(LIB_PSAPI)
AC_SUBST(MSVC_CFLAGS)


# gtk and glib
APPINDICATOR_REQUIRED=0.0.7
GLIB_REQUIRED=2.16.0
GTK_REQUIRED=2.16.0
CCNET_REQUIRED=0.9.3
SEARPC_REQUIRED=1.0
ZDB_REQUIRED=2.10
#LIBNAUTILUS_EXTENSION_REQUIRED=2.30.1
CURL_REQUIRED=7.17

PKG_CHECK_MODULES(GLIB2, [glib-2.0 >= $GLIB_REQUIRED])
AC_SUBST(GLIB2_CFLAGS)
AC_SUBST(GLIB2_LIBS)

PKG_CHECK_MODULES(GOBJECT, [gobject-2.0 >= $GLIB_REQUIRED])
AC_SUBST(GOBJECT_CFLAGS)
AC_SUBST(GOBJECT_LIBS)

PKG_CHECK_MODULES(CCNET, [libccnet >= $CCNET_REQUIRED])
AC_SUBST(CCNET_CFLAGS)
AC_SUBST(CCNET_LIBS)

PKG_CHECK_MODULES(SEARPC, [libsearpc >= $SEARPC_REQUIRED])
AC_SUBST(SEARPC_CFLAGS)
AC_SUBST(SEARPC_LIBS)

AC_ARG_ENABLE(appindicator,
   AC_HELP_STRING([--enable-appindicator[=@<:@no/auto/yes@:>@]],[Build support for application indicators ]),
   [enable_appindicator=$enableval],
   [enable_appindicator="auto"])

if test x$enable_appindicator = xyes ; then
   PKG_CHECK_EXISTS([appindicator-0.1 >= $APPINDICATOR_REQUIRED],,
                   AC_MSG_ERROR([appindicator-0.1 is not installed]))
   PKG_CHECK_MODULES(APP_INDICATOR,
                    appindicator-0.1 >= $APPINDICATOR_REQUIRED)
   AC_SUBST(APP_INDICATOR_CFLAGS)
   AC_SUBST(APP_INDICATOR_LIBS)
   AC_DEFINE(HAVE_APP_INDICATOR, 1, [Have AppIndicator])
fi

AM_CONDITIONAL(HAVE_APP_INDICATOR, [test x"$enable_appindicator" = xyes])

if test "$blinux" = true -a x${compile_client} = xyes -a x${compile_gui} = xyes; then
   dnl on linux, check GTK if client and gui is enabled
   PKG_CHECK_MODULES(GTK, [gtk+-2.0 >= $GTK_REQUIRED])
   AC_SUBST(GTK_CFLAGS)
   AC_SUBST(GTK_LIBS)

   #if test x$enable_appindicator = xauto ; then
   #  PKG_CHECK_EXISTS([appindicator-0.1 >= $APPINDICATOR_REQUIRED],
   #                   enable_appindicator="yes",
   #                   enable_appindicator="no")
   #fi

   # Is libnotify available?
   LIBNOTIFY_REQUIRED=0.4.0
   PKG_CHECK_MODULES(LIBNOTIFY, libnotify >= $LIBNOTIFY_REQUIRED)
   AC_SUBST(LIBNOTIFY_CFLAGS)
   AC_SUBST(LIBNOTIFY_LIBS)

   # check whether the version of libnotify >= 0.7.0
   PKG_CHECK_MODULES(LIBNOTIFY7, [libnotify >= 0.7.0],
                    [AC_DEFINE(LIBNOTIFY_GREAT_THAN_7, 1,[Libnotify > 0.7])],
                    [echo "libnotify version is less 0.7.0"]
                    )

   # check libnautilus-extension
   #PKG_CHECK_MODULES(LIBNAUTILUS_EXTENSION, [libnautilus-extension >= $LIBNAUTILUS_EXTENSION_REQUIRED])
   #AC_SUBST(LIBNAUTILUS_EXTENSION_CFLAGS)
   #AC_SUBST(LIBNAUTILUS_EXTENSION_LIBS)
fi

# check for intltool if compile gui
if test x${compile_client} = xyes -a x${compile_gui} = xyes; then

   m4_ifdef([IT_PROG_INTLTOOL],
        [IT_PROG_INTLTOOL([0.35.0],[no-xml])],
        [AC_MSG_ERROR("--enable-nls requires intltool to be installed.")])
   AC_CHECK_HEADERS([libintl.h])
   GETTEXT_PACKAGE=seafile
   AC_SUBST(GETTEXT_PACKAGE)
   AC_DEFINE_UNQUOTED([GETTEXT_PACKAGE],["$GETTEXT_PACKAGE"],[Gettext package])
   AM_GLIB_GNU_GETTEXT
   seafilelocaledir='${prefix}/${DATADIRNAME}/locale'
   AC_SUBST(seafilelocaledir)
   AC_SUBST(INTLLIBS)
fi

if test x${compile_python} = xyes; then
   AM_PATH_PYTHON([2.6])

   if test "$bwin32" = true; then
       # set pyexecdir to somewhere like /c/Python26/Lib/site-packages
       pyexecdir=${PYTHON_DIR}/Lib/site-packages
       pythondir=${pyexecdir}
       pkgpyexecdir=${pyexecdir}/${PACKAGE}
       pkgpythondir=${pythondir}/${PACKAGE}

   fi # end for bwin32

fi


# Check mysql client library and libzdb if compile seafile server
if test "${compile_server}" = "yes"; then
   PKG_CHECK_MODULES(ZDB, [zdb >= $ZDB_REQUIRED])
   AC_SUBST(ZDB_CFLAGS)
   AC_SUBST(ZDB_LIBS)

   if test "$bwin32" != true; then
     MYSQL_CFLAGS=$(mysql_config --include)
     MYSQL_LIBS=$(mysql_config --libs_r)

     # On CentOS, libmysqlclient is in /usr/lib64/mysql/, not /usr/lib, so we
     # need to adjust CPPFLAGS and LDFLAGS before check it
     saved_CPPFLAGS=$CPPFLAGS
     saved_LDFLAGS=$LDFLAGS
     CPPFLAGS="$MYSQL_CFLAGS $CPPFLAGS"
     LDFLAGS="$MYSQL_LIBS $LDFLAGS"

     if test "$bwin32" != true; then
       AC_CHECK_LIB(mysqlclient, mysql_init, [echo "found library mysqlclient"],
       AC_MSG_ERROR([*** Unable to find mysql client library]), )
     fi

     CPPFLAGS=$saved_CPPFLAGS
     LDFLAGS=$saved_LDFLAGS

     AC_SUBST(MYSQL_LIBS)
     AC_SUBST(MYSQL_CFLAGS)

   fi
fi

if test x${compile_httpserver} = xyes; then
   dnl check libarchive
   LIBARCHIVE_REQUIRED=2.8.5
   PKG_CHECK_MODULES(LIBARCHIVE, [libarchive >= $LIBARCHIVE_REQUIRED])
   AC_SUBST(LIBARCHIVE_CFLAGS)
   AC_SUBST(LIBARCHIVE_LIBS)
fi

# We use http to communicate with Riak, check for libcurl.
if test "${compile_riak}" = "yes"; then
   PKG_CHECK_MODULES(CURL, [libcurl >= $CURL_REQUIRED])
   AC_SUBST(CURL_CFLAGS)
   AC_SUBST(CURL_LIBS)
   AC_DEFINE([RIAK_BACKEND], [1], ["define if support Riak backend"])
fi

if test "${compile_ceph}" = "yes"; then
   AC_CHECK_LIB(rados, rados_create, [with_rados=yes],
       AC_MSG_ERROR([*** Unable to find librados]), )
   echo "found rados"
   RADOS_LIBS="-lrados"
   AC_SUBST(RADOS_LIBS)
   AC_DEFINE([HAVE_RADOS], [1], ["define if have rados"])
fi

ac_configure_args="$ac_configure_args -q"

AC_CONFIG_FILES(
    seafile-web
    Makefile
    include/Makefile
    data/Makefile
    data/icons/Makefile
    data/icons/16x16/Makefile
    data/icons/22x22/Makefile
    data/icons/24x24/Makefile
    data/icons/32x32/Makefile
    data/icons/48x48/Makefile
    lib/Makefile
    gui/Makefile
    gui/gtk/Makefile
    common/Makefile
    common/cdc/Makefile
    common/index/Makefile
    daemon/Makefile
    server/Makefile
    server/gc/Makefile
    app/Makefile
    python/Makefile
    python/seafile/Makefile
    python/seaserv/Makefile
    controller/Makefile
    httpserver/Makefile
    monitor/Makefile
    tools/Makefile
    tests/Makefile
    tests/common-conf.sh
    po/Makefile.in
    doc/Makefile
)

AC_OUTPUT


echo
echo "The following modules will be built:"
echo
if test x${compile_client} = xyes; then
    echo "seaf-daemon"
    if test x${compile_gui} = xyes; then
        echo "seafile-applet"
    fi
fi
if test x${compile_server} = xyes; then
   echo    "seaf-server"
fi

if test x${compile_httpserver} = xyes; then
   echo    "httpserver"
fi
#if test x${compile_seablock} = xyes; then
#   echo    "seablock"
#fi
#if test x${compile_cluster} = xyes; then
#   echo    "cluster"
#fi

echo
