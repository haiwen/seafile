dnl Process this file with autoconf to produce a configure script.


AC_PREREQ(2.61)
AC_INIT([seafile], [4.1.4], [freeplant@gmail.com])
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
LT_INIT

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
if test "$(uname)" = "Darwin"; then
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
   compile_cli=no
   compile_tools=no
   compile_server=no
fi

if test "$bmac" = true; then
   compile_client=yes
   compile_cli=no
   compile_tools=no
   compile_server=no
fi

if test "$blinux" = true; then
   compile_cli=yes
   compile_tools=yes

   compile_server=no

#   AC_ARG_ENABLE(seablock, AC_HELP_STRING([--enable-seablock],
#      [enable seablock]), [compile_seablock=$enableval],
#      [compile_seablock="no"])

   AC_ARG_ENABLE(riak, AC_HELP_STRING([--enable-riak], [enable riak backend]),
      [compile_riak=$enableval],[compile_riak="no"])
fi

if test "$bwin32" != true; then
   AC_ARG_ENABLE(fuse, AC_HELP_STRING([--enable-fuse], [enable fuse virtual file system]),
      [compile_fuse=$enableval],[compile_fuse="yes"])
fi

AC_ARG_ENABLE(client, AC_HELP_STRING([--enable-client], [enable client]),
   [compile_client=$enableval],[compile_client="yes"])

AC_ARG_ENABLE(server, AC_HELP_STRING([--enable-server], [enable server]),
   [compile_server=$enableval],[compile_server="no"])

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
  SERVER_PKG_RPATH=-Wl,-R,\'\$\$ORIGIN/../lib\'
  SERVER_PKG_PY_RPATH=-Wl,-R,\'\$\$ORIGIN/../../..\'
fi
AC_SUBST(SERVER_PKG_RPATH)
AC_SUBST(SERVER_PKG_PY_RPATH)


AM_CONDITIONAL([COMPILE_CLI], [test "${compile_cli}" = "yes"])
AM_CONDITIONAL([COMPILE_TOOLS], [test "${compile_tools}" = "yes"])
AM_CONDITIONAL([COMPILE_PYTHON], [test "${compile_python}" = "yes"])
AM_CONDITIONAL([COMPILE_CLIENT], [test "${compile_client}" = "yes"])
AM_CONDITIONAL([COMPILE_SERVER], [test "${compile_server}" = "yes"])
#AM_CONDITIONAL([COMPILE_SEABLOCK], [test "${compile_seablock}" = "yes"])
AM_CONDITIONAL([COMPILE_RIAK], [test "${compile_riak}" = "yes"])
AM_CONDITIONAL([COMPILE_FUSE], [test "${compile_fuse}" = "yes"])

AM_CONDITIONAL([WIN32], [test "$bwin32" = "true"])
AM_CONDITIONAL([MACOS], [test "$bmac" = "true"])
AM_CONDITIONAL([LINUX], [test "$blinux" = "true"])


# check libraries
if test "$bwin32" != true; then
  if test "$bmac" = true; then
  AC_CHECK_LIB(c, uuid_generate, [echo "found library uuid"],
          AC_MSG_ERROR([*** Unable to find uuid_generate in libc]), )
  else
  AC_CHECK_LIB(uuid, uuid_generate, [echo "found library uuid"],
          AC_MSG_ERROR([*** Unable to find uuid library]), )
  fi
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
  LIB_MAC=
  MSVC_CFLAGS="-D__MSVCRT__ -D__MSVCRT_VERSION__=0x0601"
elif test "$bmac" = true ; then
  LIB_WS32=
  LIB_GDI32=
  LIB_RT=
  LIB_INTL=
  LIB_RESOLV=-lresolv
  LIB_UUID=
  LIB_IPHLPAPI=
  LIB_SHELL32=
  LIB_PSAPI=
  MSVC_CFLAGS=
  LIB_MAC="-framework CoreServices"
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
  LIB_MAC=
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
AC_SUBST(LIB_MAC)
AC_SUBST(MSVC_CFLAGS)


LIBEVENT_REQUIRED=2.0
GLIB_REQUIRED=2.16.0
CCNET_REQUIRED=0.9.3
SEARPC_REQUIRED=1.0
JANSSON_REQUIRED=2.2.1
ZDB_REQUIRED=2.10
#LIBNAUTILUS_EXTENSION_REQUIRED=2.30.1
CURL_REQUIRED=7.17
FUSE_REQUIRED=2.7.3
ZLIB_REQUIRED=1.2.0

PKG_CHECK_MODULES(SSL, [openssl])
AC_SUBST(SSL_CFLAGS)
AC_SUBST(SSL_LIBS)

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

PKG_CHECK_MODULES(JANSSON, [jansson >= $JANSSON_REQUIRED])
AC_SUBST(JANSSON_CFLAGS)
AC_SUBST(JANSSON_LIBS)

PKG_CHECK_MODULES(LIBEVENT, [libevent >= $LIBEVENT_REQUIRED])
AC_SUBST(LIBEVENT_CFLAGS)
AC_SUBST(LIBEVENT_LIBS)

PKG_CHECK_MODULES(ZLIB, [zlib >= $ZLIB_REQUIRED])
AC_SUBST(ZLIB_CFLAGS)
AC_SUBST(ZLIB_LIBS)

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


# Check libzdb if compile seafile server
if test "${compile_server}" = "yes"; then
   PKG_CHECK_MODULES(ZDB, [zdb >= $ZDB_REQUIRED])
   AC_SUBST(ZDB_CFLAGS)
   AC_SUBST(ZDB_LIBS)
fi

if test "${compile_fuse}" = "yes"; then
   PKG_CHECK_MODULES(FUSE, [fuse >= $FUSE_REQUIRED])
   AC_SUBST(FUSE_CFLAGS)
   AC_SUBST(FUSE_LIBS)
fi

if test x${compile_server} = xyes; then
   dnl check libarchive
   LIBARCHIVE_REQUIRED=2.8.5
   PKG_CHECK_MODULES(LIBARCHIVE, [libarchive >= $LIBARCHIVE_REQUIRED])
   AC_SUBST(LIBARCHIVE_CFLAGS)
   AC_SUBST(LIBARCHIVE_LIBS)
fi

if test "${compile_client}" = "yes"; then
   PKG_CHECK_MODULES(CURL, [libcurl >= $CURL_REQUIRED])
   AC_SUBST(CURL_CFLAGS)
   AC_SUBST(CURL_LIBS)
fi

AM_CONDITIONAL([HAVE_KEYSTORAGE_GK], [test "${compile_gnome_keyring}" = "yes"])
if test "${compile_gnome_keyring}" = "yes"; then
   PKG_CHECK_MODULES(GNOME_KEYRING, [gnome-keyring-1])
   AC_SUBST(GNOME_KEYRING_CFLAGS)
   AC_SUBST(GNOME_KEYRING_LIBS)
   AC_DEFINE(HAVE_KEYSTORAGE_GK, 1, [Have Gnome-Keyring support])
fi

ac_configure_args="$ac_configure_args -q"

AC_CONFIG_FILES(
    Makefile
    include/Makefile
    fuse/Makefile
    lib/Makefile
    lib/libseafile.pc
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
    tools/Makefile
    tests/Makefile
    tests/common-conf.sh
    doc/Makefile
)

AC_OUTPUT


echo
echo "The following modules will be built:"
echo
if test x${compile_client} = xyes; then
    echo "seaf-daemon"
fi
if test x${compile_server} = xyes; then
   echo    "seaf-server"
fi

echo
