dnl Process this file with autoconf to produce a configure script.


AC_PREREQ(2.61)
AC_INIT([seafile], [8.0.6], [info@seafile.com])
AC_CONFIG_HEADER([config.h])

AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([1.9 foreign])

#AC_MINGW32
AC_CANONICAL_BUILD

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

AM_PROG_VALAC([], [], [AC_MSG_ERROR([*** Unable to find Vala compiler])])

# Checks for headers.
#AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h libintl.h limits.h locale.h netdb.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h sys/time.h termios.h unistd.h utime.h utmp.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_SYS_LARGEFILE

# Checks for library functions.
#AC_CHECK_FUNCS([alarm dup2 ftruncate getcwd gethostbyname gettimeofday memmove memset mkdir rmdir select setlocale socket strcasecmp strchr strdup strrchr strstr strtol uname utime strtok_r sendfile])

# check platform
AC_MSG_CHECKING(for WIN32)
if test "$build_os" = "mingw32" -o "$build_os" = "mingw64"; then
  bwin32=true
  AC_MSG_RESULT(compile in mingw)
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
  LIB_CRYPT32=-lcrypt32
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
  LIB_CRYPT32=
  LIB_ICONV=-liconv
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
  LIB_CRYPT32=
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
AC_SUBST(LIB_CRYPT32)
AC_SUBST(LIB_ICONV)


LIBEVENT_REQUIRED=2.0
LIBEVENT_PTHREADS_REQUIRED=2.0
GLIB_REQUIRED=2.16.0
SEARPC_REQUIRED=1.0
JANSSON_REQUIRED=2.2.1
CURL_REQUIRED=7.17
ZLIB_REQUIRED=1.2.0
GNUTLS_REQUIRED=3.3.0

PKG_CHECK_MODULES(GLIB2, [glib-2.0 >= $GLIB_REQUIRED])
AC_SUBST(GLIB2_CFLAGS)
AC_SUBST(GLIB2_LIBS)

PKG_CHECK_MODULES(GOBJECT, [gobject-2.0 >= $GLIB_REQUIRED])
AC_SUBST(GOBJECT_CFLAGS)
AC_SUBST(GOBJECT_LIBS)

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

PKG_CHECK_MODULES(CURL, [libcurl >= $CURL_REQUIRED])
AC_SUBST(CURL_CFLAGS)
AC_SUBST(CURL_LIBS)

if test "$bwin32" != true; then
# do not check libevent_pthreads in win32
PKG_CHECK_MODULES(LIBEVENT_PTHREADS, [libevent_pthreads >= $LIBEVENT_PTHREADS_REQUIRED])
AC_SUBST(LIBEVENT_PTHREADS_CFLAGS)
AC_SUBST(LIBEVENT_PTHREADS_LIBS)
fi

AC_ARG_WITH([python3], [AS_HELP_STRING([--with-python3], [use python3])],
	[with_python3="yes"],[])

if test "$with_python3" = "yes"; then
   AM_PATH_PYTHON([3.5])
else
   AM_PATH_PYTHON([2.7])
fi

if test "$bwin32" = true; then
    # set pyexecdir to somewhere like /c/Python26/Lib/site-packages
    pyexecdir=${PYTHON_DIR}/Lib/site-packages
    pythondir=${pyexecdir}
    pkgpyexecdir=${pyexecdir}/${PACKAGE}
    pkgpythondir=${pythondir}/${PACKAGE}

fi # end for bwin32


BPWRAPPER_REQUIRED=0.1
AC_ARG_ENABLE(breakpad, AC_HELP_STRING([--enable-breakpad], [build google breadpad support]),
                               [compile_breakpad=$enableval],[compile_breakpad="no"])

AM_CONDITIONAL([HAVE_BREAKPAD_SUPPORT], [test "${compile_breakpad}" = "yes"])
if test "${compile_breakpad}" = "yes"; then
   PKG_CHECK_MODULES(BPWRAPPER, [bpwrapper])
   AC_DEFINE(HAVE_BREAKPAD_SUPPORT, 1, [Breakpad support enabled])
   AC_SUBST(BPWRAPPER_CFLAGS)
   AC_SUBST(BPWRAPPER_LIBS)
fi

AC_ARG_WITH([gpl-crypto],
            AS_HELP_STRING([--with-gpl-crypto=[yes|no]],
                [Use GPL compatible crypto libraries. Default no.]),
            [ gpl_crypto=$with_gpl_crypto ],
            [ gpl_crypto="no"])
if test "xyes" = "x$gpl_crypto"; then
   PKG_CHECK_MODULES(GNUTLS, [gnutls >= $GNUTLS_REQUIRED])
   AC_SUBST(GNUTLS_CFLAGS)
   AC_SUBST(GNUTLS_LIBS)

   PKG_CHECK_MODULES(NETTLE, [nettle])
   AC_SUBST(NETTLE_CFLAGS)
   AC_SUBST(NETTLE_LIBS)

   AC_DEFINE(USE_GPL_CRYPTO, 1, [Use GPL-compatible crypto libraries])
else
   AC_CHECK_LIB(crypto, SHA1_Init, [echo "found library crypto"], AC_MSG_ERROR([*** Unable to find openssl crypto library]), )

   PKG_CHECK_MODULES(SSL, [openssl])
   AC_SUBST(SSL_CFLAGS)
   AC_SUBST(SSL_LIBS)
fi

ac_configure_args="$ac_configure_args -q"

AC_CONFIG_FILES(
    Makefile
    include/Makefile
    lib/Makefile
    lib/libseafile.pc
    common/Makefile
    common/cdc/Makefile
    common/index/Makefile
    daemon/Makefile
    app/Makefile
    doc/Makefile
    python/Makefile
    python/seafile/Makefile
)

AC_OUTPUT
