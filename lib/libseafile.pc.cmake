prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=@CMAKE_INSTALL_PREFIX@/@BIN_INSTALL_DIR@
libdir=@CMAKE_INSTALL_PREFIX@/@LIB_INSTALL_DIR@
includedir=@CMAKE_INSTALL_PREFIX@/@INCLUDE_INSTALL_DIR@

Name: libseafile
Description: Client library for accessing seafile service.
Version: @LIBSEAFILE_VERSION_STRING@
Requires: @LIBSEAFILE_PC_REQUIRES@
Libs.private: @LIBSEAFILE_PC_LIBS@
Libs: -L${libdir} -lseafile @LIBSEAFILE_LIBS@
Cflags: -I${includedir} @LIBSEAFILE_CFLAGS@
