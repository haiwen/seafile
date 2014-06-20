################################
# LIB
################################

# Generate rpc-table
set(SRC_LIB_RPCTABLE_H
  ${CMAKE_CURRENT_SOURCE_DIR}/searpc-signature.h
  ${CMAKE_CURRENT_SOURCE_DIR}/searpc-marshal.h)
add_custom_command(
  PRE_BUILD
  OUTPUT ${SRC_LIB_RPCTABLE_H}
  COMMAND ${PYTHON_EXECUTABLE} ${SearpcCodegen_EXECUTABLE} rpc_table.py
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )

# Generate vala
set(SRC_LIB_VALA
  repo.vala commit.vala
  dirent.vala dir.vala
  task.vala branch.vala
  crypt.vala
  webaccess.vala copy-task.vala
  )
set(SRC_LIB_SEAFILEOBJ_H
  ${CMAKE_CURRENT_SOURCE_DIR}/seafile-object.h
  )
add_custom_command(
  PRE_BUILD
  OUTPUT ${SRC_LIB_SEAFILEOBJ_H}
  COMMAND ${Valac_EXECUTABLE} --pkg posix ${SRC_LIB_VALA} -C -H ${SRC_LIB_SEAFILEOBJ_H}
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )
set(SRC_LIB_SEAFILEOBJ
  ${CMAKE_CURRENT_SOURCE_DIR}/repo.c ${CMAKE_CURRENT_SOURCE_DIR}/commit.c
  ${CMAKE_CURRENT_SOURCE_DIR}/dirent.c ${CMAKE_CURRENT_SOURCE_DIR}/dir.c
  ${CMAKE_CURRENT_SOURCE_DIR}/task.c ${CMAKE_CURRENT_SOURCE_DIR}/branch.c
  ${CMAKE_CURRENT_SOURCE_DIR}/crypt.c
  ${CMAKE_CURRENT_SOURCE_DIR}/webaccess.c ${CMAKE_CURRENT_SOURCE_DIR}/copy-task.c
  )
add_custom_command(
  PRE_BUILD
  OUTPUT ${SRC_LIB_SEAFILEOBJ}
  COMMAND ${Valac_EXECUTABLE} --pkg posix ${SRC_LIB_VALA} -C
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  )

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${SRC_COMMON_DIR})
include_directories(${SRC_LIB_DIR})

include_directories(${JANSSON_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${GLIB2_INCLUDE_DIR})
include_directories(${SQLITE3_INCLUDE_DIR})
include_directories(${UUID_INCLUDE_DIR})
include_directories(${ZLIB_INCLUDE_DIR})
include_directories(${LIBEVENT_INCLUDE_DIR})
include_directories(${LIBSEARPC_INCLUDE_DIR})

set(SRC_LIB_UTIL
  net.c rsa.c bloom-filter.c utils.c db.c
  )
set(SRC_LIB
  seafile-rpc-wrapper.c
  ${SRC_LIB_SEAFILEOBJ}
  )
set(SRC_LIB_COMMON
  ${SRC_LIB_SEAFILEOBJ}
  ${SRC_LIB_UTIL}
  )

# Add libseafile
add_library(libseafile SHARED
  ${SRC_LIB_RPCTABLE_H}
  ${SRC_LIB_SEAFILEOBJ_H} ${SRC_LIB_SEAFILEOBJ}
  ${SRC_LIB_H} ${SRC_LIB}
  )
target_link_libraries(libseafile
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${LIBSEARPC_LIBRARIES}
  )
set_target_properties(libseafile PROPERTIES OUTPUT_NAME libseafile)
set_target_properties(libseafile PROPERTIES SOVERSION 0)
set_target_properties(libseafile PROPERTIES PREFIX "")

# Add libseafile_common
add_library(libseafile_common STATIC
  ${SRC_LIB_RPCTABLE_H}
  ${SRC_LIB_SEAFILEOBJ_H} ${SRC_LIB_SEAFILEOBJ}
  ${SRC_LIB_H} ${SRC_LIB_COMMON}
  )
target_link_libraries(libseafile_common
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES}
  ${SQLITE3_LIBRARIES}
  ${LIBEVENT_LIBRARIES}
  ${UUID_LIBRARIES}
  ${ZLIB_LIBRARIES}
  ${LIBSEARPC_LIBRARIES}
  ${JANSSON_LIBRARIES}
  )
set_target_properties(libseafile_common PROPERTIES OUTPUT_NAME libseafile_common)
set_target_properties(libseafile_common PROPERTIES PREFIX "")

# Install library
install(TARGETS libseafile
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
  )

# Install extra header
install(FILES ${SRC_LIB_SEAFILEOBJ_H}
  DESTINATION ${INCLUDE_INSTALL_DIR}/seafile
  )

# PKG-CONFIG FILE
set(LIBSEAFILE_PC_REQUIRES "")
set(LIBSEAFILE_PC_REQUIRES "${SEAFILE_PC_REQUIRES} gobject-2.0 gio-2.0 jansson openssl")
set(LIBSEAFILE_PC_LIBS "")
set(LIBSEAFILE_PC_LIBS "${SEAFILE_PC_LIBS} -lglib-2.0 -ljansson -lssl")
set(LIBSEAFILE_VERSION_STRING ${SEAFILE_VERSION_STRING})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/libseafile.pc.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/libseafile.pc @ONLY)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libseafile.pc
  DESTINATION ${LIB_INSTALL_DIR}/pkgconfig
  )
