################################
# SERVER
################################

set(SRC_FILESERVER
  fileserver.c fileserver-config.c
  access-file.c upload-file.c seafile-session.c repo-mgr.c pack-dir.c
  ../common/seaf-db.c
  ../common/branch-mgr.c
  ../common/fs-mgr.c
  ../common/block-mgr.c
  ../common/block-backend.c
  ../common/block-backend-fs.c
  ../common/commit-mgr.c
  ../common/log.c
  ../common/object-list.c
  ../common/seaf-utils.c
  ../common/obj-store.c
  ../common/obj-backend-fs.c
  ../common/seafile-crypt.c
  )

add_definitions(-DSEAFILE_SERVER)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${SRC_COMMON_DIR})
include_directories(${SRC_LIB_DIR})

include_directories(${JANSSON_INCLUDE_DIR})
include_directories(${GLIB2_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${SQLITE3_INCLUDE_DIR})
include_directories(${LIBSEARPC_INCLUDE_DIR})
include_directories(${LIBCCNET_INCLUDE_DIR})
include_directories(${LIBEVENT_INCLUDE_DIR})
include_directories(${LIBZDB_INCLUDE_DIR})
include_directories(${ZLIB_INCLUDE_DIR})
include_directories(${LIBEVHTP_INCLUDE_DIR})
include_directories(${LIBARCHIVE_INCLUDE_DIR})

# Add seafile
add_executable(fileserver
  ${SRC_FILESERVER}
  )
target_link_libraries(fileserver
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES} ${LIBEVENT_LIBRARIES}
  ${LIBZDB_LIBRARIES} ${LIBSEARPC_LIBRARIES}
  ${UUID_LIBRARIES} ${SQLITE3_LIBRARIES}
  ${ZLIB_LIBRARIES}
  ${LIBEVHTP_LIBRARIES} ${LIBEVENT_OPENSSL_LIBRARY}
  ${LIBARCHIVE_LIBRARIES}
  ${LIBCCNET_LIBRARIES}
  pthread
  libseafile
  libcdc
  )

if(APPLE)
  target_link_libraries(fileserver iconv)
endif(APPLE)

# Install
install(TARGETS fileserver
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
  )
