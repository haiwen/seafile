################################
# SERVER-gc
################################

set(SRC_SERVER_GC
  seafile-session.c repo-mgr.c
  ../../common/seaf-db.c
  ../../common/branch-mgr.c ../../common/fs-mgr.c
  ../../common/block-mgr.c ../../common/block-backend.c
  ../../common/block-backend-fs.c ../../common/commit-mgr.c
  ../../common/log.c
  ../../common/seaf-utils.c ../../common/obj-store.c
  ../../common/obj-backend-fs.c ../../common/seafile-crypt.c
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
include_directories(${LIBEVENT_INCLUDE_DIR})
include_directories(${LIBZDB_INCLUDE_DIR})
include_directories(${ZLIB_INCLUDE_DIR})
include_directories(${LIBCCNET_INCLUDE_DIR})

# Add seafserv-gc
add_executable(seafserv-gc
  ${SRC_SERVER_GC}
  seafserv-gc.c verify.c gc-core.c
  )
target_link_libraries(seafserv-gc
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES} ${LIBEVENT_LIBRARIES}
  ${LIBZDB_LIBRARIES} ${LIBSEARPC_LIBRARIES}
  ${UUID_LIBRARIES} ${SQLITE3_LIBRARIES}
  ${ZLIB_LIBRARIES} ${LIBCCNET_LIBRARIES}
  pthread
  libseafile_common
  libcdc
  )

# Add seaf-fsck
add_executable(seaf-fsck
  ${SRC_SERVER_GC}
  seaf-fsck.c fsck.c
  )
target_link_libraries(seaf-fsck
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES} ${LIBEVENT_LIBRARIES}
  ${LIBZDB_LIBRARIES} ${LIBSEARPC_LIBRARIES}
  ${UUID_LIBRARIES} ${SQLITE3_LIBRARIES}
  ${ZLIB_LIBRARIES} ${LIBCCNET_LIBRARIES}
  pthread
  libseafile_common
  libcdc
  )

# Add seaf-migrate
add_executable(seaf-migrate
  ${SRC_SERVER_GC}
  seaf-migrate.c
  )
target_link_libraries(seaf-migrate
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES} ${LIBEVENT_LIBRARIES}
  ${LIBZDB_LIBRARIES} ${LIBSEARPC_LIBRARIES}
  ${UUID_LIBRARIES} ${SQLITE3_LIBRARIES}
  ${ZLIB_LIBRARIES} ${LIBCCNET_LIBRARIES}
  pthread
  libseafile_common
  libcdc
  )
set_target_properties(seaf-migrate
  PROPERTIES
    COMPILE_FLAGS "-DSEAFILE_SERVER -DMIGRATION"
  )

# Install
install(TARGETS seafserv-gc seaf-fsck seaf-migrate
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
  )
