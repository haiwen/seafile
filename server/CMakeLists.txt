################################
# SERVER
################################

set(SRC_SERVER_GC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/gc)
add_subdirectory(gc)

set(SRC_SERVER_PROC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proc)
file(GLOB SRC_SERVER_PROC_H ${SRC_SERVER_PROC_DIR}/*.h)
file(GLOB SRC_SERVER_PROC ${SRC_SERVER_PROC_DIR}/*.c)

set(SRC_SERVER
  seaf-server.c
  web-accesstoken-mgr.c chunkserv-mgr.c seafile-session.c
  share-mgr.c token-mgr.c passwd-mgr.c quota-mgr.c
  listen-mgr.c repo-op.c repo-perm.c size-sched.c
  virtual-repo.c copy-mgr.c monitor-rpc-wrappers.c
  repo-mgr.c block-tx-server.c
  ../common/seaf-db.c ../common/branch-mgr.c
  ../common/fs-mgr.c ../common/commit-mgr.c
  ../common/log.c ../common/object-list.c
  ../common/rpc-service.c ../common/vc-common.c
  ../common/seaf-utils.c ../common/obj-store.c
  ../common/obj-backend-fs.c ../common/seafile-crypt.c
  ../common/unpack-trees.c ../common/seaf-tree-walk.c
  ../common/diff-simple.c ../common/mq-mgr.c
  ../common/block-mgr.c ../common/block-backend.c
  ../common/block-backend-fs.c ../common/merge-new.c
  ../common/block-tx-utils.c
  processors/recvfs-proc.c processors/recvbranch-proc.c
  processors/putcs-proc.c processors/sync-repo-slave-proc.c
  processors/check-tx-slave-v2-proc.c processors/check-tx-slave-v3-proc.c
  processors/putfs-proc.c processors/putcommit-v2-proc.c
  processors/putfs-v2-proc.c
  processors/putcommit-v3-proc.c processors/recvcommit-v3-proc.c
  processors/putcs-v2-proc.c processors/checkbl-proc.c
  processors/checkff-proc.c processors/putca-proc.c
  processors/check-protocol-slave-proc.c processors/recvfs-v2-proc.c
  processors/recvbranch-v2-proc.c
  )

add_definitions(-DSEAFILE_SERVER)
add_definitions(-DFULL_FEATURE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${SRC_COMMON_DIR})
include_directories(${SRC_LIB_DIR})
include_directories(${SRC_SERVER_PROC_DIR})

include_directories(${JANSSON_INCLUDE_DIR})
include_directories(${GLIB2_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${SQLITE3_INCLUDE_DIR})
include_directories(${LIBSEARPC_INCLUDE_DIR})
include_directories(${LIBEVENT_INCLUDE_DIR})
include_directories(${LIBZDB_INCLUDE_DIR})
include_directories(${ZLIB_INCLUDE_DIR})
include_directories(${LIBCCNET_INCLUDE_DIR})

# Add seafile
add_executable(seaf-server
  ${SRC_SERVER}
  )
target_link_libraries(seaf-server
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES} ${LIBEVENT_LIBRARIES}
  ${LIBZDB_LIBRARIES} ${LIBSEARPC_LIBRARIES}
  ${UUID_LIBRARIES} ${SQLITE3_LIBRARIES}
  ${ZLIB_LIBRARIES} ${LIBCCNET_LIBRARIES}
  pthread
  libseafile_common
  libindex libcdc
  )

# Install
install(TARGETS seaf-server
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
  )
