################################
# DAEMON
################################

set(SRC_DAEMON_COMMON
  transfer-mgr.c
  ../common/unpack-trees.c ../common/seaf-tree-walk.c
  merge.c merge-recursive.c vc-utils.c
  status.c sync-mgr.c seafile-session.c
  client-migrate.c
  ../common/seafile-crypt.c ../common/diff-simple.c
  clone-mgr.c
  seafile-config.c
  ../common/branch-mgr.c ../common/fs-mgr.c
  repo-mgr.c ../common/commit-mgr.c
  ../common/log.c ../common/object-list.c
  ../common/rpc-service.c
  ../common/vc-common.c
  ../common/seaf-utils.c
  ../common/obj-store.c
  ../common/obj-backend-fs.c
  ../common/block-mgr.c
  ../common/block-backend.c
  ../common/block-backend-fs.c
  ../common/mq-mgr.c
  block-tx-client.c
  ../common/block-tx-utils.c
  processors/check-tx-proc.c
  processors/check-tx-v2-proc.c
  processors/check-tx-v3-proc.c
  processors/sendfs-proc.c
  processors/sendfs-v2-proc.c
  processors/getfs-proc.c
  processors/getfs-v2-proc.c
  processors/sendbranch-proc.c
  processors/getcs-proc.c
  processors/sync-repo-proc.c
  processors/check-tx-slave-proc.c
  processors/getcommit-v2-proc.c
  processors/sendcommit-v3-proc.c
  processors/sendcommit-v4-proc.c
  processors/sendcommit-v3-new-proc.c
  processors/getcs-v2-proc.c
  processors/sendfs-v2-proc.c
  processors/checkbl-proc.c
  processors/getcommit-v3-proc.c
  processors/checkff-proc.c
  processors/getca-proc.c
  processors/check-protocol-proc.c
  )

add_definitions(-DSEAFILE_CLIENT)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${SRC_LIB_DIR})
include_directories(${SRC_COMMON_DIR})

include_directories(${JANSSON_INCLUDE_DIR})
include_directories(${GLIB2_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${SQLITE3_INCLUDE_DIR})
include_directories(${LIBSEARPC_INCLUDE_DIR})
include_directories(${LIBCCNET_INCLUDE_DIR})
include_directories(${LIBEVENT_INCLUDE_DIR})
set(SRC_DAEMON daemon-session.c)
set(SRC_DAEMON_PROC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/processors)
file(GLOB SRC_DAEMON_PROC_H ${SRC_DAEMON_PROC_DIR}/*.h)

if(APPLE)
  set(SRC_DAEMON_WT_MONITOR wt-monitor-structs.c wt-monitor.c wt-monitor-macos.c)
elseif(WIN32)
  set(SRC_DAEMON_WT_MONITOR wt-monitor-structs.c wt-monitor.c wt-monitor-win32.c)
elseif(UNIX)
  set(SRC_DAEMON_WT_MONITOR wt-monitor-structs.c wt-monitor.c wt-monitor-linux.c)
endif(APPLE)

# Add seaf-daemon
if(SEAFILE_ENABLE_CLIENT AND NOT SEAFILE_ENABLE_SERVER)
  add_executable(seaf-daemon seaf-daemon.c client-migrate.c
    ${SRC_DAEMON_WT_MONITOR}
    ${SRC_DAEMON_COMMON}
    )
  target_link_libraries(seaf-daemon
    ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
    ${OPENSSL_LIBRARIES} ${LIBEVENT_LIBRARIES}
    ${LIBCCNET_LIBRARIES} ${LIBSEARPC_LIBRARIES}
    ${UUID_LIBRARIES} ${SQLITE3_LIBRARIES}
    libcdc libindex
    libseafile_common
    )
  if(APPLE)
    find_library(CORESERVICES_LIB
      NAMES CoreServices
      PATHS ${CMAKE_OSX_SYSROOT}/System/Library
      PATH_SUFFIXES Frameworks
      NO_DEFAULT_PATH
      )
    target_link_libraries(seaf-daemon
      ${CORESERVICES_LIB}
      )
  endif(APPLE)

  # Install
  install(TARGETS seaf-daemon
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
    )
endif(SEAFILE_ENABLE_CLIENT AND NOT SEAFILE_ENABLE_SERVER)
