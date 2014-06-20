################################
# Unit Tests
################################

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${SRC_COMMON_DIR})
include_directories(${SRC_LIB_DIR})
include_directories(${SRC_DAEMON_DIR})

include_directories(${JANSSON_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${GLIB2_INCLUDE_DIR})
include_directories(${LIBCCNET_INCLUDE_DIR})

# Add test-seafile file
add_executable(test-seafile-fmt test-seafile-fmt.c)
target_link_libraries(test-seafile-fmt
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES}
  libseafile_common
  )
add_test(test-seafile-fmt test-seafile-fmt

add_executable(test-cdc test-cdc.c)
target_link_libraries(test-cdc
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES}
  libcdc
  )
add_test(test-cdc test-cdc)

add_executable(test-index test-index.c)
target_link_libraries(test-index
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES}
  libindex
  )
add_test(test-index test-index)
