################################
# COMMON-libcdc
################################
include_directories(${SRC_COMMON_DIR})
include_directories(${SRC_LIB_DIR})
include_directories(${JANSSON_INCLUDE_DIR})
include_directories(${GLIB2_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Add libcdc
add_library(libcdc STATIC
  ${SRC_COMMON_CDC_H} ${SRC_COMMON_CDC}
  )
target_link_libraries(libcdc
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES}
  libseafile_common
  )
set_target_properties(libcdc PROPERTIES OUTPUT_NAME libcdc)
set_target_properties(libcdc PROPERTIES PREFIX "")
