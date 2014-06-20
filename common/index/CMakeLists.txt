################################
# COMMON-index
################################
include_directories(${SRC_COMMON_DIR})
include_directories(${SRC_LIB_DIR})
include_directories(${JANSSON_INCLUDE_DIR})
include_directories(${GLIB2_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Add libindex
add_library(libindex STATIC
  index.h index.c
  cache-tree.h cache-tree.c
  )
target_link_libraries(libindex
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES}
  libseafile_common
  )
set_target_properties(libindex PROPERTIES OUTPUT_NAME libindex)
set_target_properties(libindex PROPERTIES PREFIX "")
