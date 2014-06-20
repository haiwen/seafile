################################
# APP
################################

include_directories(${SRC_LIB_DIR})
include_directories(${SRC_COMMON_DIR})
include_directories(${JANSSON_INCLUDE_DIR})
include_directories(${GLIB2_INCLUDE_DIR})
include_directories(${LIBSEARPC_INCLUDE_DIR})
include_directories(${LIBCCNET_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${SQLITE3_INCLUDE_DIR})
include_directories(${UUID_INCLUDE_DIR})
include_directories(${ZLIB_INCLUDE_DIR})

# Add seafile
add_executable(seafile seafile.c)
target_link_libraries(seafile
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${OPENSSL_LIBRARIES}
  ${SQLITE3_LIBRARIES}
  ${UUID_LIBRARIES}
  ${LIBCCNET_LIBRARIES}
  ${LIBSEARPC_LIBRARIES}
  ${JANSSON_LIBRARIES}
  ${ZLIB_LIBRARIES}
  libseafile
  libseafile_common
  )

# Add seaf-cli
if(SEAFILE_ENABLE_CLIENT)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/seaf-cli
    PERMISSIONS WORLD_EXECUTE WORLD_READ GROUP_READ GROUP_EXECUTE OWNER_EXECUTE OWNER_WRITE OWNER_READ
    DESTINATION ${BIN_INSTALL_DIR}
    )
endif(SEAFILE_ENABLE_CLIENT)

# Add seafserv-tool
if(SEAFILE_ENABLE_SERVER)
  add_executable(seafserv-tool seafserv-tool.c)
  target_link_libraries(seafserv-tool
    ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
    ${OPENSSL_LIBRARIES}
    ${SQLITE3_LIBRARIES}
    ${LIBCCNET_LIBRARIES}
    ${UUID_LIBRARIES}
    ${LIBSEARPC_LIBRARIES}
    ${JANSSON_LIBRARIES}
    ${ZLIB_LIBRARIES}
    libseafile
    )
  install(TARGETS seafserv-tool
    RUNTIME DESTINATION ${BIN_INSTALL_DIR}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
    )
endif(SEAFILE_ENABLE_SERVER)

# Install
install(TARGETS seafile
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
  )
