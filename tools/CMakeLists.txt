################################
# TOOLS
################################

include_directories(${GLIB2_INCLUDE_DIR})
include_directories(${LIBZDB_INCLUDE_DIR})
include_directories(${SRC_COMMON_DIR})

# Add seaf-server-init
add_executable(seaf-server-init
  seaf-server-init.c
  ../common/seaf-db.c
  )
target_link_libraries(seaf-server-init
  ${GLIB2_LIBRARIES} gobject-2.0 gio-2.0
  ${LIBZDB_LIBRARIES}
  pthread
  )

# Add seafile-admin
if(SEAFILE_ENABLE_SERVER)
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/seafile-admin
    PERMISSIONS WORLD_EXECUTE WORLD_READ GROUP_READ GROUP_EXECUTE OWNER_EXECUTE OWNER_WRITE OWNER_READ
    DESTINATION ${BIN_INSTALL_DIR}
    )
endif(SEAFILE_ENABLE_SERVER)

# Install
install(TARGETS seaf-server-init
  RUNTIME DESTINATION ${BIN_INSTALL_DIR}
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}
  ARCHIVE DESTINATION ${LIB_INSTALL_DIR}
  )
