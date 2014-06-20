if(LIBSEARPC_LIBRARIES AND LIBSEARPC_INCLUDE_DIR)
  set(LIBSEARPC_FOUND TRUE)
else(LIBSEARPC_LIBRARIES AND LIBSEARPC_INCLUDE_DIR)
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBSEARPC QUIET libsearpc)

  find_path(LIBSEARPC_INCLUDE_DIR
    NAMES
      searpc.h searpc-client.h searpc-server.h searpc-utils.h
    HINTS
      ${PC_LIBSEARPC_INCLUDEDIR}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBSEARPC_LIBRARY
    NAMES
      searpc
    HINTS
      ${PC_LIBSEARPC_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (LIBSEARPC_INCLUDE_DIR AND LIBSEARPC_LIBRARY)
    set(LIBSEARPC_FOUND TRUE)
  endif (LIBSEARPC_INCLUDE_DIR AND LIBSEARPC_LIBRARY)

  if (LIBSEARPC_FOUND)
    #Incomplete version detection
    set(LIBSEARPC_VERSION ${PC_LIBSEARPC_VERSION})

    set(LIBSEARPC_LIBRARIES
      ${LIBSEARPC_LIBRARIES}
      ${LIBSEARPC_LIBRARY}
    )

    set(LIBSEARPC_INCLUDE_DIRS
      ${LIBSEARPC_INCLUDE_DIR}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(LIBSEARPC
      REQUIRED_VARS
        LIBSEARPC_LIBRARIES
        LIBSEARPC_INCLUDE_DIR
      VERSION_VAR
        LIBSEARPC_VERSION
      )

    mark_as_advanced(LIBSEARPC_INCLUDE_DIR LIBSEARPC_LIBRARIES)

  endif (LIBSEARPC_FOUND)
endif(LIBSEARPC_LIBRARIES AND LIBSEARPC_INCLUDE_DIR)
