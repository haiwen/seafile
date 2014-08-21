if(LIBCCNET_LIBRARIES AND LIBCCNET_INCLUDE_DIR)
  set(LIBCCNET_FOUND TRUE)
else(LIBCCNET_LIBRARIES AND LIBCCNET_INCLUDE_DIR)
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBCCNET QUIET libccnet)

  find_path(LIBCCNET_INCLUDE_DIR
    NAMES
      ccnet.h
    HINTS
      ${PC_LIBCCNET_INCLUDEDIR}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBCCNET_LIBRARY
    NAMES
      ccnet
    HINTS
      ${PC_LIBCCNET_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (LIBCCNET_INCLUDE_DIR AND LIBCCNET_LIBRARY)
    set(LIBCCNET_FOUND TRUE)
  endif (LIBCCNET_INCLUDE_DIR AND LIBCCNET_LIBRARY)

  if (LIBCCNET_FOUND)
    #Incomplete version detection
    set(LIBCCNET_VERSION ${PC_LIBCCNET_VERSION})

    set(LIBCCNET_LIBRARIES
      ${LIBCCNET_LIBRARIES}
      ${LIBCCNET_LIBRARY}
    )

    set(LIBCCNET_INCLUDE_DIRS
      ${LIBCCNET_INCLUDE_DIR}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(LIBCCNET
      REQUIRED_VARS
        LIBCCNET_LIBRARIES
        LIBCCNET_INCLUDE_DIR
      VERSION_VAR
        LIBCCNET_VERSION
      )

    mark_as_advanced(LIBCCNET_INCLUDE_DIR LIBCCNET_LIBRARIES)

  endif (LIBCCNET_FOUND)
endif(LIBCCNET_LIBRARIES AND LIBCCNET_INCLUDE_DIR)

