if(JANSSON_LIBRARIES AND JANSSON_INCLUDE_DIR)
  set(JANSSON_FOUND TRUE)
else(JANSSON_LIBRARIES AND JANSSON_INCLUDE_DIR)
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBJANSSON QUIET jansson)

  find_path(JANSSON_INCLUDE_DIR
    NAMES
      jansson.h
    HINTS
      ${PC_LIBJANSSON_INCLUDEDIR}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(JANSSON_LIBRARY
    NAMES
      jansson
    HINTS
      ${PC_LIBJANSSON_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (JANSSON_INCLUDE_DIR AND JANSSON_LIBRARY)
    set(JANSSON_FOUND TRUE)
  endif (JANSSON_INCLUDE_DIR AND JANSSON_LIBRARY)

  if (JANSSON_FOUND)
    #Incomplete version detection
    set(JANSSON_VERSION ${PC_LIBJANSSON_VERSION})

    set(JANSSON_LIBRARIES
      ${JANSSON_LIBRARIES}
      ${JANSSON_LIBRARY}
    )

    set(JANSSON_INCLUDE_DIRS
      ${JANSSON_INCLUDE_DIR}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(JANSSON
      REQUIRED_VARS
        JANSSON_LIBRARIES
        JANSSON_INCLUDE_DIR
      VERSION_VAR
        JANSSON_VERSION
      )

    mark_as_advanced(JANSSON_INCLUDE_DIR JANSSON_LIBRARIES)

  endif (JANSSON_FOUND)
endif(JANSSON_LIBRARIES AND JANSSON_INCLUDE_DIR)
