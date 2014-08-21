if(LIBEVHTP_LIBRARIES AND LIBEVHTP_INCLUDE_DIR)
  set(LIBEVHTP_FOUND TRUE)
else(LIBEVHTP_LIBRARIES AND LIBEVHTP_INCLUDE_DIR)
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBEVHTP QUIET libevhtp)

  find_path(LIBEVHTP_INCLUDE_DIR
    NAMES
      evhtp.h
    HINTS
      ${PC_LIBEVHTP_INCLUDEDIR}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBEVHTP_LIBRARY
    NAMES
      evhtp
    HINTS
      ${PC_LIBEVHTP_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (LIBEVHTP_INCLUDE_DIR AND LIBEVHTP_LIBRARY)
    set(LIBEVHTP_FOUND TRUE)
  endif (LIBEVHTP_INCLUDE_DIR AND LIBEVHTP_LIBRARY)

  if (LIBEVHTP_FOUND)
    #Incomplete version detection
    set(LIBEVHTP_VERSION ${PC_LIBEVHTP_VERSION})

    set(LIBEVHTP_LIBRARIES
      ${LIBEVHTP_LIBRARIES}
      ${LIBEVHTP_LIBRARY}
    )

    set(LIBEVHTP_INCLUDE_DIRS
      ${LIBEVHTP_INCLUDE_DIR}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(LIBEVHTP
      REQUIRED_VARS
        LIBEVHTP_LIBRARIES
        LIBEVHTP_INCLUDE_DIR
      VERSION_VAR
        LIBEVHTP_VERSION
      )

    mark_as_advanced(LIBEVHTP_INCLUDE_DIR LIBEVHTP_LIBRARIES)

  endif (LIBEVHTP_FOUND)
endif(LIBEVHTP_LIBRARIES AND LIBEVHTP_INCLUDE_DIR)
