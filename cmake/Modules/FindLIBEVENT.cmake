if(LIBEVENT_LIBRARIES AND LIBEVENT_INCLUDE_DIR)
  set(LIBEVENT_FOUND TRUE)
else(LIBEVENT_LIBRARIES AND LIBEVENT_INCLUDE_DIR)
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBEVENT QUIET libevent)

  find_path(LIBEVENT_INCLUDE_DIR
    NAMES
      event.h
    HINTS
      ${PC_LIBEVENT_INCLUDEDIR}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBEVENT_LIBRARY
    NAMES
      event
    HINTS
      ${PC_LIBEVENT_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  find_library(LIBEVENT_PTHREAD_LIBRARY
    NAMES
      event_pthreads
    HINTS
      ${PC_LIBEVENT_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  find_library(LIBEVENT_OPENSSL_LIBRARY
    NAMES
      event_openssl
    HINTS
      ${PC_LIBEVENT_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (LIBEVENT_INCLUDE_DIR AND LIBEVENT_LIBRARY)
    set(LIBEVENT_FOUND TRUE)
  endif (LIBEVENT_INCLUDE_DIR AND LIBEVENT_LIBRARY)

  if (LIBEVENT_FOUND)
    #Incomplete version detection
    set(LIBEVENT_VERSION ${PC_LIBEVENT_VERSION})

    set(LIBEVENT_LIBRARIES
      ${LIBEVENT_LIBRARIES}
      ${LIBEVENT_LIBRARY}
    )

    set(LIBEVENT_INCLUDE_DIRS
      ${LIBEVENT_INCLUDE_DIR}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(LIBEVENT
      REQUIRED_VARS
        LIBEVENT_LIBRARIES
        LIBEVENT_INCLUDE_DIR
      VERSION_VAR
        LIBEVENT_VERSION
      )
    find_package_handle_standard_args(LIBEVENT_PTHREAD
      REQUIRED_VARS
        LIBEVENT_PTHREAD_LIBRARY
        LIBEVENT_INCLUDE_DIR
      VERSION_VAR
        LIBEVENT_VERSION
      )

    find_package_handle_standard_args(LIBEVENT_OPENSSL
      REQUIRED_VARS
        LIBEVENT_OPENSSL_LIBRARY
        LIBEVENT_INCLUDE_DIR
      VERSION_VAR
        LIBEVENT_VERSION
      )

    mark_as_advanced(LIBEVENT_INCLUDE_DIR LIBEVENT_LIBRARIES)
    mark_as_advanced(LIBEVENT_PTHREAD_LIBRARY)
    mark_as_advanced(LIBEVENT_OPENSSL_LIBRARY)

  endif (LIBEVENT_FOUND)
endif(LIBEVENT_LIBRARIES AND LIBEVENT_INCLUDE_DIR)
