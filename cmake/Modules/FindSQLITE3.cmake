if(SQLITE3_LIBRARIES AND SQLITE3_INCLUDE_DIR)
  set(SQLITE3_FOUND TRUE)
else(SQLITE3_LIBRARIES AND SQLITE3_INCLUDE_DIR)
  find_package(PkgConfig)
  pkg_check_modules(PC_SQLITE3 QUIET sqlite3)

  find_path(SQLITE3_INCLUDE_DIR
    NAMES
      sqlite3.h
    HINTS
      ${PC_SQLITE3_INCLUDEDIR}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(SQLITE3_LIBRARY
    NAMES
      sqlite3
    HINTS
      ${PC_SQLITE3_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (SQLITE3_INCLUDE_DIR AND SQLITE3_LIBRARY)
    set(SQLITE3_FOUND TRUE)
  endif (SQLITE3_INCLUDE_DIR AND SQLITE3_LIBRARY)

  if (SQLITE3_FOUND)
    #Incomplete version detection
    set(SQLITE3_VERSION ${PC_SQLITE3_VERSION})

    set(SQLITE3_LIBRARIES
      ${SQLITE3_LIBRARIES}
      ${SQLITE3_LIBRARY}
    )

    set(SQLITE3_INCLUDE_DIRS
      ${SQLITE3_INCLUDE_DIR}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(SQLITE3
      REQUIRED_VARS
        SQLITE3_LIBRARIES
        SQLITE3_INCLUDE_DIR
      VERSION_VAR
        SQLITE3_VERSION
      )

    mark_as_advanced(SQLITE3_INCLUDE_DIR SQLITE3_LIBRARIES)

  endif(SQLITE3_FOUND)
endif(SQLITE3_LIBRARIES AND SQLITE3_INCLUDE_DIR)
