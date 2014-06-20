if(LIBZDB_LIBRARIES AND LIBZDB_INCLUDE_DIR)
  set(LIBZDB_FOUND TRUE)
else(LIBZDB_LIBRARIES AND LIBZDB_INCLUDE_DIR)
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBZDB QUIET zdb)

  find_path(LIBZDB_INCLUDE_DIR
    NAMES
      zdb.h
    HINTS
      ${PC_LIBZDB_INCLUDEDIR}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
    PATH_SUFFIXES
      zdb
  )

  find_library(LIBZDB_LIBRARY
    NAMES
      zdb
    HINTS
      ${PC_LIBZDB_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (LIBZDB_INCLUDE_DIR AND LIBZDB_LIBRARY)
    set(LIBZDB_FOUND TRUE)
  endif (LIBZDB_INCLUDE_DIR AND LIBZDB_LIBRARY)

  if (LIBZDB_FOUND)
    #Incomplete version detection
    set(LIBZDB_VERSION ${PC_LIBZDB_VERSION})

    set(LIBZDB_LIBRARIES
      ${LIBZDB_LIBRARIES}
      ${LIBZDB_LIBRARY}
    )

    set(LIBZDB_INCLUDE_DIRS
      ${LIBZDB_INCLUDE_DIR}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(LIBZDB
      REQUIRED_VARS
        LIBZDB_LIBRARIES
        LIBZDB_INCLUDE_DIR
      VERSION_VAR
        LIBZDB_VERSION
      )

    mark_as_advanced(LIBZDB_INCLUDE_DIR LIBZDB_LIBRARIES)

  endif (LIBZDB_FOUND)
endif(LIBZDB_LIBRARIES AND LIBZDB_INCLUDE_DIR)
