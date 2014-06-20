if(LIBARCHIVE_LIBRARIES AND LIBARCHIVE_INCLUDE_DIR)
  set(LIBARCHIVE_FOUND TRUE)
else(LIBARCHIVE_LIBRARIES AND LIBARCHIVE_INCLUDE_DIR)
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBARCHIVE QUIET libarchive)

  find_path(LIBARCHIVE_INCLUDE_DIR
    NAMES
      archive.h
    HINTS
      ${PC_LIBARCHIVE_INCLUDEDIR}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(LIBARCHIVE_LIBRARY
    NAMES
      archive
    HINTS
      ${PC_LIBARCHIVE_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (LIBARCHIVE_INCLUDE_DIR AND LIBARCHIVE_LIBRARY)
    set(LIBARCHIVE_FOUND TRUE)
  endif (LIBARCHIVE_INCLUDE_DIR AND LIBARCHIVE_LIBRARY)

  if (LIBARCHIVE_FOUND)
    #Incomplete version detection
    set(LIBARCHIVE_VERSION ${PC_LIBARCHIVE_VERSION})

    set(LIBARCHIVE_LIBRARIES
      ${LIBARCHIVE_LIBRARIES}
      ${LIBARCHIVE_LIBRARY}
    )

    set(LIBARCHIVE_INCLUDE_DIRS
      ${LIBARCHIVE_INCLUDE_DIR}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(LIBARCHIVE
      REQUIRED_VARS
        LIBARCHIVE_LIBRARIES
        LIBARCHIVE_INCLUDE_DIR
      VERSION_VAR
        LIBARCHIVE_VERSION
      )

    mark_as_advanced(LIBARCHIVE_INCLUDE_DIR LIBARCHIVE_LIBRARIES)

  endif (LIBARCHIVE_FOUND)
endif(LIBARCHIVE_LIBRARIES AND LIBARCHIVE_INCLUDE_DIR)
