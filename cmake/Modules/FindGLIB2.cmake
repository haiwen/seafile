if(GLIB2_LIBRARIES AND GLIB2_INCLUDE_DIR)
  set(GLIB2_FOUND TRUE)
else(GLIB2_LIBRARIES AND GLIB2_INCLUDE_DIR)
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBGLIB2 QUIET glib-2.0)

  find_path(GLIB2_MAIN_INCLUDE_DIR
    NAMES
      glib.h
    HINTS
      ${PC_LIBGLIB2_INCLUDEDIR}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
    PATH_SUFFIXES
      glib-2.0
  )

  find_library(GLIB2_LIBRARY
    NAMES
      glib-2.0
    HINTS
      ${PC_LIBGLIB2_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
    PATH_SUFFIXES
      glib-2.0
  )

  if (GLIB2_MAIN_INCLUDE_DIR AND GLIB2_LIBRARY)
    set(GLIB2_FOUND TRUE)
  endif (GLIB2_MAIN_INCLUDE_DIR AND GLIB2_LIBRARY)

  if (GLIB2_FOUND)
    #Incomplete version detection
    set(GLIB2_VERSION ${PC_LIBGLIB2_VERSION})

    set(GLIB2_LIBRARIES
      ${GLIB2_LIBRARIES}
      ${GLIB2_LIBRARY}
      )

    get_filename_component(glib2LibDir "${GLIB2_LIBRARIES}" PATH)

    find_path(GLIB2_INTERNAL_INCLUDE_DIR
      NAMES
      glibconfig.h
      PATH_SUFFIXES
      glib-2.0/include
      HINTS
      ${PC_LibGLIB2_INCLUDEDIR} "${glib2LibDir}"
      ${CMAKE_SYSTEM_LIBRARY_PATH}
    )

    set(GLIB2_INCLUDE_DIR
      "${GLIB2_MAIN_INCLUDE_DIR}"
      "${GLIB2_INTERNAL_INCLUDE_DIR}"
      )

    set(GLIB2_INCLUDE_DIRS
      ${GLIB2_INCLUDE_DIR}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(GLIB2
      REQUIRED_VARS
        GLIB2_LIBRARIES
        GLIB2_INCLUDE_DIR
      VERSION_VAR
        GLIB2_VERSION
      )

    mark_as_advanced(GLIB2_INCLUDE_DIR GLIB2_LIBRARIES)

  endif (GLIB2_FOUND)
endif(GLIB2_LIBRARIES AND GLIB2_INCLUDE_DIR)
