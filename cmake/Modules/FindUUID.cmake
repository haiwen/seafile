if (UUID_LIBRARIES AND UUID_INCLUDE_DIR)
  set(UUID_FOUND TRUE)
else (UUID_LIBRARIES AND UUID_INCLUDE_DIR)
  find_package(PkgConfig)
  pkg_check_modules(PC_LIBUUID QUIET uuid)

  find_path(UUID_INCLUDE_DIR
    NAMES
      uuid.h
      uuid/uuid.h
    HINTS
      ${PC_LIBUUID_INCLUDEDIR}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ${CMAKE_INCLUDE_PATH}
      ${CMAKE_INSTALL_PREFIX}/include
  )

  find_library(UUID_LIBRARY
    NAMES
      uuid
    HINTS
      ${PC_LIBUUID_LIBDIR}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ${CMAKE_LIBRARY_PATH}
      ${CMAKE_INSTALL_PREFIX}/lib
  )

  if (UUID_INCLUDE_DIR AND UUID_LIBRARY)
    set(UUID_FOUND TRUE)
  endif (UUID_INCLUDE_DIR AND UUID_LIBRARY)

  if (UUID_FOUND)
    #Incomplete version detection
    set(UUID_VERSION ${PC_LIBUUID_VERSION})

    set(UUID_LIBRARIES
      ${UUID_LIBRARIES}
      ${UUID_LIBRARY}
    )

    set(UUID_INCLUDE_DIRS
      ${UUID_INCLUDE_DIR}
    )

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(UUID
      REQUIRED_VARS
        UUID_LIBRARIES
        UUID_INCLUDE_DIR
      VERSION_VAR
        UUID_VERSION
      )

    mark_as_advanced(UUID_INCLUDE_DIR UUID_LIBRARIES)

  endif (UUID_FOUND)
endif (UUID_LIBRARIES AND UUID_INCLUDE_DIR)
