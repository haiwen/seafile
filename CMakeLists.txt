# CMake build script for the seafile project
#
# Building (out of source build):
# > mkdir build && cd build
# > cmake .. [-DSETTINGS=VALUE]
# > cmake --build .
#
# Install:
# > cmake --build .
if(EXISTS CMakeLists.txt)
  message(FATAL_ERROR
    "Looks like you are trying to run cmake from the base source directory.\n"
    "** RUNNING CMAKE FROM THE BASE DIRECTORY WILL NOT WORK **\n"
    "To Fix:\n"
    " 1. Remove the CMakeCache.txt file in this directory. ex: rm CMakeCache.txt\n"
    " 2. Create a build directory from here. ex: mkdir build\n"
    " 3. cd into that directory. ex: cd build\n"
    " 4. Run cmake from the build directory. ex: cmake ..\n"
    " 5. Run make from the build directory. ex: make\n"
    "Full paste-able example:\n"
    "( rm -f CMakeCache.txt; mkdir build; cd build; cmake ..; make )\n"
    )
endif()
cmake_minimum_required(VERSION 2.8)

# Add path for custom modules
set(CMAKE_MODULE_PATH
  ${CMAKE_MODULE_PATH}
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
  "${CMAKE_SOURCE_DIR}/cmake/Modules/"
  )

project(seafile)

set(SEAFILE_VERSION_MAJOR 3)
set(SEAFILE_VERSION_MINOR 0)
set(SEAFILE_VERSION_PATCH 5)
set(SEAFILE_VERSION_STRING "${SEAFILE_VERSION_MAJOR}.${SEAFILE_VERSION_MINOR}.${SEAFILE_VERSION_PATCH}")

if (NOT PACKAGE_VERSION)
  set(PACKAGE_VERSION "${SEAFILE_VERSION_STRING}")
endif()
add_definitions(-DPACKAGE_VERSION=\"${PACKAGE_VERSION}\")

set(PACKAGE_NAME seafile)
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
set(PACKAGE_BUGREPORT "freeplant@gmail.com")
set(PACKAGE_URL "http://seafile.com")

set(BUG_REPORT_EMAIL "${PACKAGE_BUGREPORT}" CACHE STRING
  "Default Email where bug reports are to be submitted.")
set(BUG_REPORT_URL "https://github.com/haiwen/seafile/issues" CACHE STRING
  "Default Url where bug reports are to be submitted.")

# Configure CPack
set(CPACK_PACKAGE_NAME ${PACKAGE_NAME})
set(CPACK_PACKAGE_INSTALL_DIRECTORY "seafile")
set(CPACK_PACKAGE_VENDOR "Haiwen Inc.")
set(CPACK_PACKAGE_VERSION_MAJOR ${SEAFILE_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${SEAFILE_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${SEAFILE_VERSION_PATCH})
set(CPACK_PACKAGE_VERSION ${PACKAGE_VERSION})
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENCE.txt")

set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Lingtao Pan <freeplant@gmail.com>")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "http://www.seafile.com")
set(CPACK_DEBIAN_PACKAGE_DEPENDS
  "libccnet0 (>=3.0) libsearpc1 (>=1.0) libevent-2.0-5 (>=2.0) libsqlite3-0 (>=3.7.0) libzdb9 (>=2.10) libglib2.0 (>= 2.28.0) libjansson4 (>=2.1) zlib1g (>=1.2.0)"
  )
set(CPACK_RPM_PACKAGE_LICENSE "GPLv3")
set(CPACK_RPM_PACKAGE_URL "http://www.seafile.com")
set(CPACK_RPM_PACKAGE_REQUIRES
  "libccnet libsearpc libevent sqlite libzdb glib2 jansson zlib"
  )
include(CPack)

# SET UP DEFAULT CMAKE_BUILD_TYPE
if( NOT CMAKE_CONFIGURATION_TYPES )
  # Build Debug by default
  if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
  endif ()
else()
  # Using a multi-configuration generator eg MSVC or Xcode
  # that uses CMAKE_CONFIGURATION_TYPES and not CMAKE_BUILD_TYPE
endif()

message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

option(USE_BUNDLED_ZLIB
  "Enable building of the bundled zlib" OFF)
option(USE_BUNDLED_LIBARCHIVE
  "Enable building of the bundled libarchive" OFF)
option(USE_BUNDLED_LIBEVHTP
  "Enable building of the bundled libevhtp" OFF)
option(SEAFILE_BUILD_APP
  "Build seafile app." ON)
option(SEAFILE_ENABLE_CLIENT
  "Build seafile client." ON)
option(SEAFILE_ENABLE_SERVER
  "Build seafile server." OFF)
option(SEAFILE_BUILD_TESTS
  "Build seafile tests." OFF)
option(SEAFILE_BUILD_PYTHON
  "Build seafile python binding." ON)
option(SEAFILE_BUILD_FUSE
  "Build seafile fuse binding." OFF)
option(SEAFILE_BUILD_STATIC
  "Build static library" OFF)

if(SEAFILE_BUILD_STATIC)
  set(SEAFILE_LIBTYPE STATIC)
else()
  set(SEAFILE_LIBTYPE SHARED)
endif()

# Find Library Dependencies
find_package(Threads REQUIRED)
find_package(GLIB2 2.26.0 REQUIRED)
find_package(JANSSON 2.2.1 REQUIRED)
find_package(OpenSSL 0.9.8 REQUIRED)
find_package(SQLITE3 3.7.0 REQUIRED)
find_package(SearpcCodegen REQUIRED)
find_package(Valac REQUIRED)
find_package(UUID REQUIRED)
find_package(LIBEVENT 2.0 REQUIRED)
find_package(LIBZDB 2.10 REQUIRED)
include(ExternalProject)

if(NOT USE_BUNDLED_ZLIB)
  find_package(ZLIB 1.2.0 REQUIRED)
  if(NOT ZLIB_FOUND)
    message(STATUS "Couldn't find system zlib")
    set(USE_BUNDLED_ZLIB ON)
  endif()
endif(NOT USE_BUNDLED_ZLIB)
if(USE_BUNDLED_ZLIB)
  set(ZLIB_PREFIX "${PROJECT_BINARY_DIR}/zlib-prefix")
  set(ZLIB_SOURCE_DIR "${ZLIB_PREFIX}/src/zlib")
  message(STATUS "Using bundled zlib in '${ZLIB_PREFIX}'")
  set(ZLIB_INCLUDE_DIR "${ZLIB_SOURCE_DIR}")
  if(NOT WIN32)
    set(ZLIB_LIBRARIES "${ZLIB_SOURCE_DIR}/libz.a")
    ExternalProject_Add(zlib
      PREFIX ${ZLIB_PREFIX}
      URL "http://zlib.net/zlib-1.2.8.tar.gz"
      URL_MD5 "44d667c142d7cda120332623eab69f40"
      CONFIGURE_COMMAND "./configure"
      BUILD_COMMAND ${CMD_MAKE}
      BUILD_IN_SOURCE 1
      INSTALL_COMMAND "")
  else()
    set(ZLIB_LIBRARIES "${ZLIB_SOURCE_DIR}/zdll.lib")
    ExternalProject_Add(zlib
      PREFIX ${ZLIB_PREFIX}
      URL "http://zlib.net/zlib-1.2.8.tar.gz"
      URL_MD5 "44d667c142d7cda120332623eab69f40"
      CONFIGURE_COMMAND ""
      BUILD_COMMAND nmake -f win32/Makefile.msc
      BUILD_IN_SOURCE 1
      INSTALL_COMMAND "")
  endif()
endif(USE_BUNDLED_ZLIB)

if(NOT LIBSEARPC_FOUND)
  if(NOT EXISTS "${CMAKE_SOURCE_DIR}/deps/libsearpc")
    set(LIBSEARPC_FOUND false)
    find_package(LIBSEARPC 1.0 REQUIRED)
  else()
    set(LIBSEARPC_FOUND true)
    add_subdirectory(deps/libsearpc)
  endif()
endif(NOT LIBSEARPC_FOUND)

if(NOT LIBCCNET_FOUND)
  if(NOT EXISTS "${CMAKE_SOURCE_DIR}/deps/ccnet")
    set(LIBCCNET_FOUND false)
    find_package(LIBCCNET 1.0 REQUIRED)
  else()
    set(LIBCCNET_FOUND true)
    add_subdirectory(deps/ccnet)
  endif()
endif(NOT LIBCCNET_FOUND)

# System Check
# Borrowed from llvm
include(config-ix)

# Verify that we can find a Python 2 interpreter. Python 3 is unsupported.
set(Python_ADDITIONAL_VERSIONS 2.7 2.6 2.5)
include(FindPythonInterp)
if(NOT PYTHONINTERP_FOUND)
  message(FATAL_ERROR
"Unable to find Python interpreter, required for searpc-codegen and pysearpc.
Please install Python or specify the PYTHON_EXECUTABLE CMake variable.")
endif()

# CONFIG.H
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/config.h @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

# INSTALLATION PATHS
set(BIN_INSTALL_DIR bin CACHE PATH "Where to install binaries to.")
set(LIB_INSTALL_DIR lib CACHE PATH "Where to install libraries to.")
set(INCLUDE_INSTALL_DIR include CACHE PATH "Where to install headers to.")

# INSTALLATION header files
set(SRC_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)
set(SEAFILE_INCLUDE_DIR ${SRC_INCLUDE_DIR})
file(GLOB SRC_INCLUDE_H include/*.h)
install(FILES ${SRC_INCLUDE_H}
  DESTINATION ${INCLUDE_INSTALL_DIR}/seafile
  )
include_directories(${SRC_INCLUDE_DIR})
set(SRC_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib)
set(SRC_COMMON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/common)

# LIB
file(GLOB SRC_LIB_H ${SRC_LIB_DIR}/*.h)
add_subdirectory(lib)
set(LIBSEARPC_INCLUDE_DIR ${SRC_INCLUDE_DIR})
set(LIBSEARPC_INCLUDE_DIRS ${LIBSEARPC_INCLUDE_DIR})
set(LIBSEARPC_LIBRARIES libseafile)

# COMMON
file(GLOB SRC_COMMON_H ${SRC_COMMON_DIR}/*.h)
add_subdirectory(common)

# APP
if(SEAFILE_BUILD_APP)
  set(SRC_APP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/app)
  add_subdirectory(app)
ENDIF(SEAFILE_BUILD_APP)

# DAEMON
if(SEAFILE_ENABLE_CLIENT)
  set(SRC_DAEMON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/daemon)
  file(GLOB SRC_DAEMON_H ${SRC_DAEMON_DIR}/*.h)
  add_subdirectory(daemon)
endif(SEAFILE_ENABLE_CLIENT)

if(SEAFILE_ENABLE_SERVER)
  # SERVER
  set(SRC_SERVER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/server)
  file(GLOB SRC_SERVER_H ${SRC_SERVER_DIR}/*.h)
  add_subdirectory(server)

  # FILESERVER 0
  if(NOT USE_BUNDLED_LIBARCHIVE)
    find_package(LIBARCHIVE 1.0 REQUIRED)
    if(NOT LIBARCHIVE_FOUND)
      message(STATUS "Couldn't find system libarchive")
      set(USE_BUNDLED_LIBARCHIVE ON)
    endif()
  endif(NOT USE_BUNDLED_LIBARCHIVE)
  if(USE_BUNDLED_LIBARCHIVE)
    set(LIBARCHIVE_PREFIX "${PROJECT_BINARY_DIR}/libarchive-prefix")
    set(LIBARCHIVE_SOURCE_DIR "${LIBARCHIVE_PREFIX}/src/libarchive")
    set(LIBARCHIVE_BINARY_DIR "${LIBARCHIVE_PREFIX}/src/libarchive-build")
    message(STATUS "Using bundled LIBARCHIVE in '${LIBARCHIVE_SOURCE_DIR}'")
    set(LIBARCHIVE_INCLUDE_DIR "${LIBARCHIVE_SOURCE_DIR}/libarchive")
    set(LIBARCHIVE_LIBRARIES "${LIBARCHIVE_BINARY_DIR}/libarchive/libarchive.a")
    ExternalProject_Add(libarchive
      PREFIX ${LIBARCHIVE_PREFIX}
      URL "http://libarchive.org/downloads/libarchive-3.1.2.tar.gz"
      URL_MD5 "efad5a503f66329bb9d2f4308b5de98a"
      CMAKE_ARGS "-DENABLE_TEST=off"
      BUILD_COMMAND make
      BUILD_IN_SOURCE 0
      INSTALL_COMMAND "")
  endif(USE_BUNDLED_LIBARCHIVE)

  # FILESERVER 1
  if(NOT USE_BUNDLED_LIBEVHTP)
    find_package(LIBEVHTP 1.0 REQUIRED)
    if(NOT LIBEVHTP_FOUND)
      message(STATUS "Couldn't find system libevhtp")
      set(USE_BUNDLED_LIBEVHTP ON)
    endif()
  endif(NOT USE_BUNDLED_LIBEVHTP)
  if(USE_BUNDLED_LIBEVHTP)
    set(LIBEVHTP_PREFIX "${PROJECT_BINARY_DIR}/libevhtp-prefix")
    set(LIBEVHTP_SOURCE_DIR "${LIBEVHTP_PREFIX}/src/libevhtp")
    set(LIBEVHTP_BINARY_DIR "${LIBEVHTP_PREFIX}/src/libevhtp-build")
    message(STATUS "Using bundled LIBEVHTP in '${LIBEVHTP_SOURCE_DIR}'")
    set(LIBEVHTP_INCLUDE_DIR
      "${LIBEVHTP_SOURCE_DIR}" "${LIBEVHTP_SOURCE_DIR}/evthr"
      "${LIBEVHTP_SOURCE_DIR}/htparse" "${LIBEVHTP_SOURCE_DIR}/oniguruma"
      "${LIBEVHTP_BINARY_DIR}" "${LIBEVHTP_BINARY_DIR}/compat"
      )
    set(LIBEVHTP_LIBRARIES "${LIBEVHTP_BINARY_DIR}/libevhtp.a")
    ExternalProject_Add(libevhtp
      PREFIX ${LIBEVHTP_PREFIX}
      URL "https://github.com/ellzey/libevhtp/archive/1.2.9.tar.gz"
      URL_MD5 "428a8d179fcc0cadedd914ed6456e08f"
      CMAKE_ARGS "-DEVHTP_BUILD_SHARED=off"
      BUILD_COMMAND make
      BUILD_IN_SOURCE 0
      INSTALL_COMMAND "")
  endif(USE_BUNDLED_LIBEVHTP)

  # FILESERVER 2
  set(SRC_FILESERVER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fileserver)
  file(GLOB SRC_FILESERVER_H ${SRC_FILESERVER_DIR}/*.h)
  add_subdirectory(fileserver)

  # TOOLS
  set(SRC_TOOLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tools)
  add_subdirectory(tools)
endif(SEAFILE_ENABLE_SERVER)


# PYTHON BINDING
if(SEAFILE_BUILD_PYTHON)
  include(FindPythonLibs)
  if(NOT PYTHONLIBS_FOUND OR NOT PYTHON_EXECUTABLE)
    message(SEND_ERROR "You need Python to build the python bindings")
  else()
    set(SRC_PYTHON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/python)
    add_subdirectory(python)
  endif()
endif(SEAFILE_BUILD_PYTHON)

# FUSE BINDING
if(SEAFILE_BUILD_FUSE)
  set(SRC_FUSE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/fuse)
  file(GLOB SRC_FUSE_H ${SRC_FUSE_DIR}/*.h)
  add_subdirectory(fuse)
endif(SEAFILE_BUILD_FUSE)

# Unit Tests
if(SEAFILE_BUILD_TESTS)
  set(SRC_TESTS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tests)
  enable_testing()
  add_subdirectory(tests)
endif(SEAFILE_BUILD_TESTS)
