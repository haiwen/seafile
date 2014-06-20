if( WIN32 AND NOT CYGWIN )
  # We consider Cygwin as another Unix
  set(PURE_WINDOWS 1)
endif()

include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckIncludeFileCXX)
include(CheckLibraryExists)
include(CheckSymbolExists)
include(CheckFunctionExists)
include(CheckCXXSourceCompiles)
include(TestBigEndian)

if( UNIX AND NOT BEOS )
  # Used by check_symbol_exists:
  set(CMAKE_REQUIRED_LIBRARIES m)
endif()

# Helper macros and functions
macro(add_cxx_include result files)
  set(${result} "")
  foreach (file_name ${files})
     set(${result} "${${result}}#include<${file_name}>\n")
  endforeach()
endmacro(add_cxx_include files result)

function(check_type_exists type files variable)
  add_cxx_include(includes "${files}")
  CHECK_CXX_SOURCE_COMPILES("
    ${includes} ${type} typeVar;
    int main() {
        return 0;
    }
    " ${variable})
endfunction()

# include checks
check_include_files("stdlib.h;stdarg.h;string.h;float.h" STDC_HEADERS)
check_include_file(dlfcn.h HAVE_DLFCN_H)
check_include_file(memory.h HAVE_MEMORY_H)
check_include_file(stdint.h HAVE_STDINT_H)
check_include_file(stdlib.h HAVE_STDLIB_H)
check_include_file(string.h HAVE_STRING_H)
check_include_file(strings.h HAVE_STRINGS_H)
check_include_file(sys/stat.h HAVE_SYS_STAT_H)
check_include_file(sys/types.h HAVE_SYS_TYPES_H)
check_include_file(unistd.h HAVE_UNISTD_H)
if( NOT PURE_WINDOWS )
  check_include_file(pthread.h HAVE_PTHREAD_H)
endif()

# library checks
if( NOT PURE_WINDOWS )
  check_library_exists(pthread pthread_create "" HAVE_LIBPTHREAD)
  if (HAVE_LIBPTHREAD)
    check_library_exists(pthread pthread_getspecific "" HAVE_PTHREAD_GETSPECIFIC)
    check_library_exists(pthread pthread_rwlock_init "" HAVE_PTHREAD_RWLOCK_INIT)
    check_library_exists(pthread pthread_mutex_lock "" HAVE_PTHREAD_MUTEX_LOCK)
  else()
    # this could be Android
    check_library_exists(c pthread_create "" PTHREAD_IN_LIBC)
    if (PTHREAD_IN_LIBC)
      check_library_exists(c pthread_getspecific "" HAVE_PTHREAD_GETSPECIFIC)
      check_library_exists(c pthread_rwlock_init "" HAVE_PTHREAD_RWLOCK_INIT)
      check_library_exists(c pthread_mutex_lock "" HAVE_PTHREAD_MUTEX_LOCK)
    endif()
  endif()
  check_library_exists(dl dlopen "" HAVE_LIBDL)
  check_library_exists(rt clock_gettime "" HAVE_LIBRT)
  check_library_exists(edit el_init "" HAVE_LIBEDIT)
endif()

set(headers "sys/types.h")

if (HAVE_INTTYPES_H)
  set(headers ${headers} "inttypes.h")
endif()

if (HAVE_STDINT_H)
  set(headers ${headers} "stdint.h")
endif()

check_type_exists(int64_t "${headers}" HAVE_INT64_T)
check_type_exists(uint64_t "${headers}" HAVE_UINT64_T)
check_type_exists(u_int64_t "${headers}" HAVE_U_INT64_T)

if( SEAFILE_ENABLE_PIC )
  set(ENABLE_PIC 1)
else()
  set(ENABLE_PIC 0)
endif()

if( MINGW )
  set(HAVE_LIBIMAGEHLP 1)
  set(HAVE_LIBPSAPI 1)
  set(HAVE_LIBSHELL32 1)
  # TODO: Check existence of libraries.
  #   include(CheckLibraryExists)
  #   CHECK_LIBRARY_EXISTS(imagehlp ??? . HAVE_LIBIMAGEHLP)
endif( MINGW )

if( MSVC )
  set(SHLIBEXT ".lib")
  set(stricmp "_stricmp")
  set(strdup "_strdup")
endif( MSVC )

if( PURE_WINDOWS )
  CHECK_CXX_SOURCE_COMPILES("
    #include <windows.h>
    #include <imagehlp.h>
    extern \"C\" void foo(PENUMLOADED_MODULES_CALLBACK);
    extern \"C\" void foo(BOOL(CALLBACK*)(PCSTR,ULONG_PTR,ULONG,PVOID));
    int main(){return 0;}"
    HAVE_ELMCB_PCSTR)
  if( HAVE_ELMCB_PCSTR )
    set(WIN32_ELMCB_PCSTR "PCSTR")
  else()
    set(WIN32_ELMCB_PCSTR "PSTR")
  endif()
endif( PURE_WINDOWS )

include(CheckTypeSize)
if("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")
  set(_FILE_OFFSET_BITS 64)
endif("${CMAKE_SYSTEM_NAME}" MATCHES "Linux")

set(SEAFILE_PREFIX ${CMAKE_INSTALL_PREFIX})

if(PURE_WINDOWS)
  # We consider Cygwin as another Unix
  add_definitions(-DWIN32)
  add_compile_options(-Wl,--subsystem,windows -Wl,--entry,_mainCRTStartup)
endif()
if(APPLE)
  add_definitions(-DMACOS)
endif(APPLE)
