if(SearpcCodegen_EXECUTABLE)
  set(SearpcCodegen_FOUND TRUE)
else(SearpcCodegen_EXECUTABLE)
  find_program(SearpcCodegen_EXECUTABLE
    NAMES searpc-codegen.py searpc-codegen
    HINTS ${LIBSEARPC_INCLUDE_DIR}/../bin ${LIBSEARPC_INCLUDE_DIR}/../lib
    DOC "Path to searpc-codegen executable"
    )

  # Handle REQUIRED and QUIET arguments
  # this will also set SearpcCodegen_FOUND to true if SearpcCodegen_EXECUTABLE exists
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(SearpcCodegen DEFAULT_MSG SearpcCodegen_EXECUTABLE)
endif(SearpcCodegen_EXECUTABLE)
