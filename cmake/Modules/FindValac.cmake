if(Valac_EXECUTABLE)
  set(Valac_FOUND TRUE)
else(Valac_EXECUTABLE)
  find_program(Valac_EXECUTABLE
    NAMES valac
    DOC "Path to valac executable"
    )

  # Handle REQUIRED and QUIET arguments
  # this will also set Valac_FOUND to true if Valac_EXECUTABLE exists
  include(FindPackageHandleStandardArgs)
  find_package_handle_standard_args(Valac DEFAULT_MSG Valac_EXECUTABLE)
endif(Valac_EXECUTABLE)
