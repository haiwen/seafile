################################
# Python Binding
################################

set(SETUP_PY_IN "${CMAKE_CURRENT_SOURCE_DIR}/setup.py.cmake")
set(SETUP_PY    "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
set(DEPS        "${CMAKE_CURRENT_SOURCE_DIR}/seafile/__init__.py"
                "${CMAKE_CURRENT_SOURCE_DIR}/seaserv/__init__.py"
  )
set(OUTPUT      "${CMAKE_CURRENT_BINARY_DIR}/build")

configure_file(${SETUP_PY_IN} ${SETUP_PY})

add_custom_command(
  OUTPUT ${OUTPUT}/timestamp
  COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} build
  COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}/timestamp
  DEPENDS ${DEPS}
)
add_custom_target(target ALL DEPENDS ${OUTPUT}/timestamp)
install(CODE "execute_process(COMMAND ${PYTHON_EXECUTABLE} ${SETUP_PY} -q install --prefix=${CMAKE_INSTALL_PREFIX}
          WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)")
