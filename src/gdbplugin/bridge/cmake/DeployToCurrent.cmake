# Copies SRC_SO and/or SRC_DBG and/or SRC_PYS (list of .py files) into CURRENT_DIR if CURRENT_DIR exists.

if(NOT DEFINED CURRENT_DIR)
  message(FATAL_ERROR "CURRENT_DIR not set")
endif()

if(EXISTS "${CURRENT_DIR}")
  # Resolve real paths for comparison to avoid redundant copies when 'current' points to the same directory
  get_filename_component(_CURRENT_REAL "${CURRENT_DIR}" REALPATH)

  set(_SRC_DIR "")
  if(DEFINED SRC_SO)
    get_filename_component(_SRC_DIR "${SRC_SO}" DIRECTORY)
  elseif(DEFINED SRC_DBG)
    get_filename_component(_SRC_DIR "${SRC_DBG}" DIRECTORY)
  elseif(DEFINED SRC_PYS)
    # Take directory from the first python file in the list
    list(LENGTH SRC_PYS _pysz)
    if(_pysz GREATER 0)
      list(GET SRC_PYS 0 _first_py)
      get_filename_component(_SRC_DIR "${_first_py}" DIRECTORY)
    endif()
  endif()

  if(_SRC_DIR)
    get_filename_component(_SRC_REAL "${_SRC_DIR}" REALPATH)
  endif()

  # If source dir and 'current' resolve to same location, skip to prevent double-copy
  if(DEFINED _SRC_REAL AND _SRC_REAL STREQUAL _CURRENT_REAL)
    # no-op
  else()
    if(DEFINED SRC_SO AND EXISTS "${SRC_SO}")
      execute_process(COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${SRC_SO}" "${CURRENT_DIR}/")
    endif()
    if(DEFINED SRC_DBG AND EXISTS "${SRC_DBG}")
      execute_process(COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${SRC_DBG}" "${CURRENT_DIR}/")
    endif()
    if(DEFINED SRC_PYS)
      foreach(_py ${SRC_PYS})
        if(EXISTS "${_py}")
          execute_process(COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${_py}" "${CURRENT_DIR}/")
        endif()
      endforeach()
    endif()
  endif()
endif()
