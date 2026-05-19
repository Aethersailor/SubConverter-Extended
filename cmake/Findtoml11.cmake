find_path(TOML11_INCLUDE_DIR
  NAMES toml.hpp
  PATHS "${CMAKE_SOURCE_DIR}/include"
)

set(TOML11_INCLUDE_DIRS "${TOML11_INCLUDE_DIR}")
set(toml11_INCLUDE_DIRS "${TOML11_INCLUDE_DIRS}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(toml11 DEFAULT_MSG TOML11_INCLUDE_DIR)

if(toml11_FOUND AND NOT TARGET toml11::toml11)
  add_library(toml11::toml11 INTERFACE IMPORTED)
  set_target_properties(toml11::toml11 PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${TOML11_INCLUDE_DIR}"
  )
endif()

mark_as_advanced(TOML11_INCLUDE_DIR)
