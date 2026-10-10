# Build one pinned static yaml-cpp provider for all consumers.
include_guard(GLOBAL)
include(FetchContent)
include(CheckIPOSupported)
include(CheckCXXCompilerFlag)
set(_SCE_YAML_HELPER_DIR "${CMAKE_CURRENT_LIST_DIR}")

function(_sce_prepare_bundled_yaml_cpp)
  if(TARGET yaml-cpp OR TARGET yaml-cpp::yaml-cpp)
    message(FATAL_ERROR "A foreign yaml-cpp target already exists; do not mix providers")
  endif()
  # Preserve the runtime source version shipped by v1.9.13 on each platform.
  # Windows MSYS2 used unpatched upstream 0.9.0; the Linux images used 0.8.0.
  if(WIN32)
    set(_version "0.9.0")
    set(_revision "56e3bb550c91fd7005566f19c079cb7a503223cf")
    set(_archive_sha256 "b8e01ea231a96d6984b0795f225281d1e9989f40ccd589568a051450f41e9151")
  else()
    set(_version "0.8.0")
    set(_revision "f7320141120f720aecc4c32be25586e7da9eb978")
    set(_archive_sha256 "2fd3bf695ccc056835a70dd6d3046312cc1004e8338b8b5c91646918a27b7ef6")
  endif()
  message(STATUS "yaml-cpp: preserving platform source version ${_version} (${_revision})")
  set(_patch_script "${_SCE_YAML_HELPER_DIR}/patch_yaml_cpp.cmake")

  # The explicit Populate form works on CMake 3.13 and avoids CMP0169's
  # deprecated single-argument form. Its offline override is handled here.
  if(DEFINED FETCHCONTENT_SOURCE_DIR_SCE_YAML_CPP AND
     NOT "${FETCHCONTENT_SOURCE_DIR_SCE_YAML_CPP}" STREQUAL "")
    get_filename_component(_source "${FETCHCONTENT_SOURCE_DIR_SCE_YAML_CPP}" ABSOLUTE)
    set(_binary "${CMAKE_BINARY_DIR}/_deps/sce_yaml_cpp-build")
    message(STATUS "yaml-cpp: explicit offline source override; critical source hash guards still apply")
  else()
    FetchContent_Populate(sce_yaml_cpp
      URL "https://codeload.github.com/jbeder/yaml-cpp/tar.gz/${_revision}"
      URL_HASH "SHA256=${_archive_sha256}"
      TLS_VERIFY TRUE
      SOURCE_DIR "${CMAKE_BINARY_DIR}/_deps/sce_yaml_cpp-src"
      BINARY_DIR "${CMAKE_BINARY_DIR}/_deps/sce_yaml_cpp-build"
      SUBBUILD_DIR "${CMAKE_BINARY_DIR}/_deps/sce_yaml_cpp-subbuild")
    set(_source "${sce_yaml_cpp_SOURCE_DIR}")
    set(_binary "${sce_yaml_cpp_BINARY_DIR}")
  endif()
  execute_process(COMMAND "${CMAKE_COMMAND}"
    "-DSCE_YAML_CPP_SOURCE_DIR:PATH=${_source}"
    "-DSCE_YAML_CPP_VERSION:STRING=${_version}" -P "${_patch_script}"
    RESULT_VARIABLE _patch_result)
  if(NOT _patch_result EQUAL 0)
    message(FATAL_ERROR "Pinned yaml-cpp source verification/patch failed")
  endif()

  # Scope compatibility settings to this function and dependency subdirectory.
  # yaml-cpp 0.8's old minimum otherwise fails with CMake 4 or ignores IPO.
  if(CMAKE_VERSION VERSION_GREATER_EQUAL "4.0" AND
     (NOT DEFINED CMAKE_POLICY_VERSION_MINIMUM OR CMAKE_POLICY_VERSION_MINIMUM VERSION_LESS "3.5"))
    set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
  endif()
  set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
  set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
  set(YAML_BUILD_SHARED_LIBS OFF CACHE BOOL "Use the pinned static dependency" FORCE)
  set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "Do not build yaml-cpp tools" FORCE)
  set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "Use the application's existing suite" FORCE)
  set(YAML_CPP_FORMAT_SOURCE OFF CACHE BOOL "Preserve reviewed source bytes" FORCE)
  set(YAML_CPP_INSTALL OFF CACHE BOOL "Do not add dependency install rules" FORCE)
  add_subdirectory("${_source}" "${_binary}" EXCLUDE_FROM_ALL)
  get_target_property(_kind yaml-cpp TYPE)
  if(NOT _kind STREQUAL "STATIC_LIBRARY")
    message(FATAL_ERROR "Pinned yaml-cpp target must be static")
  endif()
  set_property(TARGET yaml-cpp PROPERTY INTERPROCEDURAL_OPTIMIZATION FALSE)
  set(_ipo_configs Debug Release RelWithDebInfo MinSizeRel
      ${CMAKE_BUILD_TYPE} ${CMAKE_CONFIGURATION_TYPES})
  get_cmake_property(_cmake_variables VARIABLES)
  foreach(_variable IN LISTS _cmake_variables)
    if(_variable MATCHES "^CMAKE_INTERPROCEDURAL_OPTIMIZATION_(.+)$")
      list(APPEND _ipo_configs "${CMAKE_MATCH_1}")
    endif()
  endforeach()
  list(REMOVE_DUPLICATES _ipo_configs)
  foreach(_config IN LISTS _ipo_configs)
    string(TOUPPER "${_config}" _config)
    set_property(TARGET yaml-cpp PROPERTY
        "INTERPROCEDURAL_OPTIMIZATION_${_config}" FALSE)
  endforeach()
  string(TOUPPER "${CMAKE_BUILD_TYPE}" _build_type)
  string(TOUPPER "${CMAKE_CONFIGURATION_TYPES}" _configuration_types)
  set(_release_requested FALSE)
  if(_build_type STREQUAL "RELEASE" OR _configuration_types MATCHES "(^|;)RELEASE(;|$)")
    set(_release_requested TRUE)
  endif()
  if(NOT ENABLE_SANITIZERS AND _release_requested)
    check_ipo_supported(RESULT _ipo_ok OUTPUT _ipo_error LANGUAGES CXX)
    if(_ipo_ok)
      set_property(TARGET yaml-cpp PROPERTY INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE)
      message(STATUS "yaml-cpp: Release IPO enabled")
    else()
      message(STATUS "yaml-cpp: Release IPO unavailable; keeping it disabled: ${_ipo_error}")
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
      target_compile_options(yaml-cpp PRIVATE "$<$<CONFIG:Release>:-O3>")
      check_cxx_compiler_flag("-fno-semantic-interposition" _sce_yaml_fno_interposition)
      if(_sce_yaml_fno_interposition)
        target_compile_options(yaml-cpp PRIVATE "$<$<CONFIG:Release>:-fno-semantic-interposition>")
      endif()
    endif()
  endif()
  # Preserve the existing library-private Linux hardening without touching
  # application flags or adding _GLIBCXX_ASSERTIONS.
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang|AppleClang)$")
    check_cxx_compiler_flag("-fstack-protector-strong" _sce_yaml_stack_protector)
    if(_sce_yaml_stack_protector)
      target_compile_options(yaml-cpp PRIVATE -fstack-protector-strong)
    endif()
    # Evaluate the effective configuration in the preprocessor, preserving
    # explicit caller values and avoiding config-specific generator-expression
    # parsing. file(GENERATE) leaves unchanged content and its mtime intact.
    set(_hardening_header "${_binary}/sce_yaml_cpp_hardening.h")
    file(GENERATE OUTPUT "${_hardening_header}" CONTENT [==[
#if !defined(_FORTIFY_SOURCE) && defined(__OPTIMIZE__) && __OPTIMIZE__ > 0
#define _FORTIFY_SOURCE 2
#endif
]==])
    target_compile_options(yaml-cpp PRIVATE
        "SHELL:-include \"${_hardening_header}\"")
  endif()
  get_target_property(_yaml_public_includes yaml-cpp INTERFACE_INCLUDE_DIRECTORIES)
  set_property(TARGET yaml-cpp PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${_yaml_public_includes}")
  # Public include directories and YAML_CPP_STATIC_DEFINE already come from
  # upstream's target interface, including for MinGW and test consumers.
  set(SCE_YAML_CPP_VERSION "${_version}" CACHE INTERNAL "Pinned yaml-cpp platform version" FORCE)
  set(SCE_YAML_CPP_REVISION "${_revision}" CACHE INTERNAL "Pinned yaml-cpp platform revision" FORCE)
  set(SCE_YAML_CPP_SOURCE_DIR "${_source}" CACHE INTERNAL "Pinned yaml-cpp source" FORCE)
  set(SCE_YAML_CPP_BINARY_DIR "${_binary}" CACHE INTERNAL "Pinned yaml-cpp build" FORCE)
endfunction()
_sce_prepare_bundled_yaml_cpp()
