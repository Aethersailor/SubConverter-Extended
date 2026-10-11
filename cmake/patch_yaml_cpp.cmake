# Exact, idempotent platform-pinned yaml-cpp scalar validation transformation.
if(NOT DEFINED SCE_YAML_CPP_SOURCE_DIR OR NOT DEFINED SCE_YAML_CPP_VERSION)
  message(FATAL_ERROR "SCE_YAML_CPP_SOURCE_DIR and SCE_YAML_CPP_VERSION are required")
endif()
if(SCE_YAML_CPP_VERSION STREQUAL "0.8.0")
  set(_cmake_expected "d0c3194e276f87e99af788a641c4c7c39f1c831b3139e9178d1e789103bb70fb")
  set(_original_hash "060c36de7147a43e46cd6df7e9460fa5ba35e76c6cb8f77b3b17f06be61565b0")
  set(_patched_hash "d8bf52ef8ec4ad0b582ff9ff9c26918125439714765b4a2d9cedf033fc99bb26")
  set(_replacement [==[  // This ASCII subset cannot contain a plain-scalar start/end indicator,
  // whitespace, comment, non-printable byte, BOM, break, tab, or ampersand.
  // Keep the null guard above and all explicit style decisions unchanged.
  const auto asciiWord = [](unsigned char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9') || ch == '_';
  };
  // Bound the extra work before fallback; long scalars enter the validation loop.
  if (str.size() <= 64 &&
      asciiWord(static_cast<unsigned char>(str.front())) &&
      std::all_of(str.begin() + 1, str.end(), [&](unsigned char ch) {
        return asciiWord(ch) || ch == '-' || ch == '.';
      })) {
    return true;
  }

  // check the start
]==])
elseif(SCE_YAML_CPP_VERSION STREQUAL "0.9.0")
  set(_cmake_expected "1b1b0b9d346f68976873e8e4f3fdd71dd6ae0ff62d47b7fd83a18a69410f8a29")
  set(_original_hash "d690f3c40fb0de5032002fa540f734335bbc4f969e5722f589842c86f5da0f51")
  set(_patched_hash "e783088c1484bfb252afd1dc179b29d7e07256bc2bb89ee8549ae995871eebb0")
  set(_replacement [==[  // This ASCII subset cannot contain a plain-scalar start/end indicator,
  // whitespace, comment, non-printable byte, BOM, break, tab, or ampersand.
  // Keep the null guard above and all explicit style decisions unchanged.
  const auto asciiWord = [](unsigned char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
           (ch >= '0' && ch <= '9') || ch == '_';
  };
  // Bound the extra work before fallback; long scalars enter the validation loop.
  if (size <= 64 &&
      asciiWord(static_cast<unsigned char>(str[0])) &&
      std::all_of(str + 1, str + size, [&](unsigned char ch) {
        return asciiWord(ch) || ch == '-' || ch == '.';
      })) {
    return true;
  }

  // check the start
]==])
else()
  message(FATAL_ERROR "Unsupported pinned yaml-cpp platform version: ${SCE_YAML_CPP_VERSION}")
endif()
set(_source "${SCE_YAML_CPP_SOURCE_DIR}/src/emitterutils.cpp")
file(READ "${SCE_YAML_CPP_SOURCE_DIR}/CMakeLists.txt" _cmake_text)
string(REPLACE "\r\n" "\n" _cmake_text "${_cmake_text}")
string(SHA256 _cmake_hash "${_cmake_text}")
if(NOT _cmake_hash STREQUAL _cmake_expected)
  message(FATAL_ERROR "yaml-cpp source is not the pinned upstream ${SCE_YAML_CPP_VERSION} CMake project")
endif()
# The leading-byte predicate relies on these exact disallowed expressions.
file(READ "${SCE_YAML_CPP_SOURCE_DIR}/src/exp.h" _exp_text)
string(REPLACE "\r\n" "\n" _exp_text "${_exp_text}")
string(SHA256 _exp_hash "${_exp_text}")
if(NOT _exp_hash STREQUAL "c3ee620cc13d02c6b1559af0551866d164ac7b82bfba0ac924386f9e47b4f403")
  message(FATAL_ERROR "yaml-cpp scalar validation expressions do not match the pinned source")
endif()
file(READ "${_source}" _original)
string(REPLACE "\r\n" "\n" _original "${_original}")
string(SHA256 _before_hash "${_original}")
if(_before_hash STREQUAL _patched_hash)
  file(SHA256 "${_source}" _raw_hash)
  if(NOT _raw_hash STREQUAL _patched_hash)
    file(WRITE "${_source}" "${_original}")
  endif()
  return()
endif()
if(NOT _before_hash STREQUAL _original_hash)
  message(FATAL_ERROR "yaml-cpp emitter source hash is neither the reviewed original nor scalar validation result")
endif()
set(_needle [==[  // check the start
]==])
string(REPLACE "\r\n" "\n" _needle "${_needle}")
string(REPLACE "\r\n" "\n" _replacement "${_replacement}")
string(REPLACE "${_needle}" "${_replacement}" _patched "${_original}")
set(_loop_needle [==[  while (buffer) {
    if (disallowed.Matches(buffer)) {
]==])
set(_loop_replacement [==[  while (buffer) {
    // These leading bytes cannot match any disallowed expression.
    const unsigned char ch = static_cast<unsigned char>(buffer[0]);
    if (asciiWord(ch) ||
        (!allowOnlyAscii && ch >= 0x80 && ch != 0xC2 && ch != 0xEF)) {
      ++buffer;
      continue;
    }
    if (disallowed.Matches(buffer)) {
]==])
string(REPLACE "\r\n" "\n" _loop_needle "${_loop_needle}")
string(REPLACE "\r\n" "\n" _loop_replacement "${_loop_replacement}")
string(REPLACE "${_loop_needle}" "${_loop_replacement}" _patched "${_patched}")
string(SHA256 _after_hash "${_patched}")
if(NOT _after_hash STREQUAL _patched_hash)
  message(FATAL_ERROR "yaml-cpp scalar validation transformation did not produce its reviewed hash")
endif()
file(WRITE "${_source}" "${_patched}")
