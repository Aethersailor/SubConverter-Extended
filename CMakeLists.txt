CMAKE_MINIMUM_REQUIRED(VERSION 3.13)
PROJECT(subconverter LANGUAGES CXX)
SET(BUILD_TARGET_NAME ${PROJECT_NAME})
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
# Bundled headers under include/ are third-party dependencies.  Treat them as
# system headers so their diagnostics do not require project-wide suppression.
INCLUDE_DIRECTORIES(SYSTEM "${CMAKE_SOURCE_DIR}/include/")

if (MINGW)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--allow-multiple-definition")
endif()

IF(NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE Release)
ENDIF()
SET(CMAKE_CXX_STANDARD 20)

# ========== Alpine/musl 链接优化 ==========
# 检测 musl 环境并应用特殊链接策略，解决 Go CGO 与 C++ 混合编译时的 Segfault 问题
SET(USING_MUSL FALSE)
IF(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # 检测是否为 musl libc（Alpine）
    EXECUTE_PROCESS(
        COMMAND ldd --version
        OUTPUT_VARIABLE LDD_OUTPUT
        ERROR_VARIABLE LDD_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    IF(LDD_OUTPUT MATCHES "musl")
        SET(USING_MUSL TRUE)
        MESSAGE(STATUS "Detected musl libc (Alpine), applying special link flags")
        
        # 禁用 LTO（Link Time Optimization）- 避免符号丢失
        SET(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)
        
        # 禁用 PIE（Position Independent Executable）- 减少重定位复杂度
        SET(CMAKE_POSITION_INDEPENDENT_CODE OFF)
        
        # 添加链接器标志
        SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-as-needed")
    ENDIF()
ENDIF()

IF(NOT MSVC)
    ADD_COMPILE_OPTIONS(-Wall -Wextra)
ELSE()
    ADD_COMPILE_OPTIONS(/W4)
ENDIF()

#remove std::regex support since it is not compatible with group modifiers and slow
#OPTION(USING_STD_REGEX "Use std::regex from C++ library instead of PCRE2." OFF)
OPTION(USING_MALLOC_TRIM "Call malloc_trim after processing request to lower memory usage (Your system must support malloc_trim)." OFF)
#now using internal MD5 calculation
#OPTION(USING_MBEDTLS "Use mbedTLS instead of OpenSSL for MD5 calculation." OFF)
OPTION(BUILD_STATIC_LIBRARY "Build a static library containing only the essential part." OFF)
OPTION(BUILD_TESTS "Build focused regression tests." OFF)
OPTION(ENABLE_SANITIZERS "Build tests and runtime with ASan and UBSan." OFF)
SET(MIHOMO_TEST_BINARY "" CACHE FILEPATH
    "Pinned Mihomo CLI used by compatibility tests")
OPTION(REQUIRE_MIHOMO_TEST_BINARY
    "Fail configuration unless a Mihomo test CLI is supplied." OFF)
SET(SINGBOX_STABLE_TEST_BINARY "" CACHE FILEPATH
    "Pinned stable sing-box CLI used by compatibility tests")
SET(SINGBOX_NEXT_TEST_BINARY "" CACHE FILEPATH
    "Pinned next-version sing-box CLI used by compatibility tests")
OPTION(REQUIRE_SINGBOX_TEST_BINARIES
    "Fail configuration unless both sing-box test CLIs are supplied." OFF)

IF(ENABLE_SANITIZERS)
    IF(NOT CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        MESSAGE(FATAL_ERROR "ENABLE_SANITIZERS requires GCC or Clang")
    ENDIF()
    ADD_COMPILE_OPTIONS(
        -O1
        -g
        -fno-omit-frame-pointer
        -fsanitize=address,undefined)
    ADD_LINK_OPTIONS(-fsanitize=address,undefined)
ENDIF()

INCLUDE(CheckCXXSourceCompiles)
CHECK_CXX_SOURCE_COMPILES(
"
#include<string>
int main(){std::to_string(0);}
" HAVE_TO_STRING)

IF(NOT BUILD_STATIC_LIBRARY)

SET(DASHBOARD_HTML_SOURCE
    "${CMAKE_SOURCE_DIR}/resources/dashboard/index.html")
SET(DASHBOARD_HTML_GENERATED
    "${CMAKE_CURRENT_BINARY_DIR}/generated/dashboard_page.html.inc")
IF(NOT EXISTS "${DASHBOARD_HTML_SOURCE}")
    MESSAGE(FATAL_ERROR
        "Dashboard source is missing: ${DASHBOARD_HTML_SOURCE}")
ENDIF()
ADD_CUSTOM_COMMAND(
    OUTPUT "${DASHBOARD_HTML_GENERATED}"
    COMMAND "${CMAKE_COMMAND}"
            "-DINPUT_FILE=${DASHBOARD_HTML_SOURCE}"
            "-DOUTPUT_FILE=${DASHBOARD_HTML_GENERATED}"
            -P "${CMAKE_SOURCE_DIR}/cmake/embed_dashboard.cmake"
    DEPENDS
        "${DASHBOARD_HTML_SOURCE}"
        "${CMAKE_SOURCE_DIR}/cmake/embed_dashboard.cmake"
    COMMENT "Embedding Dashboard HTML"
    VERBATIM)
ADD_CUSTOM_TARGET(dashboard_resource
    DEPENDS "${DASHBOARD_HTML_GENERATED}")

SET(SUBCONVERTER_RUNTIME_SOURCES
    src/config/preference_file.cpp
    src/config/ruleset.cpp
    src/generator/config/clash_proxy.cpp
    src/generator/config/external_rules.cpp
    src/generator/config/nodemanip.cpp
    src/generator/config/ruleconvert.cpp
    src/generator/config/subexport.cpp
    src/generator/template/templates.cpp
    src/handler/dashboard_auth.cpp
    src/handler/dashboard_auth_limiter.cpp
    src/handler/dashboard_page.cpp
    src/handler/cocr_source_url.cpp
    src/handler/cache_storage.cpp
    src/handler/curl_handle_pool.cpp
    src/handler/inspect_page.cpp
    src/handler/interfaces.cpp
    src/handler/multithread.cpp
    src/handler/statistics.cpp
    src/handler/statistics_v2.cpp
    src/handler/upload.cpp
    src/handler/user_agent.cpp
    src/handler/version_page.cpp
    src/handler/webget.cpp
    src/handler/proxy_policy.cpp
    src/handler/ruleset_output.cpp
    src/handler/settings.cpp
    src/handler/settings_view.cpp
    src/handler/sub_request_key.cpp
    src/parser/infoparser.cpp
    src/parser/mieru_uri.cpp
    src/parser/subparser.cpp
    src/parser/mihomo_bridge.cpp
    src/script/cron.cpp
    src/script/script_quickjs.cpp
    src/server/client_ip.cpp
    src/server/webserver_beast.cpp
    src/server/webserver_httplib.cpp
    src/utils/base64/base64.cpp
    src/utils/codepage.cpp
    src/utils/file.cpp
    src/utils/logger.cpp
    src/utils/md5/md5.cpp
    src/utils/network.cpp
    src/utils/redact.cpp
    src/utils/regexp.cpp
    src/utils/resource_control.cpp
    src/utils/string.cpp
    src/utils/system.cpp
    src/utils/urlencode.cpp)
ADD_EXECUTABLE(${BUILD_TARGET_NAME}
    ${SUBCONVERTER_RUNTIME_SOURCES}
    src/main.cpp)
ADD_DEPENDENCIES(${BUILD_TARGET_NAME} dashboard_resource)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE
    src
    "${CMAKE_CURRENT_BINARY_DIR}")
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${CMAKE_SOURCE_DIR})

FIND_PACKAGE(PkgConfig REQUIRED)

SET(THREADS_PREFER_PTHREAD_FLAG ON)
FIND_PACKAGE(Threads REQUIRED)
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${CMAKE_THREAD_LIBS_INIT})

FIND_PACKAGE(CURL 7.54.0 REQUIRED)
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${CURL_LIBRARY_DIRS})
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} SYSTEM PRIVATE ${CURL_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} CURL::libcurl)
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE CURL_STATICLIB)

FIND_PACKAGE(Rapidjson REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} SYSTEM PRIVATE ${RAPIDJSON_INCLUDE_DIRS})

FIND_PACKAGE(toml11 REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} SYSTEM PRIVATE ${TOML11_INCLUDE_DIRS})

PKG_CHECK_MODULES(YAML_CPP yaml-cpp>=0.6.3 REQUIRED)
FIND_LIBRARY(YAML_CPP_LIBRARY NAMES yaml-cpp yaml-cppd PATHS ${YAML_CPP_LIBRARY_DIRS})
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY_DIRS})
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} SYSTEM PRIVATE ${YAML_CPP_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${YAML_CPP_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE YAML_CPP_STATIC_DEFINE)

FIND_PACKAGE(PCRE2 REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} SYSTEM PRIVATE ${PCRE2_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${PCRE2_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE PCRE2_STATIC)

FIND_PACKAGE(QuickJS REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} SYSTEM PRIVATE ${QUICKJS_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${QUICKJS_LIBRARIES})
SET(CMAKE_REQUIRED_INCLUDES ${QUICKJS_INCLUDE_DIRS})
CHECK_CXX_SOURCE_COMPILES(
"
#include <quickjs/quickjs.h>
int main(){ return sizeof(&JS_SetHostUnhandledPromiseRejectionTracker) > 0 ? 0 : 1; }
" HAVE_QUICKJS_HOST_UNHANDLED_PROMISE_REJECTION_TRACKER)
UNSET(CMAKE_REQUIRED_INCLUDES)
IF(HAVE_QUICKJS_HOST_UNHANDLED_PROMISE_REJECTION_TRACKER)
    TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE QUICKJS_HAS_HOST_UNHANDLED_PROMISE_REJECTION_TRACKER)
ELSE()
    TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE JS_SetHostUnhandledPromiseRejectionTracker=JS_SetHostPromiseRejectionTracker)
ENDIF()

FIND_PACKAGE(LibCron REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} SYSTEM PRIVATE ${LIBCRON_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${LIBCRON_LIBRARIES})

# Mihomo Go Parser Bridge
# 支持 c-shared (.so) 和 c-archive (.a) 两种模式
# c-shared 模式：解决 musl/Alpine 环境下 Go runtime 初始化问题
IF(EXISTS "${CMAKE_SOURCE_DIR}/bridge/libmihomo.so")
    MESSAGE(STATUS "Found mihomo Go shared library (.so), enabling native parser support")
    TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/bridge")
    TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE USE_MIHOMO_PARSER)
    
    # Link pthread (required by Go runtime on Linux)
    IF(UNIX AND NOT APPLE)
        TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} pthread)
    ENDIF()
    
    # 动态库链接（无需 --whole-archive）
    TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} "${CMAKE_SOURCE_DIR}/bridge/libmihomo.so")
    
ELSEIF(EXISTS "${CMAKE_SOURCE_DIR}/bridge/libmihomo.a")
    MESSAGE(STATUS "Found mihomo Go static library (.a), enabling native parser support")
    TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE "${CMAKE_SOURCE_DIR}/bridge")
    TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE USE_MIHOMO_PARSER)
    
    # Link pthread BEFORE Go library (required by Go runtime)
    IF(UNIX AND NOT APPLE)
        TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} pthread)
        
        # 使用 --whole-archive 确保 Go 符号被完整拉入（仅静态库需要）
        IF(USING_MUSL)
            MESSAGE(STATUS "Using --whole-archive for Go library linking (musl mode)")
            TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} 
                "-Wl,--whole-archive"
                "${CMAKE_SOURCE_DIR}/bridge/libmihomo.a"
                "-Wl,--no-whole-archive"
            )
        ELSE()
            TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} "${CMAKE_SOURCE_DIR}/bridge/libmihomo.a")
        ENDIF()
    ELSE()
        TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} "${CMAKE_SOURCE_DIR}/bridge/libmihomo.a")
    ENDIF()
ELSE()
    MESSAGE(WARNING
        "mihomo Go library not found; Clash/ClashR node parsing is disabled")
ENDIF()

IF(WIN32)
    TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} wsock32 ws2_32 mswsock)
ELSE()
    INCLUDE(GNUInstallDirs)
    INSTALL(TARGETS ${BUILD_TARGET_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR}/${BUILD_TARGET_NAME})
    INSTALL(DIRECTORY base/ DESTINATION ${CMAKE_INSTALL_BINDIR}/${BUILD_TARGET_NAME} FILES_MATCHING PATTERN "*")
ENDIF()

IF(BUILD_TESTS)
    ENABLE_TESTING()
    FIND_PACKAGE(Python3 COMPONENTS Interpreter REQUIRED)

    ADD_EXECUTABLE(user_agent_test
        tests/user_agent_test.cpp
        src/handler/user_agent.cpp
        src/utils/regexp.cpp)
    TARGET_INCLUDE_DIRECTORIES(user_agent_test PRIVATE src)
    TARGET_INCLUDE_DIRECTORIES(user_agent_test SYSTEM PRIVATE
        ${PCRE2_INCLUDE_DIRS})
    TARGET_LINK_LIBRARIES(user_agent_test ${PCRE2_LIBRARY})
    TARGET_COMPILE_DEFINITIONS(user_agent_test PRIVATE PCRE2_STATIC)
    ADD_TEST(NAME user_agent COMMAND user_agent_test)
    SET_TESTS_PROPERTIES(user_agent PROPERTIES LABELS fast)

    SET(SETTINGS_SNAPSHOT_RUNTIME_SOURCES ${SUBCONVERTER_RUNTIME_SOURCES})
    LIST(REMOVE_ITEM SETTINGS_SNAPSHOT_RUNTIME_SOURCES
        src/parser/mihomo_bridge.cpp)
    ADD_EXECUTABLE(settings_snapshot_test_helper
        ${SETTINGS_SNAPSHOT_RUNTIME_SOURCES}
        src/handler/settings_snapshot.cpp
        tests/settings_snapshot_test_helper.cpp)
    ADD_DEPENDENCIES(settings_snapshot_test_helper dashboard_resource)
    TARGET_INCLUDE_DIRECTORIES(settings_snapshot_test_helper PRIVATE
        $<TARGET_PROPERTY:${BUILD_TARGET_NAME},INCLUDE_DIRECTORIES>)
    TARGET_LINK_DIRECTORIES(settings_snapshot_test_helper PRIVATE
        $<TARGET_PROPERTY:${BUILD_TARGET_NAME},LINK_DIRECTORIES>)
    TARGET_LINK_LIBRARIES(settings_snapshot_test_helper PRIVATE
        $<TARGET_PROPERTY:${BUILD_TARGET_NAME},LINK_LIBRARIES>)
    TARGET_COMPILE_DEFINITIONS(settings_snapshot_test_helper PRIVATE
        $<TARGET_PROPERTY:${BUILD_TARGET_NAME},COMPILE_DEFINITIONS>)

    SET(COMPATIBILITY_SECURITY_BASELINE_ARGS
        --binary $<TARGET_FILE:${BUILD_TARGET_NAME}>
        --settings-snapshot-helper
        $<TARGET_FILE:settings_snapshot_test_helper>)
    IF(MIHOMO_TEST_BINARY)
        IF(NOT EXISTS "${MIHOMO_TEST_BINARY}")
            MESSAGE(FATAL_ERROR
                "MIHOMO_TEST_BINARY does not exist: ${MIHOMO_TEST_BINARY}")
        ENDIF()
        LIST(APPEND COMPATIBILITY_SECURITY_BASELINE_ARGS
            --mihomo-binary "${MIHOMO_TEST_BINARY}")
    ELSEIF(REQUIRE_MIHOMO_TEST_BINARY)
        MESSAGE(FATAL_ERROR
            "REQUIRE_MIHOMO_TEST_BINARY requires MIHOMO_TEST_BINARY")
    ENDIF()
    IF(SINGBOX_STABLE_TEST_BINARY)
        IF(NOT EXISTS "${SINGBOX_STABLE_TEST_BINARY}")
            MESSAGE(FATAL_ERROR
                "SINGBOX_STABLE_TEST_BINARY does not exist: ${SINGBOX_STABLE_TEST_BINARY}")
        ENDIF()
        LIST(APPEND COMPATIBILITY_SECURITY_BASELINE_ARGS
            --singbox-stable-binary "${SINGBOX_STABLE_TEST_BINARY}")
    ELSEIF(REQUIRE_SINGBOX_TEST_BINARIES)
        MESSAGE(FATAL_ERROR
            "REQUIRE_SINGBOX_TEST_BINARIES requires SINGBOX_STABLE_TEST_BINARY")
    ENDIF()
    IF(SINGBOX_NEXT_TEST_BINARY)
        IF(NOT EXISTS "${SINGBOX_NEXT_TEST_BINARY}")
            MESSAGE(FATAL_ERROR
                "SINGBOX_NEXT_TEST_BINARY does not exist: ${SINGBOX_NEXT_TEST_BINARY}")
        ENDIF()
        LIST(APPEND COMPATIBILITY_SECURITY_BASELINE_ARGS
            --singbox-next-binary "${SINGBOX_NEXT_TEST_BINARY}")
    ELSEIF(REQUIRE_SINGBOX_TEST_BINARIES)
        MESSAGE(FATAL_ERROR
            "REQUIRE_SINGBOX_TEST_BINARIES requires SINGBOX_NEXT_TEST_BINARY")
    ENDIF()

    ADD_TEST(
        NAME compatibility_security_baseline
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/tests/compatibility_security_baseline.py
                ${COMPATIBILITY_SECURITY_BASELINE_ARGS})
    SET_TESTS_PROPERTIES(compatibility_security_baseline PROPERTIES
        LABELS full
        TIMEOUT 120
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
    ADD_TEST(
        NAME compatibility_security_baseline_httplib
        COMMAND ${Python3_EXECUTABLE}
                ${CMAKE_SOURCE_DIR}/tests/compatibility_security_baseline.py
                ${COMPATIBILITY_SECURITY_BASELINE_ARGS})
    SET_TESTS_PROPERTIES(compatibility_security_baseline_httplib PROPERTIES
        LABELS full
        TIMEOUT 120
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        ENVIRONMENT "SUBCONVERTER_HTTP_BACKEND=httplib;SUBCONVERTER_RESOURCE_CONTROL=compat")

    IF(UNIX)
        ADD_TEST(
            NAME shutdown_process
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/shutdown_process_test.py
                    --binary $<TARGET_FILE:${BUILD_TARGET_NAME}>)
        SET_TESTS_PROPERTIES(shutdown_process PROPERTIES
            LABELS full
            RUN_SERIAL TRUE
            TIMEOUT 120
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
        ADD_TEST(
            NAME shutdown_process_httplib
            COMMAND ${Python3_EXECUTABLE}
                    ${CMAKE_SOURCE_DIR}/tests/shutdown_process_test.py
                    --binary $<TARGET_FILE:${BUILD_TARGET_NAME}>)
        SET_TESTS_PROPERTIES(shutdown_process_httplib PROPERTIES
            LABELS full
            RUN_SERIAL TRUE
            TIMEOUT 120
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            ENVIRONMENT "SUBCONVERTER_HTTP_BACKEND=httplib;SUBCONVERTER_RESOURCE_CONTROL=compat")
    ENDIF()

    ADD_EXECUTABLE(proxy_policy_test
        tests/proxy_policy_test.cpp
        src/handler/proxy_policy.cpp
        src/server/client_ip.cpp
        src/utils/redact.cpp
        src/utils/string.cpp
        src/utils/system.cpp)
    TARGET_INCLUDE_DIRECTORIES(proxy_policy_test PRIVATE src)
    TARGET_LINK_LIBRARIES(proxy_policy_test ${CMAKE_THREAD_LIBS_INIT})
    IF(WIN32)
        TARGET_LINK_LIBRARIES(proxy_policy_test ws2_32)
    ENDIF()
    ADD_TEST(NAME proxy_policy COMMAND proxy_policy_test)
    SET_TESTS_PROPERTIES(proxy_policy PROPERTIES LABELS fast)

    ADD_EXECUTABLE(webserver_error_test
        tests/webserver_error_test.cpp
        src/handler/settings_view.cpp
        src/server/client_ip.cpp
        src/server/webserver_beast.cpp
        src/server/webserver_httplib.cpp
        src/utils/base64/base64.cpp
        src/utils/logger.cpp
        src/utils/redact.cpp
        src/utils/string.cpp
        src/utils/system.cpp
        src/utils/urlencode.cpp)
    TARGET_INCLUDE_DIRECTORIES(webserver_error_test PRIVATE src)
    TARGET_COMPILE_DEFINITIONS(webserver_error_test PRIVATE
        $<TARGET_PROPERTY:${BUILD_TARGET_NAME},COMPILE_DEFINITIONS>)
    TARGET_LINK_LIBRARIES(webserver_error_test ${CMAKE_THREAD_LIBS_INIT})
    IF(WIN32)
        TARGET_LINK_LIBRARIES(webserver_error_test ws2_32 mswsock)
    ENDIF()
    ADD_TEST(NAME webserver_error COMMAND webserver_error_test)
    SET_TESTS_PROPERTIES(webserver_error PROPERTIES LABELS fast TIMEOUT 30)
    ADD_TEST(NAME webserver_error_httplib COMMAND webserver_error_test)
    SET_TESTS_PROPERTIES(webserver_error_httplib PROPERTIES
        LABELS fast
        TIMEOUT 30
        ENVIRONMENT "SUBCONVERTER_HTTP_BACKEND=httplib;SUBCONVERTER_RESOURCE_CONTROL=compat")

    ADD_EXECUTABLE(client_ip_test
        tests/client_ip_test.cpp
        src/server/client_ip.cpp)
    TARGET_INCLUDE_DIRECTORIES(client_ip_test PRIVATE src)
    IF(WIN32)
        TARGET_LINK_LIBRARIES(client_ip_test ws2_32)
    ENDIF()
    ADD_TEST(NAME client_ip COMMAND client_ip_test)
    SET_TESTS_PROPERTIES(client_ip PROPERTIES LABELS fast)

    ADD_EXECUTABLE(dashboard_auth_limiter_test
        tests/dashboard_auth_limiter_test.cpp
        src/handler/dashboard_auth_limiter.cpp
        src/server/client_ip.cpp)
    TARGET_INCLUDE_DIRECTORIES(dashboard_auth_limiter_test PRIVATE src)
    TARGET_COMPILE_DEFINITIONS(dashboard_auth_limiter_test PRIVATE
        DASHBOARD_AUTH_LIMITER_TESTING)
    TARGET_LINK_LIBRARIES(dashboard_auth_limiter_test
        ${CMAKE_THREAD_LIBS_INIT})
    IF(WIN32)
        TARGET_LINK_LIBRARIES(dashboard_auth_limiter_test ws2_32)
    ENDIF()
    ADD_TEST(NAME dashboard_auth_limiter COMMAND dashboard_auth_limiter_test)
    SET_TESTS_PROPERTIES(dashboard_auth_limiter PROPERTIES LABELS fast)

    ADD_EXECUTABLE(cocr_source_url_test
        tests/cocr_source_url_test.cpp
        src/handler/cocr_source_url.cpp)
    TARGET_INCLUDE_DIRECTORIES(cocr_source_url_test PRIVATE src)
    ADD_TEST(NAME cocr_source_url COMMAND cocr_source_url_test)
    SET_TESTS_PROPERTIES(cocr_source_url PROPERTIES LABELS fast)

    ADD_EXECUTABLE(ruleset_options_test
        tests/ruleset_options_test.cpp
        src/config/ruleset.cpp)
    TARGET_INCLUDE_DIRECTORIES(ruleset_options_test PRIVATE src)
    ADD_TEST(NAME ruleset_options COMMAND ruleset_options_test)
    SET_TESTS_PROPERTIES(ruleset_options PROPERTIES LABELS fast)

    ADD_EXECUTABLE(ruleset_output_test
        tests/ruleset_output_test.cpp
        src/handler/ruleset_output.cpp
        src/utils/regexp.cpp
        src/utils/string.cpp)
    TARGET_INCLUDE_DIRECTORIES(ruleset_output_test PRIVATE src)
    TARGET_INCLUDE_DIRECTORIES(ruleset_output_test SYSTEM PRIVATE
        ${PCRE2_INCLUDE_DIRS})
    TARGET_LINK_LIBRARIES(ruleset_output_test ${PCRE2_LIBRARY})
    TARGET_COMPILE_DEFINITIONS(ruleset_output_test PRIVATE PCRE2_STATIC)
    ADD_TEST(NAME ruleset_output COMMAND ruleset_output_test)
    SET_TESTS_PROPERTIES(ruleset_output PROPERTIES LABELS fast)

    ADD_EXECUTABLE(external_rules_test
        tests/external_rules_test.cpp
        src/generator/config/external_rules.cpp)
    TARGET_INCLUDE_DIRECTORIES(external_rules_test PRIVATE src)
    TARGET_INCLUDE_DIRECTORIES(external_rules_test SYSTEM PRIVATE ${YAML_CPP_INCLUDE_DIRS})
    TARGET_LINK_DIRECTORIES(external_rules_test PRIVATE
        ${YAML_CPP_LIBRARY_DIRS})
    TARGET_LINK_LIBRARIES(external_rules_test
        ${YAML_CPP_LIBRARY})
    ADD_TEST(NAME external_rules COMMAND external_rules_test)
    SET_TESTS_PROPERTIES(external_rules PROPERTIES LABELS fast)

    ADD_EXECUTABLE(clash_proxy_test
        tests/clash_proxy_test.cpp
        src/generator/config/clash_proxy.cpp)
    TARGET_INCLUDE_DIRECTORIES(clash_proxy_test PRIVATE src)
    TARGET_INCLUDE_DIRECTORIES(clash_proxy_test SYSTEM PRIVATE
        ${YAML_CPP_INCLUDE_DIRS})
    TARGET_LINK_DIRECTORIES(clash_proxy_test PRIVATE
        ${YAML_CPP_LIBRARY_DIRS})
    TARGET_LINK_LIBRARIES(clash_proxy_test ${YAML_CPP_LIBRARY})
    ADD_TEST(NAME clash_proxy COMMAND clash_proxy_test)
    SET_TESTS_PROPERTIES(clash_proxy PROPERTIES LABELS fast)

    ADD_EXECUTABLE(concurrency_primitives_test
        tests/concurrency_primitives_test.cpp)
    TARGET_INCLUDE_DIRECTORIES(concurrency_primitives_test PRIVATE src)
    TARGET_LINK_LIBRARIES(concurrency_primitives_test
        ${CMAKE_THREAD_LIBS_INIT})
    ADD_TEST(NAME concurrency_primitives COMMAND concurrency_primitives_test)
    SET_TESTS_PROPERTIES(concurrency_primitives PROPERTIES LABELS fast)

    ADD_EXECUTABLE(settings_view_test
        tests/settings_view_test.cpp
        src/handler/settings_view.cpp)
    TARGET_INCLUDE_DIRECTORIES(settings_view_test PRIVATE src)
    TARGET_COMPILE_DEFINITIONS(settings_view_test PRIVATE
        $<TARGET_PROPERTY:${BUILD_TARGET_NAME},COMPILE_DEFINITIONS>)
    TARGET_LINK_LIBRARIES(settings_view_test ${CMAKE_THREAD_LIBS_INIT})
    ADD_TEST(NAME settings_view COMMAND settings_view_test)
    SET_TESTS_PROPERTIES(settings_view PROPERTIES LABELS fast)
    ADD_TEST(
        NAME settings_view_invariant_failure
        COMMAND settings_view_test --inject-invariant-failure)
    SET_TESTS_PROPERTIES(settings_view_invariant_failure PROPERTIES
        LABELS fast
        WILL_FAIL TRUE)

    ADD_EXECUTABLE(statistics_v2_test
        tests/statistics_v2_test.cpp
        src/handler/statistics_v2.cpp)
    TARGET_INCLUDE_DIRECTORIES(statistics_v2_test PRIVATE src)
    TARGET_COMPILE_DEFINITIONS(statistics_v2_test PRIVATE
        STATISTICS_V2_TESTING)
    TARGET_LINK_LIBRARIES(statistics_v2_test
        ${CMAKE_THREAD_LIBS_INIT})
    ADD_TEST(NAME statistics_v2 COMMAND statistics_v2_test)
    SET_TESTS_PROPERTIES(statistics_v2 PROPERTIES
        LABELS fast
        TIMEOUT 120)

    ADD_EXECUTABLE(sub_request_key_test
        tests/sub_request_key_test.cpp
        src/handler/sub_request_key.cpp
        src/utils/md5/md5.cpp)
    TARGET_INCLUDE_DIRECTORIES(sub_request_key_test PRIVATE src)
    ADD_TEST(NAME sub_request_key COMMAND sub_request_key_test)
    SET_TESTS_PROPERTIES(sub_request_key PROPERTIES LABELS fast)

    ADD_EXECUTABLE(proxy_provider_interval_test
        tests/proxy_provider_interval_test.cpp)
    TARGET_INCLUDE_DIRECTORIES(proxy_provider_interval_test PRIVATE src)
    ADD_TEST(NAME proxy_provider_interval COMMAND proxy_provider_interval_test)
    SET_TESTS_PROPERTIES(proxy_provider_interval PROPERTIES LABELS fast)

    ADD_EXECUTABLE(proxy_provider_direct_test
        tests/proxy_provider_direct_test.cpp)
    TARGET_INCLUDE_DIRECTORIES(proxy_provider_direct_test PRIVATE src)
    ADD_TEST(NAME proxy_provider_direct COMMAND proxy_provider_direct_test)
    SET_TESTS_PROPERTIES(proxy_provider_direct PROPERTIES LABELS fast)

    ADD_EXECUTABLE(mieru_uri_test
        tests/mieru_uri_test.cpp
        src/parser/mieru_uri.cpp)
    TARGET_INCLUDE_DIRECTORIES(mieru_uri_test PRIVATE src)
    ADD_TEST(NAME mieru_uri COMMAND mieru_uri_test)
    SET_TESTS_PROPERTIES(mieru_uri PROPERTIES LABELS fast)

    ADD_EXECUTABLE(curl_handle_pool_test
        tests/curl_handle_pool_test.cpp
        src/handler/curl_handle_pool.cpp)
    TARGET_INCLUDE_DIRECTORIES(curl_handle_pool_test PRIVATE src)
    TARGET_INCLUDE_DIRECTORIES(curl_handle_pool_test SYSTEM PRIVATE ${CURL_INCLUDE_DIRS})
    TARGET_LINK_LIBRARIES(curl_handle_pool_test
        ${CMAKE_THREAD_LIBS_INIT}
        CURL::libcurl)
    TARGET_COMPILE_DEFINITIONS(curl_handle_pool_test PRIVATE CURL_STATICLIB)
    IF(WIN32)
        TARGET_LINK_LIBRARIES(curl_handle_pool_test ws2_32)
    ENDIF()
    ADD_TEST(NAME curl_handle_pool COMMAND curl_handle_pool_test)
    SET_TESTS_PROPERTIES(curl_handle_pool PROPERTIES LABELS fast)

    ADD_EXECUTABLE(file_scope_test
        tests/file_scope_test.cpp
        src/utils/file.cpp
        src/utils/string.cpp)
    TARGET_INCLUDE_DIRECTORIES(file_scope_test PRIVATE src)
    TARGET_COMPILE_DEFINITIONS(file_scope_test PRIVATE FILE_IO_TESTING)
    ADD_TEST(NAME file_scope COMMAND file_scope_test)
    SET_TESTS_PROPERTIES(file_scope PROPERTIES
        LABELS fast
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

    ADD_EXECUTABLE(preference_file_test
        tests/preference_file_test.cpp
        src/config/preference_file.cpp
        src/utils/file.cpp
        src/utils/string.cpp)
    TARGET_INCLUDE_DIRECTORIES(preference_file_test PRIVATE src)
    TARGET_COMPILE_DEFINITIONS(preference_file_test PRIVATE FILE_IO_TESTING)
    ADD_TEST(NAME preference_file COMMAND preference_file_test)
    SET_TESTS_PROPERTIES(preference_file PROPERTIES LABELS fast)

    ADD_EXECUTABLE(cache_storage_test
        tests/cache_storage_test.cpp
        src/handler/cache_storage.cpp
        src/utils/file.cpp
        src/utils/string.cpp)
    TARGET_INCLUDE_DIRECTORIES(cache_storage_test PRIVATE src)
    TARGET_COMPILE_DEFINITIONS(cache_storage_test PRIVATE
        FILE_IO_TESTING CACHE_STORAGE_TESTING)
    ADD_TEST(NAME cache_storage COMMAND cache_storage_test)
    SET_TESTS_PROPERTIES(cache_storage PROPERTIES LABELS fast)

    ADD_EXECUTABLE(upload_persistence_test
        tests/upload_persistence_test.cpp
        src/handler/upload.cpp
        src/handler/settings_view.cpp
        src/utils/codepage.cpp
        src/utils/file.cpp
        src/utils/redact.cpp
        src/utils/string.cpp)
    TARGET_INCLUDE_DIRECTORIES(upload_persistence_test PRIVATE src)
    TARGET_COMPILE_DEFINITIONS(upload_persistence_test PRIVATE
        FILE_IO_TESTING
        JS_SetHostUnhandledPromiseRejectionTracker=JS_SetHostPromiseRejectionTracker)
    ADD_TEST(NAME upload_persistence COMMAND upload_persistence_test)
    SET_TESTS_PROPERTIES(upload_persistence PROPERTIES LABELS fast)

    # Regression executables must keep assert() active even in a Release build.
    # This is test-only and does not change the production target's NDEBUG state.
    SET(SUBCONVERTER_ASSERTING_TEST_TARGETS
        proxy_policy_test
        webserver_error_test
        client_ip_test
        dashboard_auth_limiter_test
        cocr_source_url_test
        ruleset_options_test
        ruleset_output_test
        external_rules_test
        clash_proxy_test
        concurrency_primitives_test
        settings_view_test
        statistics_v2_test
        sub_request_key_test
        proxy_provider_interval_test
        proxy_provider_direct_test
        mieru_uri_test
        curl_handle_pool_test
        file_scope_test
        preference_file_test
        cache_storage_test
        upload_persistence_test)
    FOREACH(TEST_TARGET IN LISTS SUBCONVERTER_ASSERTING_TEST_TARGETS)
        IF(MSVC)
            TARGET_COMPILE_OPTIONS(${TEST_TARGET} PRIVATE /UNDEBUG)
        ELSE()
            TARGET_COMPILE_OPTIONS(${TEST_TARGET} PRIVATE -UNDEBUG)
        ENDIF()
    ENDFOREACH()
ENDIF()

ELSE() #BUILD_STATIC_LIBRARY

ADD_LIBRARY(${BUILD_TARGET_NAME} STATIC
    src/config/ruleset.cpp
    src/generator/config/clash_proxy.cpp
    src/generator/config/external_rules.cpp
    src/generator/config/ruleconvert.cpp
    src/generator/config/subexport.cpp
    src/generator/template/templates.cpp
    src/lib/wrapper.cpp
    src/parser/mieru_uri.cpp
    src/parser/subparser.cpp
    src/utils/base64/base64.cpp
    src/utils/codepage.cpp
    src/utils/logger.cpp
    src/utils/md5/md5.cpp
    src/utils/network.cpp
    src/utils/redact.cpp
    src/utils/regexp.cpp
    src/utils/string.cpp
    src/utils/urlencode.cpp)
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE NO_JS_RUNTIME NO_WEBGET)

TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PUBLIC src)

FIND_PACKAGE(Rapidjson REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} SYSTEM PRIVATE ${RAPIDJSON_INCLUDE_DIRS})

FIND_PACKAGE(PkgConfig REQUIRED)

PKG_CHECK_MODULES(YAML_CPP yaml-cpp>=0.6.3 REQUIRED)
FIND_LIBRARY(YAML_CPP_LIBRARY NAMES yaml-cpp yaml-cppd PATHS ${YAML_CPP_LIBRARY_DIRS})
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY_DIRS})
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} SYSTEM PRIVATE ${YAML_CPP_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE YAML_CPP_STATIC_DEFINE)

FIND_PACKAGE(PCRE2 REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} SYSTEM PRIVATE ${PCRE2_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} PRIVATE ${PCRE2_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE PCRE2_STATIC)

IF(WIN32)
    TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} PRIVATE ws2_32)
ENDIF()

ENDIF() #BUILD_STATIC_LIBRARY

IF(HAVE_TO_STRING)
    TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE HAVE_TO_STRING)
ENDIF()

IF(USING_MALLOC_TRIM)
    TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE MALLOC_TRIM)
ENDIF()
