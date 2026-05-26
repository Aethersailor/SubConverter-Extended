CMAKE_MINIMUM_REQUIRED(VERSION 3.5)
PROJECT(subconverter LANGUAGES CXX)
SET(BUILD_TARGET_NAME ${PROJECT_NAME})
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/")
INCLUDE_DIRECTORIES("${CMAKE_SOURCE_DIR}/include/")

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

# Suppress warnings from third-party libraries
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    add_compile_options(-Wno-array-bounds)
    add_compile_options(-Wno-unused-but-set-parameter)
endif()

IF(NOT MSVC)
    ADD_COMPILE_OPTIONS(-Wall -Wextra -Wno-unused-parameter -Wno-unused-result)
ELSE()
    ADD_COMPILE_OPTIONS(/W4)
ENDIF()

#remove std::regex support since it is not compatible with group modifiers and slow
#OPTION(USING_STD_REGEX "Use std::regex from C++ library instead of PCRE2." OFF)
OPTION(USING_MALLOC_TRIM "Call malloc_trim after processing request to lower memory usage (Your system must support malloc_trim)." OFF)
#now using internal MD5 calculation
#OPTION(USING_MBEDTLS "Use mbedTLS instead of OpenSSL for MD5 calculation." OFF)
OPTION(BUILD_STATIC_LIBRARY "Build a static library containing only the essential part." OFF)

INCLUDE(CheckCXXSourceCompiles)
CHECK_CXX_SOURCE_COMPILES(
"
#include<string>
int main(){std::to_string(0);}
" HAVE_TO_STRING)

IF(NOT BUILD_STATIC_LIBRARY)

ADD_EXECUTABLE(${BUILD_TARGET_NAME} 
    src/generator/config/nodemanip.cpp
    src/generator/config/ruleconvert.cpp
    src/generator/config/subexport.cpp
    src/generator/template/templates.cpp
    src/handler/dashboard_auth.cpp
    src/handler/dashboard_page.cpp
    src/handler/inspect_page.cpp
    src/handler/interfaces.cpp
    src/handler/multithread.cpp
    src/handler/statistics.cpp
    src/handler/upload.cpp
    src/handler/version_page.cpp
    src/handler/webget.cpp
    src/handler/settings.cpp
    src/main.cpp
    src/parser/infoparser.cpp
    src/parser/subparser.cpp
    src/parser/mihomo_bridge.cpp
    src/script/cron.cpp
    src/script/script_quickjs.cpp
#    src/server/webserver_libevent.cpp
    src/server/webserver_httplib.cpp
    src/utils/base64/base64.cpp
    src/utils/codepage.cpp
    src/utils/file.cpp
    src/utils/logger.cpp
    src/utils/md5/md5.cpp
    src/utils/network.cpp
    src/utils/regexp.cpp
    src/utils/string.cpp
    src/utils/system.cpp
    src/utils/urlencode.cpp)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE src)
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${CMAKE_SOURCE_DIR})

FIND_PACKAGE(PkgConfig REQUIRED)

SET(THREADS_PREFER_PTHREAD_FLAG ON)
FIND_PACKAGE(Threads REQUIRED)
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${CMAKE_THREAD_LIBS_INIT})

#PKG_CHECK_MODULES(LIBEVENT libevent>=2.1.10 REQUIRED)
#FIND_PATH(LIBEVENT_INCLUDE_DIR NAMES event.h PATHS ${LIBEVENT_INCLUDE_DIRS})
#FIND_LIBRARY(LIBEVENT_LIBRARY NAMES event PATHS ${LIBEVENT_LIBRARY_DIRS})
#TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${LIBEVENT_LIBRARY_DIRS})
#TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${LIBEVENT_INCLUDE_DIR})
#TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${LIBEVENT_LIBRARY})

FIND_PACKAGE(CURL 7.54.0 REQUIRED)
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${CURL_LIBRARY_DIRS})
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${CURL_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} CURL::libcurl)
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE CURL_STATICLIB)

FIND_PACKAGE(Rapidjson REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${RAPIDJSON_INCLUDE_DIRS})

FIND_PACKAGE(toml11 REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${TOML11_INCLUDE_DIRS})

PKG_CHECK_MODULES(YAML_CPP yaml-cpp>=0.6.3 REQUIRED)
FIND_LIBRARY(YAML_CPP_LIBRARY NAMES yaml-cpp yaml-cppd PATHS ${YAML_CPP_LIBRARY_DIRS})
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY_DIRS})
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${YAML_CPP_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE YAML_CPP_STATIC_DEFINE)

FIND_PACKAGE(PCRE2 REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${PCRE2_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} ${PCRE2_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE PCRE2_STATIC)

FIND_PACKAGE(QuickJS REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${QUICKJS_INCLUDE_DIRS})
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
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${LIBCRON_INCLUDE_DIRS})
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
    MESSAGE(WARNING "mihomo Go library not found, parser will use fallback mode")
ENDIF()

IF(WIN32)
    TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} wsock32 ws2_32)
ELSE()
    INCLUDE(GNUInstallDirs)
    INSTALL(TARGETS ${BUILD_TARGET_NAME} DESTINATION ${CMAKE_INSTALL_BINDIR}/${BUILD_TARGET_NAME})
    INSTALL(DIRECTORY base/ DESTINATION ${CMAKE_INSTALL_BINDIR}/${BUILD_TARGET_NAME} FILES_MATCHING PATTERN "*")
ENDIF()

ELSE() #BUILD_STATIC_LIBRARY

ADD_LIBRARY(${BUILD_TARGET_NAME} STATIC
    src/generator/config/ruleconvert.cpp
    src/generator/config/subexport.cpp
    src/generator/template/templates.cpp
    src/lib/wrapper.cpp
    src/parser/subparser.cpp
    src/utils/base64/base64.cpp
    src/utils/codepage.cpp
    src/utils/logger.cpp
    src/utils/md5/md5.cpp
    src/utils/network.cpp
    src/utils/regexp.cpp
    src/utils/string.cpp
    src/utils/urlencode.cpp)
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE NO_JS_RUNTIME NO_WEBGET)

TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PUBLIC src)

FIND_PACKAGE(Rapidjson REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${RAPIDJSON_INCLUDE_DIRS})

FIND_PACKAGE(PkgConfig REQUIRED)

PKG_CHECK_MODULES(YAML_CPP yaml-cpp>=0.6.3 REQUIRED)
FIND_LIBRARY(YAML_CPP_LIBRARY NAMES yaml-cpp yaml-cppd PATHS ${YAML_CPP_LIBRARY_DIRS})
TARGET_LINK_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY_DIRS})
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_INCLUDE_DIRS})
TARGET_LINK_LIBRARIES(${BUILD_TARGET_NAME} PRIVATE ${YAML_CPP_LIBRARY})
TARGET_COMPILE_DEFINITIONS(${BUILD_TARGET_NAME} PRIVATE YAML_CPP_STATIC_DEFINE)

FIND_PACKAGE(PCRE2 REQUIRED)
TARGET_INCLUDE_DIRECTORIES(${BUILD_TARGET_NAME} PRIVATE ${PCRE2_INCLUDE_DIRS})
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
