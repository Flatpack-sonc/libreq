cmake_minimum_required(VERSION 3.16)
project(libreq VERSION 1.1.0 LANGUAGES C)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
find_package(OpenSSL 1.1 REQUIRED)
find_package(Threads REQUIRED)

option(REQ_SANITIZE "Build with ASan+UBSan" OFF)
option(REQ_WERROR "Warnings as errors" ON)
option(REQ_BUILD_TESTS "Build tests" ${PROJECT_IS_TOP_LEVEL})
option(REQ_BUILD_EXAMPLES "Build examples" ${PROJECT_IS_TOP_LEVEL})
# Backwards compatibility with the 1.0 option name.
if (SP_SANITIZE)
    set(REQ_SANITIZE ON)
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

function(req_sanitize tgt)
    if (REQ_SANITIZE AND NOT MSVC)
        target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
    endif()
endfunction()

add_library(req src/req.c src/req_url.c src/req_net.c)
add_library(req::req ALIAS req)
set_target_properties(req PROPERTIES
    OUTPUT_NAME req
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})
target_include_directories(req PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
target_compile_definitions(req PRIVATE REQ_USE_OPENSSL _DEFAULT_SOURCE)
target_link_libraries(req PUBLIC OpenSSL::SSL OpenSSL::Crypto)
if (NOT MSVC)
    target_compile_options(req PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
    if (REQ_WERROR)
        target_compile_options(req PRIVATE -Werror)
    endif()
endif()
req_sanitize(req)

if (REQ_BUILD_TESTS)
    enable_testing()
    set(REQ_TEST_FLAGS -Wall -Wextra -Wno-deprecated-declarations)

    add_executable(req_unit tests/test_unit.c)
    target_compile_definitions(req_unit PRIVATE REQ_USE_OPENSSL _DEFAULT_SOURCE)
    target_compile_options(req_unit PRIVATE ${REQ_TEST_FLAGS})
    target_link_libraries(req_unit PRIVATE req)
    req_sanitize(req_unit)
    add_test(NAME req_unit COMMAND req_unit)

    add_executable(req_integration tests/test_req.c)
    target_compile_definitions(req_integration PRIVATE _DEFAULT_SOURCE)
    target_compile_options(req_integration PRIVATE ${REQ_TEST_FLAGS})
    target_link_libraries(req_integration PRIVATE req Threads::Threads)
    req_sanitize(req_integration)
    add_test(NAME req_integration COMMAND req_integration)
endif()

if (REQ_BUILD_EXAMPLES)
    add_executable(req_get examples/get.c)
    target_compile_definitions(req_get PRIVATE _DEFAULT_SOURCE)
    target_link_libraries(req_get PRIVATE req)
    req_sanitize(req_get)
endif()

install(TARGETS req EXPORT reqTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(FILES include/req.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT reqTargets NAMESPACE req:: DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/req)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/reqConfig.cmake.in
    "@PACKAGE_INIT@\ninclude(CMakeFindDependencyMacro)\nfind_dependency(OpenSSL 1.1)\n"
    "include(\"\${CMAKE_CURRENT_LIST_DIR}/reqTargets.cmake\")\n")
configure_package_config_file(${CMAKE_CURRENT_BINARY_DIR}/reqConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/reqConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/req)
write_basic_package_version_file(${CMAKE_CURRENT_BINARY_DIR}/reqConfigVersion.cmake
    COMPATIBILITY SameMajorVersion)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/reqConfig.cmake ${CMAKE_CURRENT_BINARY_DIR}/reqConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/req)

file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/libreq.pc
    "prefix=${CMAKE_INSTALL_PREFIX}\n"
    "libdir=\${prefix}/${CMAKE_INSTALL_LIBDIR}\n"
    "includedir=\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}\n\n"
    "Name: libreq\nDescription: C11 HTTP/1.1 client\nVersion: ${PROJECT_VERSION}\n"
    "Requires.private: openssl\nLibs: -L\${libdir} -lreq\nCflags: -I\${includedir}\n")
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/libreq.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
