cmake_minimum_required(VERSION 3.16)
project(libreq VERSION 1.0.0 LANGUAGES C)

include(GNUInstallDirs)
include(CTest)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

option(SP_SANITIZE "ASan+UBSan" OFF)
option(REQ_WERROR "Warnings as errors" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_VISIBILITY_PRESET hidden)

add_library(req STATIC src/req.c src/req_url.c src/req_net.c)
add_library(req::req ALIAS req)
target_include_directories(req PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_compile_definitions(req PUBLIC REQ_USE_OPENSSL PRIVATE _DEFAULT_SOURCE)
target_link_libraries(req PUBLIC OpenSSL::SSL OpenSSL::Crypto)
if (NOT MSVC)
    target_compile_options(req PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion)
    if (REQ_WERROR)
        target_compile_options(req PRIVATE -Werror)
    endif()
endif()

function(req_sanitize tgt)
    if (SP_SANITIZE AND NOT MSVC)
        target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
    endif()
endfunction()
req_sanitize(req)

if (BUILD_TESTING)
    add_executable(req_tests tests/test_req.c)
    target_link_libraries(req_tests PRIVATE req Threads::Threads)
    add_test(NAME req_tests COMMAND req_tests)
    req_sanitize(req_tests)

    add_executable(req_example examples/get.c)
    target_link_libraries(req_example PRIVATE req)
    req_sanitize(req_example)
endif()

install(TARGETS req ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES include/req.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
