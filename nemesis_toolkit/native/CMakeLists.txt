cmake_minimum_required(VERSION 3.20)
project(nemesis_scan VERSION 1.0.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Core sources for the scanning engine
set(CORE_SOURCES
    src/core/config.cpp
    src/core/engine.cpp
    src/core/port_spec.cpp
    src/core/target.cpp
    src/core/timing.cpp
    src/detection/service_detector.cpp
    src/output/json_output.cpp
    src/scanning/tcp_connect_scan.cpp
)

add_library(nemesis_scan_core STATIC ${CORE_SOURCES})

target_include_directories(nemesis_scan_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(WIN32)
    target_link_libraries(nemesis_scan_core PUBLIC ws2_32 iphlpapi)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(nemesis_scan_core PUBLIC Threads::Threads)
endif()

# Standalone CLI binary
add_executable(nemesis-scan src/bindings/cli_main.cpp)
target_link_libraries(nemesis-scan PRIVATE nemesis_scan_core)

set_target_properties(nemesis-scan PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}/bin"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}/bin"
)

# Optional pybind11 Python extension module
find_package(pybind11 CONFIG QUIET)
if(pybind11_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/src/bindings/python_module.cpp")
    pybind11_add_module(nemesis_scan src/bindings/python_module.cpp)
    target_link_libraries(nemesis_scan PRIVATE nemesis_scan_core)
    set_target_properties(nemesis_scan PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_SOURCE_DIR}"
        LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_SOURCE_DIR}"
    )
endif()
