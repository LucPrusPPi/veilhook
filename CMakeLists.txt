cmake_minimum_required(VERSION 3.25)
project(veilhook VERSION 0.1.0 LANGUAGES CXX)

# We require C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Add fadec submodule
add_subdirectory(3rdparty/fadec)

# Zydis and asmjit from vcpkg
find_package(zydis CONFIG REQUIRED)
find_package(asmjit CONFIG REQUIRED)

# The static library
add_library(veilhook STATIC)

# Source files
target_sources(veilhook PRIVATE
    source/hwbp_manager.cpp
    source/veh_hub.cpp
    source/cave_alloc.cpp
    source/hook_inline.cpp
    source/hook_mid.cpp
    source/hook_vmt.cpp
    source/syscalls.cpp
    source/analyzer_detector.cpp
    source/analyzer_prologue.cpp
    source/hook_guard.cpp
    source/hook_phantom.cpp
)

# Includes
target_include_directories(veilhook PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Dependencies
target_link_libraries(veilhook 
    PUBLIC fadec
    PUBLIC Zydis::Zydis
    PRIVATE asmjit::asmjit
)

# Tests executable
add_executable(veilhook_tests tests/main.cpp)
target_link_libraries(veilhook_tests PRIVATE veilhook)

# If you use NTAPI, you might need ntdll
target_link_libraries(veilhook_tests PRIVATE ntdll)
