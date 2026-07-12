cmake_minimum_required(VERSION 3.25)
project(veilhook VERSION 0.1.0 LANGUAGES CXX)

# Generate random seeds for ODR-safe struct padding randomization
string(TIMESTAMP CURRENT_SEC "%S")
string(TIMESTAMP CURRENT_MIN "%M")
string(TIMESTAMP CURRENT_HOUR "%H")

math(EXPR SEED_1 "(${CURRENT_SEC} * 17 + 5) % 15 + 1")
math(EXPR SEED_2 "(${CURRENT_MIN} * 31 + 12) % 15 + 1")
math(EXPR SEED_3 "(${CURRENT_HOUR} * 13 + 7) % 15 + 1")

configure_file(
    include/veilhook/mutation_seed.hpp.in
    ${CMAKE_CURRENT_SOURCE_DIR}/include/veilhook/mutation_seed.hpp
)

# We require C++23
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# /W4 on our target only; third_party stays quiet

# Add fadec submodule
add_subdirectory(3rdparty/fadec)

# Zydis and asmjit from vcpkg
find_package(zydis CONFIG REQUIRED)
find_package(asmjit CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)

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

# Apply strict warnings only to our code
if(MSVC)
    target_compile_options(veilhook PRIVATE /W4 /WX)
endif()

# Tests executable
add_executable(veilhook_tests tests/test_main.cpp tests/test_hooks.cpp tests/test_detector.cpp)
target_link_libraries(veilhook_tests PRIVATE veilhook GTest::gtest GTest::gtest_main)

# If you use NTAPI, you might need ntdll
target_link_libraries(veilhook_tests PRIVATE ntdll)
