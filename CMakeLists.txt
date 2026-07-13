cmake_minimum_required(VERSION 3.25)
project(veilhook VERSION 0.1.0 LANGUAGES CXX)

# Per-build junk padding sizes (see mutation_seed.hpp.in)
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

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ON  = vendored fadec submodule + zydis/asmjit via vcpkg manifest (default, clone-and-build).
# OFF = fadec::fadec (or fadec), Zydis::Zydis, asmjit::asmjit must already exist
#       (e.g. sibling add_subdirectory in your own superbuild).
option(VEILHOOK_BUNDLED_DEPS "Use vendored fadec and fetch zydis/asmjit via vcpkg" ON)
option(VEILHOOK_BUILD_TESTS "Build veilhook_tests (needs GTest)" ON)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/VeilhookDeps.cmake)
veilhook_setup_dependencies()

add_library(veilhook STATIC)

target_sources(veilhook PRIVATE
    source/decode.cpp
    source/reloc.cpp
    source/thread_patch.cpp
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
    source/hook_ud2.cpp
)

target_include_directories(veilhook PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(veilhook
    PUBLIC ${VEILHOOK_FADEC_TARGET}
    PUBLIC ${VEILHOOK_ZYDIS_TARGET}
    PRIVATE ${VEILHOOK_ASMJIT_TARGET}
)

if(MSVC)
    target_compile_options(veilhook PRIVATE /W4 /WX)
endif()

if(VEILHOOK_BUILD_TESTS)
    veilhook_setup_gtest()

    add_executable(veilhook_tests
        tests/test_main.cpp
        tests/test_hooks.cpp
        tests/test_detector.cpp
    )
    target_link_libraries(veilhook_tests PRIVATE
        veilhook
        GTest::gtest
        GTest::gtest_main
        ntdll
    )
endif()
