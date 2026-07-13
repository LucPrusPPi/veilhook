# Resolves fadec / Zydis / AsmJit for veilhook.
# Bundled (default): vendored fadec submodule + find_package for zydis/asmjit (vcpkg manifest).
# External: parent project must expose CMake targets before add_subdirectory(veilhook).

macro(_veilhook_require_target _out_var _primary _fallback)
    if(TARGET ${_primary})
        set(${_out_var} ${_primary})
    elseif(_fallback AND TARGET ${_fallback})
        set(${_out_var} ${_fallback})
    elseif(_fallback)
        message(FATAL_ERROR
            "veilhook: missing target '${_primary}' or '${_fallback}'. "
            "Set VEILHOOK_BUNDLED_DEPS=ON or add the dependency before veilhook.")
    else()
        message(FATAL_ERROR
            "veilhook: missing target '${_primary}'. "
            "Set VEILHOOK_BUNDLED_DEPS=ON or add the dependency before veilhook.")
    endif()
endmacro()

function(veilhook_setup_dependencies)
    if(VEILHOOK_BUNDLED_DEPS)
        if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/fadec/CMakeLists.txt")
            message(FATAL_ERROR
                "VEILHOOK_BUNDLED_DEPS=ON but 3rdparty/fadec is missing. "
                "Run: git submodule update --init --recursive")
        endif()

        add_subdirectory(3rdparty/fadec)
        _veilhook_require_target(_fadec fadec fadec::fadec)

        if(NOT TARGET Zydis::Zydis)
            find_package(zydis CONFIG REQUIRED)
        endif()
        _veilhook_require_target(_zydis Zydis::Zydis "")

        if(NOT TARGET asmjit::asmjit)
            find_package(asmjit CONFIG REQUIRED)
        endif()
        _veilhook_require_target(_asmjit asmjit::asmjit "")
    else()
        _veilhook_require_target(_fadec fadec::fadec fadec)
        _veilhook_require_target(_zydis Zydis::Zydis "")
        _veilhook_require_target(_asmjit asmjit::asmjit "")
    endif()

    set(VEILHOOK_FADEC_TARGET ${_fadec} PARENT_SCOPE)
    set(VEILHOOK_ZYDIS_TARGET ${_zydis} PARENT_SCOPE)
    set(VEILHOOK_ASMJIT_TARGET ${_asmjit} PARENT_SCOPE)
endfunction()

function(veilhook_setup_gtest)
    if(NOT VEILHOOK_BUILD_TESTS)
        return()
    endif()

    if(NOT TARGET GTest::gtest)
        find_package(GTest CONFIG REQUIRED)
    endif()
endfunction()
