# veilhook

Windows x64 in-process hooking library (C++23). VEH hub, hardware breakpoints, inline/mid detours, shadow VMT, page-guard and phantom (view-remap) hooks. Nt* memory/thread ops go through indirect syscalls resolved at runtime.

Inject a DLL built against veilhook with [syail](https://github.com/LucPrusPPi/syail) if you need manual-map into another process. veilhook itself does not inject.

## What is in here

| Piece | Notes |
|-------|--------|
| `veh::Hub` | One vectored handler; HWBP/guard register filters here |
| `hwbp::Manager` | Dr0-Dr3 per thread, callbacks via VEH |
| `mem::CaveAlloc` | Module caves or near pages for trampolines |
| `hook::Inline` / `Mid` | Suspend threads, patch, asmjit trampolines, Zydis reloc |
| `hook::Vmt` | Shadow vtable copy in cave memory |
| `hook::Guard` | PAGE_GUARD + VEH |
| `hook::Phantom` | Section remap so the original page stays clean in memory scans |
| `syscalls` | HalosGate-style SSN walk + asmjit indirect stubs |
| `analyzer` | Prologue scan, jmp chain chase, light anti-debug checks |

Fadec for fast length/decode; Zydis when we need proper relocation on stolen bytes.

## Build

Two ways to wire dependencies:

### Bundled (default)

Fadec submodule + Zydis/AsmJit/GTest from vcpkg manifest. Good for a standalone clone.

```bat
git submodule update --init --recursive
cmake -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
build\Release\veilhook_tests.exe
```

`vcpkg.json` pulls zydis, asmjit, gtest. Fadec lives in `3rdparty/fadec`.

### External deps

If you already build fadec / Zydis / AsmJit next to veilhook (or in a parent CMake project), skip the submodule and vcpkg manifest:

```bat
git clone https://github.com/LucPrusPPi/veilhook
cmake -B build -DVEILHOOK_BUNDLED_DEPS=OFF
cmake --build build --config Release
```

Your superbuild must expose these targets **before** `add_subdirectory(veilhook)`:

| Target | Role |
|--------|------|
| `fadec::fadec` or `fadec` | fast insn length/decode |
| `Zydis::Zydis` | reloc stolen bytes in trampolines |
| `asmjit::asmjit` | trampoline codegen |

Example parent `CMakeLists.txt`:

```cmake
add_subdirectory(../fadec)
find_package(zydis CONFIG REQUIRED)
find_package(asmjit CONFIG REQUIRED)

add_subdirectory(../veilhook)  # with -DVEILHOOK_BUNDLED_DEPS=OFF
```

No vcpkg toolchain needed for external mode. Use `-DVEILHOOK_BUILD_TESTS=OFF` if you do not want GTest.

## Minimal usage

```cpp
#include <veilhook/veilhook.hpp>

// inline detour
veilhook::hook::Inline hook(
    reinterpret_cast<uintptr_t>(&target_fn),
    reinterpret_cast<uintptr_t>(&my_detour));
hook.install();
// ...
hook.uninstall();

// HWBP on current thread
veilhook::hwbp::Manager::get().set_for_current_thread(
    addr, veilhook::hwbp::Type::Execute, veilhook::hwbp::Length::Len1,
    [](PEXCEPTION_POINTERS ep) { /* ... */ return; });
```

Call `veilhook::syscalls::init()` once early if you rely on Nt* wrappers (hooks do this internally on install paths).

## License

Attribution Required - see [LICENSE](LICENSE) and [NOTICE](NOTICE). Not MIT.

## Related

- [syail](https://github.com/LucPrusPPi/syail) - manual-map injector (use this to load your veilhook DLL)
- [vecasm](https://github.com/LucPrusPPi/vecasm) - unrelated, same author
