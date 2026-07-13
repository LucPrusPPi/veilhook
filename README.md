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

Needs MSVC, CMake 3.25+, vcpkg (Zydis, AsmJit, GTest). Fadec is vendored:

```bat
git submodule update --init --recursive
cmake --preset windows-release-vcpkg
cmake --build cmake-build/build/windows-release-vcpkg --config Release
ctest --test-dir cmake-build/build/windows-release-vcpkg -C Release
```

Or plain:

```bat
cmake -B build -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
build\Release\veilhook_tests.exe
```

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
    addr, veilhook::hwbp::Type::Execute, veilhook::hwbp::Length::Byte1,
    [](PEXCEPTION_POINTERS ep) { /* ... */ return; });
```

Call `veilhook::syscalls::init()` once early if you rely on Nt* wrappers (hooks do this internally on install paths).

## License

Attribution Required - see [LICENSE](LICENSE) and [NOTICE](NOTICE). Not MIT.

## Related

- [syail](https://github.com/LucPrusPPi/syail) - manual-map injector (use this to load your veilhook DLL)
- [vecasm](https://github.com/LucPrusPPi/vecasm) - unrelated, same author
