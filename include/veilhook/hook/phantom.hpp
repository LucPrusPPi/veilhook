#pragma once

#include <windows.h>
#include <cstdint>
#include <vector>

#include <veilhook/hook/status.hpp>
#include <veilhook/obfuscation.hpp>
#include <veilhook/reloc.hpp>

namespace veilhook::hook {

class Phantom {
public:
    // Creates a high-speed, invisible hook using View Remapping (Phantom Hooking)
    // - Replaces the underlying physical page with a modified copy
    // - Bypasses EDRs monitoring VirtualProtect
    // - Warning: Bypasses execution checks, but a direct read of this page by AC will see the patch.
    Phantom(uintptr_t target, uintptr_t destination);
    ~Phantom();

    bool install();
    bool uninstall();
    InstallStatus last_status() const { return last_status_; }

    template<typename T>
    T get_original() const {
        return reinterpret_cast<T>(original_callable_);
    }

private:
    uintptr_t target_;
    VEIL_STRUCT_PADDING_1
    uintptr_t destination_;
    VEIL_STRUCT_PADDING_2
    bool is_installed_ = false;
    InstallStatus last_status_ = InstallStatus::Ok;

    // Phantom Section specific data
    HANDLE h_section_ = nullptr;
    VEIL_STRUCT_PADDING_3
    PVOID p_view_ = nullptr;
    size_t patch_size_ = 0;
    size_t page_size_ = 0;

    // We store the original memory block pointer to restore the view
    // Note: To truly restore, we'd need to re-map the original DLL view, but
    // usually we just write back the original bytes to our custom view during uninstall.
    std::vector<uint8_t> original_bytes_;
    std::vector<reloc::InstSite> reloc_sites_;
    uint8_t* trampoline_ = nullptr;
    VEIL_STRUCT_PADDING_1
    size_t trampoline_size_ = 0;
    void* original_callable_ = nullptr;
};

} // namespace veilhook::hook
