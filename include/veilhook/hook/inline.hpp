#pragma once

#include <windows.h>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

#include <veilhook/obfuscation.hpp>

namespace veilhook::hook {

class Inline {
public:
    Inline(uintptr_t target, uintptr_t destination);
    ~Inline();

    bool install();
    bool uninstall();

    template<typename T>
    T get_original() const {
        return reinterpret_cast<T>(original_callable_);
    }

private:
    uintptr_t target_;
    VEIL_STRUCT_PADDING_1
    uintptr_t destination_;
    VEIL_STRUCT_PADDING_2
    uint8_t* original_callable_ = nullptr;
    
    // Memory tracking
    uint8_t* trampoline_ = nullptr;
    VEIL_STRUCT_PADDING_3
    size_t trampoline_size_ = 0;
    
    // Patch window tracking
    std::vector<uint8_t> original_bytes_;
    size_t patch_size_ = 0;
    bool is_installed_ = false;

};

} // namespace veilhook::hook
