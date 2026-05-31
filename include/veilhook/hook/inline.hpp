#pragma once

#include <windows.h>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

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
    uintptr_t destination_;
    uint8_t* original_callable_ = nullptr;
    
    // Memory tracking
    uint8_t* trampoline_ = nullptr;
    size_t trampoline_size_ = 0;
    
    // Patch window tracking
    std::vector<uint8_t> original_bytes_;
    size_t patch_size_ = 0;
    bool is_installed_ = false;

    bool suspend_threads_and_patch(const std::vector<uint8_t>& patch_bytes);
};

} // namespace veilhook::hook
