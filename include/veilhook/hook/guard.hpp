#pragma once

#include <windows.h>
#include <cstdint>
#include <functional>
#include <vector>
#include <vector>
#include <shared_mutex>
#include <memory>
#include <veilhook/veh_hub.hpp>

namespace veilhook::hook {

// Context structure mirroring standard x64 Context control and integer registers
struct GuardContext {
    uint64_t Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    uint64_t R8, R9, R10, R11, R12, R13, R14, R15;
    uint64_t RFlags, Rip;
};

using GuardCallback = std::function<void(GuardContext&)>;

class Guard {
public:
    // Hooks a function using PAGE_GUARD memory protection.
    // Extremely stealthy: no bytes are patched, no debug registers used.
    Guard(uintptr_t target, GuardCallback callback);
    ~Guard();

    bool install();
    bool uninstall();

private:
    uintptr_t target_;
    GuardCallback callback_;
    bool is_installed_ = false;

    // We store the original memory protection to restore it
    ULONG original_protection_ = 0;
    
    // Page aligned address and size
    uintptr_t page_base_ = 0;
    size_t page_size_ = 0;

    // VEH Subscription
    std::unique_ptr<veilhook::veh::Subscription> veh_guard_sub_;
    std::unique_ptr<veilhook::veh::Subscription> veh_step_sub_;

    bool handle_guard_page(PEXCEPTION_POINTERS ep);
    bool handle_single_step(PEXCEPTION_POINTERS ep);
};

} // namespace veilhook::hook
