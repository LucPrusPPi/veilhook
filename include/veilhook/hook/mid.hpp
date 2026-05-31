#pragma once

#include <windows.h>
#include <cstdint>
#include <functional>

namespace veilhook::hook {

// Context representing the CPU state at the point of the mid-hook
struct Context {
    uint64_t Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
    uint64_t R8, R9, R10, R11, R12, R13, R14, R15;
    uint64_t RFlags;
    uint64_t Rip;
    
    // Future expansion: XMM registers (requires alignment)
};

using MidCallback = std::function<void(Context&)>;

class Mid {
public:
    // `target` should be the address of an instruction boundary where the hook is placed.
    // The framework will replace that instruction (and subsequent ones if needed to fit the jump).
    Mid(uintptr_t target, MidCallback callback);
    ~Mid();

    bool install();
    bool uninstall();

private:
    uintptr_t target_;
    MidCallback callback_;
    bool is_installed_ = false;

    uint8_t* trampoline_ = nullptr;
    size_t trampoline_size_ = 0;
    
    // Needs static/global registry mapping trampoline back to Mid instance 
    // because the shellcode can only easily call a global function pointer.
    static void __stdcall dispatch_callback(Context* ctx, Mid* instance);
};

} // namespace veilhook::hook
