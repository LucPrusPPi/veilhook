#include <veilhook/hook/mid.hpp>
#include <veilhook/cave_alloc.hpp>
#include <veilhook/decode.hpp>
#include <veilhook/thread_patch.hpp>
#include <asmjit/asmjit.h>
#include <stdexcept>
#include <cstring>

namespace veilhook::hook {

Mid::Mid(uintptr_t target, MidCallback callback)
    : target_(target), callback_(std::move(callback)) {}

Mid::~Mid() {
    uninstall();
}

void __stdcall Mid::dispatch_callback(Context* ctx, Mid* instance) {
    if (instance && instance->callback_) {
        instance->callback_(*ctx);
    }
}

bool Mid::install() {
    if (is_installed_) return true;

    decode::InstructionView decoder;
    patch_size_ = decoder.get_boundary_length(reinterpret_cast<uint8_t*>(target_), 5);
    if (patch_size_ == 0) return false;

    original_bytes_.resize(patch_size_);
    std::memcpy(original_bytes_.data(), reinterpret_cast<void*>(target_), patch_size_);

    // Generate trampoline using AsmJit
    asmjit::JitRuntime rt;
    asmjit::CodeHolder code;
    code.init(rt.environment());
    asmjit::x86::Assembler a(&code);

    using namespace asmjit::x86;

    // --- Save Context ---
    // Save CPU state matching `struct Context` perfectly.
    // struct Context {
    //    Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi,
    //    R8...R15, RFlags, Rip
    // }
    
    // Push Rip (target_ address for context info, we pretend it's the current RIP)
    a.mov(rax, target_);
    a.push(rax);
    
    a.pushfq(); // RFlags
    
    a.push(r15); a.push(r14); a.push(r13); a.push(r12);
    a.push(r11); a.push(r10); a.push(r9);  a.push(r8);
    a.push(rdi); a.push(rsi); a.push(rbp); a.push(rsp);
    a.push(rbx); a.push(rdx); a.push(rcx); a.push(rax);

    // Arg1: Context*
    a.mov(rcx, rsp);
    // Arg2: Mid* instance
    a.mov(rdx, reinterpret_cast<uintptr_t>(this));

    // Stack alignment to 16-bytes
    a.mov(rbp, rsp);         
    a.and_(rsp, ~0xFull);    
    a.sub(rsp, 0x20);        

    // Call user callback via dispatch wrapper
    a.mov(rax, reinterpret_cast<uintptr_t>(&Mid::dispatch_callback));
    a.call(rax);

    // Restore stack alignment
    a.mov(rsp, rbp);

    // Pop Context
    a.pop(rax); a.pop(rcx); a.pop(rdx); a.pop(rbx);
    a.lea(rsp, ptr(rsp, 8)); // skip rsp
    a.pop(rbp); a.pop(rsi); a.pop(rdi);
    a.pop(r8);  a.pop(r9);  a.pop(r10); a.pop(r11);
    a.pop(r12); a.pop(r13); a.pop(r14); a.pop(r15);
    
    a.popfq();
    a.lea(rsp, ptr(rsp, 8)); // skip dummy Rip

    // --- Stolen Instructions ---
    // Embed the original bytes.
    // NOTE: This does not fix RIP-relative addressing for midline hook yet.
    // A robust midline hook would rewrite instructions using Zydis here.
    a.embed(original_bytes_.data(), original_bytes_.size());

    // Jump back to original function flow
    a.mov(rax, target_ + patch_size_);
    a.jmp(rax);

    // Extract assembled bytes
    asmjit::CodeBuffer& buffer = code.sectionById(0)->buffer();
    trampoline_size_ = buffer.size();

    trampoline_ = mem::CaveAlloc::get().allocate(target_, trampoline_size_);
    if (!trampoline_) return false;

    std::memcpy(trampoline_, buffer.data(), trampoline_size_);

    // Inject Jump at target
    std::vector<uint8_t> patch(patch_size_, 0x90);
    int64_t rel_disp = reinterpret_cast<uintptr_t>(trampoline_) - (target_ + 5);
    
    if (std::abs(rel_disp) <= 0x7FFFFFFF) {
        patch[0] = 0xE9;
        *reinterpret_cast<int32_t*>(&patch[1]) = static_cast<int32_t>(rel_disp);
    } else {
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        return false;
    }

    if (thread_patch::suspend_others_and_patch(target_, patch_size_, patch, trampoline_)) {
        is_installed_ = true;
        return true;
    }

    mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
    trampoline_ = nullptr;
    return false;
}

bool Mid::uninstall() {
    if (!is_installed_) return true;

    if (thread_patch::suspend_others_and_patch(target_, patch_size_, original_bytes_, nullptr)) {
        is_installed_ = false;
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        return true;
    }
    
    return false;
}

} // namespace veilhook::hook
