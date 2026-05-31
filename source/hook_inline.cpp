#include <veilhook/hook/inline.hpp>
#include <veilhook/cave_alloc.hpp>
#include <veilhook/decode.hpp>
#include <tlhelp32.h>
#include <stdexcept>

namespace veilhook::hook {

Inline::Inline(uintptr_t target, uintptr_t destination)
    : target_(target), destination_(destination) {}

Inline::~Inline() {
    uninstall();
}

bool Inline::suspend_threads_and_patch(const std::vector<uint8_t>& patch_bytes) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    DWORD current_process_id = GetCurrentProcessId();
    DWORD current_thread_id = GetCurrentThreadId();
    std::vector<HANDLE> suspended_threads;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

    // Suspend threads
    if (Thread32First(snapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == current_process_id && te32.th32ThreadID != current_thread_id) {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te32.th32ThreadID);
                if (hThread) {
                    SuspendThread(hThread);
                    suspended_threads.push_back(hThread);
                }
            }
        } while (Thread32Next(snapshot, &te32));
    }
    CloseHandle(snapshot);

    // Apply Patch
    DWORD old_protect;
    bool success = false;
    if (VirtualProtect(reinterpret_cast<void*>(target_), patch_bytes.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
        
        // Before patching, fix any threads that might be executing in the patch window
        for (HANDLE hThread : suspended_threads) {
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(hThread, &ctx)) {
                if (ctx.Rip >= target_ && ctx.Rip < target_ + patch_size_) {
                    // Thread is caught in the crossfire!
                    // Fix RIP to point to the trampoline's equivalent offset
                    size_t offset = ctx.Rip - target_;
                    ctx.Rip = reinterpret_cast<uintptr_t>(trampoline_) + offset;
                    SetThreadContext(hThread, &ctx);
                }
            }
        }

        // Batch write the patch
        std::memcpy(reinterpret_cast<void*>(target_), patch_bytes.data(), patch_bytes.size());
        
        VirtualProtect(reinterpret_cast<void*>(target_), patch_bytes.size(), old_protect, &old_protect);
        success = true;
    }

    // Resume threads
    for (HANDLE hThread : suspended_threads) {
        ResumeThread(hThread);
        CloseHandle(hThread);
    }

    return success;
}

bool Inline::install() {
    if (is_installed_) return true;

    decode::InstructionView decoder;
    
    // We need at least 5 bytes for a rel32 jump, or 14 bytes for an absolute jump
    // We'll aim for 5 bytes assuming CaveAlloc gives us near memory.
    patch_size_ = decoder.get_boundary_length(reinterpret_cast<uint8_t*>(target_), 5);
    
    if (patch_size_ == 0) return false;

    // Allocate trampoline (+5 for jmp back)
    trampoline_size_ = patch_size_ + 14; // Over-allocate slightly for potential far jump back
    trampoline_ = mem::CaveAlloc::get().allocate(target_, trampoline_size_);
    
    if (!trampoline_) return false;

    original_bytes_.resize(patch_size_);
    std::memcpy(original_bytes_.data(), reinterpret_cast<void*>(target_), patch_size_);

    // Copy original prologue to trampoline
    std::memcpy(trampoline_, original_bytes_.data(), patch_size_);
    
    // Simplistic fixup for RIP-relative in the trampoline
    // A proper implementation would use Fadec/Zydis to fix up rip-relative displacements here.
    // For MVP, if it's rip-relative, we just blindly copy and hope it wasn't RIP-rel (or add fixups later).
    
    // Write jump back to target + patch_size
    uint8_t* jmp_back_addr = trampoline_ + patch_size_;
    uintptr_t return_target = target_ + patch_size_;
    
    // Write absolute jump back (mov rax, target; jmp rax) for simplicity
    jmp_back_addr[0] = 0x48; jmp_back_addr[1] = 0xB8; // mov rax, imm64
    *reinterpret_cast<uintptr_t*>(&jmp_back_addr[2]) = return_target;
    jmp_back_addr[10] = 0xFF; jmp_back_addr[11] = 0xE0; // jmp rax

    original_callable_ = trampoline_;

    // Prepare patch for original function
    std::vector<uint8_t> patch(patch_size_, 0x90); // Fill with NOPs
    
    int64_t rel_disp = destination_ - (target_ + 5);
    if (std::abs(rel_disp) <= 0x7FFFFFFF) {
        // Near jump
        patch[0] = 0xE9;
        *reinterpret_cast<int32_t*>(&patch[1]) = static_cast<int32_t>(rel_disp);
    } else {
        // We shouldn't hit this if the user uses a near trampoline, but if destination is far:
        // We'd need 14 bytes for a far jump, which might exceed patch_size_.
        // In a real framework, we'd use a relay trampoline allocated via CaveAlloc.
        // Assuming destination is a near trampoline for MVP inline hooking.
        return false;
    }

    if (suspend_threads_and_patch(patch)) {
        is_installed_ = true;
        return true;
    }

    mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
    trampoline_ = nullptr;
    return false;
}

bool Inline::uninstall() {
    if (!is_installed_) return true;

    if (suspend_threads_and_patch(original_bytes_)) {
        is_installed_ = false;
        
        // Note: we might want to delay free or keep it around to avoid crashing threads
        // that are currently executing the trampoline.
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        return true;
    }
    
    return false;
}

} // namespace veilhook::hook
