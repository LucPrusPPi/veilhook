#include <veilhook/hook/inline.hpp>
#include <veilhook/cave_alloc.hpp>
#include <veilhook/decode.hpp>
#include <asmjit/asmjit.h>
#include <tlhelp32.h>
#include <stdexcept>
#include <cstring>
#include <iostream>

namespace veilhook::hook {

// Private suspension logic shared between inline and mid
static bool suspend_threads_and_patch(uintptr_t target, size_t patch_size, const std::vector<uint8_t>& patch_bytes, uint8_t* trampoline) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    DWORD current_process_id = GetCurrentProcessId();
    DWORD current_thread_id = GetCurrentThreadId();
    std::vector<HANDLE> suspended_threads;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

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

    DWORD old_protect;
    bool success = false;
    if (VirtualProtect(reinterpret_cast<void*>(target), patch_bytes.size(), PAGE_EXECUTE_READWRITE, &old_protect)) {
        for (HANDLE hThread : suspended_threads) {
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL;
            if (GetThreadContext(hThread, &ctx)) {
                if (ctx.Rip >= target && ctx.Rip < target + patch_size) {
                    size_t offset = ctx.Rip - target;
                    ctx.Rip = reinterpret_cast<uintptr_t>(trampoline) + offset;
                    SetThreadContext(hThread, &ctx);
                }
            }
        }

        std::memcpy(reinterpret_cast<void*>(target), patch_bytes.data(), patch_bytes.size());
        VirtualProtect(reinterpret_cast<void*>(target), patch_bytes.size(), old_protect, &old_protect);
        success = true;
    }

    for (HANDLE hThread : suspended_threads) {
        ResumeThread(hThread);
        CloseHandle(hThread);
    }

    return success;
}

Inline::Inline(uintptr_t target, uintptr_t destination)
    : target_(target), destination_(destination) {}

Inline::~Inline() {
    uninstall();
}

bool Inline::install() {
    if (is_installed_) return true;

    decode::InstructionView decoder;
    
    // Find boundary size to fit a near JMP (5 bytes)
    patch_size_ = decoder.get_boundary_length(reinterpret_cast<uint8_t*>(target_), 5);
    if (patch_size_ == 0) return false;

    original_bytes_.resize(patch_size_);
    std::memcpy(original_bytes_.data(), reinterpret_cast<void*>(target_), patch_size_);

    // We over-allocate the trampoline to ensure we have enough space for the re-encoded instructions
    trampoline_size_ = patch_size_ + 128; 
    trampoline_ = mem::CaveAlloc::get().allocate(target_, trampoline_size_);
    
    if (!trampoline_) return false;

    // Use AsmJit to assemble the trampoline directly at the allocated base
    asmjit::JitRuntime rt;
    asmjit::CodeHolder code;
    code.init(rt.environment(), reinterpret_cast<uint64_t>(trampoline_));
    asmjit::x86::Assembler a(&code);

    using namespace asmjit::x86;

    // Save the pointer to the original callable trampoline
    original_callable_ = trampoline_;

    // 1. Process and emit original instructions
    uint8_t* current = original_bytes_.data();
    size_t processed = 0;

    while (processed < patch_size_) {
        ZydisDecodedInstruction zydis_inst = decoder.decode_advanced(current);
        if (zydis_inst.length == 0) break; 

        // VERY BASIC RIP FIXUP for branching (Jmp/Call).
        if (zydis_inst.meta.category == ZYDIS_CATEGORY_COND_BR || 
            zydis_inst.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
            zydis_inst.meta.category == ZYDIS_CATEGORY_CALL) {
            
            const ZydisDecodedOperand* op = nullptr;
            for (int i = 0; i < zydis_inst.operand_count; ++i) {
                // New Zydis interface requires accessing operands array separately if using the combined struct,
                // or fetching them using ZydisDecoderDecodeOperands.
                // Assuming standard Zydis 4.x decode, operands are in ZydisDecodedInstruction if decoded correctly,
                // but actually the new API separates instruction and operands.
                // We will decode operands properly here:
                ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
                ZydisDecoderDecodeOperands(&decoder.zydis_decoder(), nullptr, &zydis_inst, operands, zydis_inst.operand_count);
                
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative) {
                    op = &operands[i];
                    
                    uint64_t absolute_target = 0;
                    ZydisCalcAbsoluteAddress(&zydis_inst, op, static_cast<uint64_t>(target_ + processed), &absolute_target);
                    
                    if (zydis_inst.meta.category == ZYDIS_CATEGORY_CALL) {
                        a.mov(rax, absolute_target);
                        a.call(rax);
                    } else if (zydis_inst.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
                        a.mov(rax, absolute_target);
                        a.jmp(rax);
                    } else {
                        a.embed(current, zydis_inst.length);
                    }
                    break;
                }
            }

            if (!op) {
                a.embed(current, zydis_inst.length);
            }
        } else {
            a.embed(current, zydis_inst.length);
        }

        current += zydis_inst.length;
        processed += zydis_inst.length;
    }

    // 2. Add the jump back to the original function
    a.mov(rax, target_ + patch_size_);
    a.jmp(rax);

    // Extract the generated code into the trampoline
    asmjit::CodeBuffer& buffer = code.sectionById(0)->buffer();
    
    if (buffer.size() > trampoline_size_) {
        // This shouldn't happen with our buffer padding, but safe fallback
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        return false;
    }

    // Write actual trampoline payload
    std::memcpy(trampoline_, buffer.data(), buffer.size());

    // Prepare the patch (JMP rel32)
    std::vector<uint8_t> patch(patch_size_, 0x90); // NOP padding
    
    int64_t rel_disp = static_cast<int64_t>(destination_) - static_cast<int64_t>(target_ + 5);
    if (std::abs(rel_disp) <= 0x7FFFFFFF) {
        patch[0] = 0xE9; // JMP rel32
        *reinterpret_cast<int32_t*>(&patch[1]) = static_cast<int32_t>(rel_disp);
    } else {
        // Fallback to far jump via an intermediate relay or direct inline if 14 bytes available
        if (patch_size_ >= 14) {
            patch[0] = 0xFF; patch[1] = 0x25; // jmp qword ptr [rip]
            *reinterpret_cast<int32_t*>(&patch[2]) = 0;
            *reinterpret_cast<uint64_t*>(&patch[6]) = destination_;
        } else {
            // No room for near or far jump directly, would need a relay. Out of MVP scope.
            mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
            trampoline_ = nullptr;
            return false;
        }
    }

    // Transactionally apply the patch and fix thread contexts
    if (suspend_threads_and_patch(target_, patch_size_, patch, trampoline_)) {
        is_installed_ = true;
        return true;
    }

    mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
    trampoline_ = nullptr;
    return false;
}

bool Inline::uninstall() {
    if (!is_installed_) return true;

    // Passing `trampoline_` doesn't make sense for uninstalls, we are restoring bytes.
    // Our shared helper expects 4 args, for restore we pass nullptr or ignore rip migration
    if (suspend_threads_and_patch(target_, patch_size_, original_bytes_, nullptr)) {
        is_installed_ = false;
        mem::CaveAlloc::get().deallocate(trampoline_, trampoline_size_);
        trampoline_ = nullptr;
        return true;
    }
    
    return false;
}

} // namespace veilhook::hook
