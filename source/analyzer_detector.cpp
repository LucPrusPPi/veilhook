#include <veilhook/analyzer/detector.hpp>
#include <veilhook/syscalls.hpp>
#include <tlhelp32.h>

namespace veilhook::analyzer {

DetectionResult Detector::check_memory(uintptr_t target_function) {
    if (!target_function) return {false, HookType::None, 0};

    const uint8_t* code = reinterpret_cast<const uint8_t*>(target_function);

    // 1. Check for INT 3 (Software Breakpoint)
    if (code[0] == 0xCC) {
        return {true, HookType::SoftwareInt3, 0};
    }

    // 2. Check for Near JMP (E9 rel32)
    if (code[0] == 0xE9) {
        int32_t rel_offset = *reinterpret_cast<const int32_t*>(code + 1);
        uintptr_t destination = target_function + 5 + rel_offset;
        return {true, HookType::InlineNearJmp, destination};
    }

    // 3. Check for Far JMP (FF 25 [rel32])
    if (code[0] == 0xFF && code[1] == 0x25) {
        int32_t rel_offset = *reinterpret_cast<const int32_t*>(code + 2);
        uintptr_t ptr_address = target_function + 6 + rel_offset;
        uintptr_t destination = *reinterpret_cast<const uintptr_t*>(ptr_address);
        return {true, HookType::InlineFarJmp, destination};
    }

    return {false, HookType::None, 0};
}

DetectionResult Detector::check_hwbp_current_thread(uintptr_t target_function) {
    return check_hwbp(GetCurrentThread(), target_function);
}

DetectionResult Detector::check_hwbp(HANDLE thread, uintptr_t target_function) {
    if (!target_function) return {false, HookType::None, 0};

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    // Use stealth syscall to bypass any hooks on GetThreadContext
    if (syscalls::nt_get_context_thread(thread, &ctx) != syscalls::STATUS_SUCCESS) {
        return {false, HookType::Unknown, 0};
    }

    // Check if the address is present in any Dr register AND the corresponding local enable bit is set in Dr7
    if (ctx.Dr0 == target_function && (ctx.Dr7 & (1ull << 0))) {
        return {true, HookType::HardwareDr0, 0};
    }
    if (ctx.Dr1 == target_function && (ctx.Dr7 & (1ull << 2))) {
        return {true, HookType::HardwareDr1, 0};
    }
    if (ctx.Dr2 == target_function && (ctx.Dr7 & (1ull << 4))) {
        return {true, HookType::HardwareDr2, 0};
    }
    if (ctx.Dr3 == target_function && (ctx.Dr7 & (1ull << 6))) {
        return {true, HookType::HardwareDr3, 0};
    }

    return {false, HookType::None, 0};
}

} // namespace veilhook::analyzer
