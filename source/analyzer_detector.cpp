#include <veilhook/analyzer/detector.hpp>
#include <veilhook/decode.hpp>
#include <veilhook/syscalls.hpp>

namespace veilhook::analyzer {

DetectionResult Detector::check_memory(uintptr_t target_function) {
    if (!target_function) {
        return {false, HookType::None, 0};
    }

    decode::InstructionView view;
    const decode::EntryPatchInfo patch = decode::detect_entry_patch(view, target_function);

    switch (patch.kind) {
    case decode::EntryPatch::Int3:
        return {true, HookType::SoftwareInt3, 0};
    case decode::EntryPatch::NearJmp:
        return {true, HookType::InlineNearJmp, patch.destination};
    case decode::EntryPatch::FarJmp:
        return {true, HookType::InlineFarJmp, patch.destination};
    default:
        return {false, HookType::None, 0};
    }
}

DetectionResult Detector::check_hwbp_current_thread(uintptr_t target_function) {
    return check_hwbp(GetCurrentThread(), target_function);
}

DetectionResult Detector::check_hwbp(HANDLE thread, uintptr_t target_function) {
    if (!target_function) {
        return {false, HookType::None, 0};
    }

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (syscalls::nt_get_context_thread(thread, &ctx) != syscalls::STATUS_SUCCESS) {
        return {false, HookType::Unknown, 0};
    }

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
