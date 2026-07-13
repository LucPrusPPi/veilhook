#include <veilhook/analyzer/prologue.hpp>
#include <veilhook/decode.hpp>
#include <cstring>

namespace veilhook::analyzer {

std::vector<InstructionInfo> Prologue::analyze(uintptr_t target_function, size_t max_bytes) {
    std::vector<InstructionInfo> instructions;
    if (!target_function) {
        return instructions;
    }

    decode::InstructionView view;
    auto decoded = decode::decode_range(view, reinterpret_cast<uint8_t*>(target_function), max_bytes);

    for (const auto& inst : decoded) {
        InstructionInfo info{};
        info.address = reinterpret_cast<uintptr_t>(inst.address);
        info.length = inst.length;
        std::memcpy(info.bytes, inst.address, inst.length);
        info.is_branch = inst.is_branch;
        info.is_call = inst.is_call;
        info.branch_target = inst.absolute_target;
        instructions.push_back(info);
    }

    return instructions;
}

std::optional<size_t> Prologue::find_safe_hook_boundary(uintptr_t target_function, size_t required_bytes) {
    decode::InstructionView view;
    const size_t length = view.get_boundary_length(reinterpret_cast<uint8_t*>(target_function), required_bytes);
    if (length >= required_bytes) {
        return length;
    }
    return std::nullopt;
}

uintptr_t Prologue::resolve_jmp_chain(uintptr_t target_function, int max_depth) {
    decode::InstructionView view;
    return decode::follow_jump_chain(view, target_function, max_depth);
}

} // namespace veilhook::analyzer
