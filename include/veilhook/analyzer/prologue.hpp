#pragma once

#include <cstdint>
#include <optional>
#include <vector>

namespace veilhook::analyzer {

struct InstructionInfo {
    uintptr_t address;
    size_t length;
    uint8_t bytes[15]; // Max x86-64 instruction length
    bool is_branch;
    bool is_call;
    uintptr_t branch_target; // Absolute destination if it's a Jmp/Call
};

class Prologue {
public:
    // Analyzes the first `max_bytes` of a function and decodes them into InstructionInfo structures.
    static std::vector<InstructionInfo> analyze(uintptr_t target_function, size_t max_bytes = 32);

    // Determines if a full 5-byte hook can be safely placed at the target address.
    // Returns the exact number of bytes that must be overwritten (to avoid splitting instructions).
    static std::optional<size_t> find_safe_hook_boundary(uintptr_t target_function, size_t required_bytes = 5);

    // Chases consecutive JMPs (e.g. from EDR trampolines or compiler thunks)
    // to find the final actual code destination.
    // Follows both E9 (Near JMP) and FF 25 (Far JMP).
    // Stops after max_depth to prevent infinite loops.
    static uintptr_t resolve_jmp_chain(uintptr_t target_function, int max_depth = 10);
};

} // namespace veilhook::analyzer
