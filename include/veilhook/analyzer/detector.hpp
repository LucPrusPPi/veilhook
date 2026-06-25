#pragma once

#include <cstdint>
#include <optional>
#include <vector>
#include <windows.h>

namespace veilhook::analyzer {

// Represents the type of hook detected
enum class HookType {
    None,
    InlineNearJmp,  // E9 rel32
    InlineFarJmp,   // FF 25 [rel32]
    SoftwareInt3,   // CC
    HardwareDr0,
    HardwareDr1,
    HardwareDr2,
    HardwareDr3,
    Unknown
};

struct DetectionResult {
    bool is_hooked;
    HookType type;
    uintptr_t destination; // Absolute address where the hook jumps to (if applicable)
};

class Detector {
public:
    // Scans a specific function prologue in memory for software hooks (E9, FF 25, CC)
    static DetectionResult check_memory(uintptr_t target_function);

    // Checks the current thread's debug registers for Hardware Breakpoints
    static DetectionResult check_hwbp_current_thread(uintptr_t target_function);
    
    // Checks a specific thread's debug registers for Hardware Breakpoints
    static DetectionResult check_hwbp(HANDLE thread, uintptr_t target_function);
};

} // namespace veilhook::analyzer
