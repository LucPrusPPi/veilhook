#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

namespace veilhook::thread_patch {

// Suspend other threads in this process, fix RIP if it sits inside [target, target+patch_size),
// apply patch_bytes at target. trampoline is used for RIP migration offset (may be null on restore).
bool suspend_others_and_patch(
    uintptr_t target,
    size_t patch_size,
    const std::vector<uint8_t>& patch_bytes,
    uint8_t* trampoline);

} // namespace veilhook::thread_patch
