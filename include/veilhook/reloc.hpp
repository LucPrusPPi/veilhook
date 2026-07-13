#pragma once

#include <cstddef>
#include <cstdint>

#include <Zydis/Decoder.h>
#include <asmjit/x86.h>

namespace veilhook::reloc {

enum class Status {
    Ok,
    DecodeFailed,
    UnsupportedInstruction,
    DispOverflow,
};

// Relocate stolen prologue bytes into an asmjit code buffer.
// stolen_runtime_base is the original in-image address of stolen[0].
// emit_runtime_base is where the relocated code will execute (trampoline address).
// Does not append the continuation jmp; callers add that after this returns.
Status emit_stolen_range(
    asmjit::x86::Assembler& a,
    ZydisDecoder& decoder,
    const uint8_t* stolen,
    size_t stolen_size,
    uint64_t stolen_runtime_base,
    uint64_t emit_runtime_base);

} // namespace veilhook::reloc
