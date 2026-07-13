#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

#include <Zydis/Decoder.h>
#include <asmjit/x86.h>

namespace veilhook::reloc {

enum class Status {
    Ok,
    DecodeFailed,
    UnsupportedInstruction,
    DispOverflow,
};

// Maps one source instruction in the stolen prologue to its emitted trampoline bytes.
struct InstSite {
    size_t source_offset = 0;
    size_t source_length = 0;
    size_t emit_offset = 0;
    size_t emit_length = 0;
};

// Deduplicated FF25 jump slots emitted after the relocated body + continuation.
struct BranchSlotTable {
    void reset() {
        slots_.clear();
        order_.clear();
    }

    asmjit::Label slot_for(asmjit::x86::Assembler& a, uint64_t destination);
    void emit_jump(asmjit::x86::Assembler& a, uint64_t destination) const;
    void emit_data(asmjit::x86::Assembler& a) const;
    bool empty() const { return order_.empty(); }

private:
    std::unordered_map<uint64_t, asmjit::Label> slots_;
    std::vector<std::pair<asmjit::Label, uint64_t>> order_;
};

// push rax; mov rax, dest; xchg [rsp], rax; ret — no caller-visible register clobber.
void emit_absolute_jump(asmjit::x86::Assembler& a, uint64_t destination);

// push rax/r11 around an indirect call so both survive the synthesized branch.
void emit_absolute_call(asmjit::x86::Assembler& a, uint64_t destination);

// Relocate stolen prologue bytes into an asmjit code buffer.
// stolen_runtime_base is the original in-image address of stolen[0].
// emit_runtime_base is where the relocated code will execute (trampoline address).
// sites_out, when non-null, receives per-instruction source/emit offsets for RIP fixups.
// branch_slots_out collects FF25 slots; call emit_branch_slot_data() after continuation.
// Does not append the continuation jump; callers add that after this returns.
Status emit_stolen_range(
    asmjit::x86::Assembler& a,
    ZydisDecoder& decoder,
    const uint8_t* stolen,
    size_t stolen_size,
    uint64_t stolen_runtime_base,
    uint64_t emit_runtime_base,
    std::vector<InstSite>* sites_out = nullptr,
    BranchSlotTable* branch_slots_out = nullptr);

// Emit deduplicated slot payloads (call after continuation jump).
void emit_branch_slot_data(asmjit::x86::Assembler& a, BranchSlotTable& table);

// Map a runtime RIP inside the stolen window to the corresponding trampoline address.
uint64_t translate_runtime_ip(
    uint64_t runtime_rip,
    uint64_t stolen_runtime_base,
    size_t stolen_size,
    uint64_t trampoline_runtime_base,
    const std::vector<InstSite>& sites);

// Inverse of translate_runtime_ip for uninstall / trampoline -> original mapping.
uint64_t translate_emit_ip_to_source(
    uint64_t runtime_rip,
    uint64_t emit_runtime_base,
    size_t emit_size,
    uint64_t stolen_runtime_base,
    const std::vector<InstSite>& sites);

} // namespace veilhook::reloc
