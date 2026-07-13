#pragma once

#include <cstdint>
#include <vector>
#include <span>

extern "C" {
#include <fadec.h>
}
#include <Zydis/Zydis.h>

namespace veilhook::decode {

enum class EntryPatch {
    None,
    Int3,
    NearJmp,
    FarJmp
};

struct EntryPatchInfo {
    EntryPatch kind = EntryPatch::None;
    uintptr_t destination = 0;
};

struct Instruction {
    uint8_t* address;
    size_t length;
    bool is_branch;
    bool is_call;
    bool is_ret;
    uintptr_t absolute_target; // if branch/call
    
    // Raw bytes
    std::span<uint8_t> bytes() const {
        return {address, length};
    }
};

class InstructionView {
public:
    InstructionView() {
        ZydisDecoderInit(&zydis_decoder_, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    }

    // fadec: quick length + branch target
    Instruction decode_fast(uint8_t* address) {
        FdInstr fd_instr;
        int len = fd_decode(address, 15, 64, reinterpret_cast<uintptr_t>(address), &fd_instr);
        
        Instruction inst{};
        inst.address = address;
        inst.length = (len > 0) ? len : 0;
        
        uint16_t type = FD_TYPE(&fd_instr);
        inst.is_branch = (type == FDI_JMP || (type >= FDI_JA && type <= FDI_JZ));
        inst.is_call = (type == FDI_CALL);
        inst.is_ret = (type == FDI_RET || type == FDI_RETF);

        if (inst.is_branch || inst.is_call) {
            if (len >= 5 && (address[0] == 0xE9 || address[0] == 0xE8)) {
                const int32_t rel = *reinterpret_cast<const int32_t*>(address + 1);
                inst.absolute_target = reinterpret_cast<uintptr_t>(address) + 5 + rel;
            } else if (len >= 6 && address[0] == 0xFF && address[1] == 0x25) {
                const int32_t rel = *reinterpret_cast<const int32_t*>(address + 2);
                const uintptr_t ptr_address = reinterpret_cast<uintptr_t>(address) + 6 + rel;
                inst.absolute_target = *reinterpret_cast<const uintptr_t*>(ptr_address);
            } else if (FD_OP_TYPE(&fd_instr, 0) == FD_OT_OFF || FD_OP_TYPE(&fd_instr, 0) == FD_OT_IMM) {
                inst.absolute_target = reinterpret_cast<uintptr_t>(address) + len + FD_OP_IMM(&fd_instr, 0);
            }
        }
        
        return inst;
    }

    // zydis: reloc stolen instructions into trampoline
    ZydisDecodedInstruction decode_advanced(uint8_t* address) {
        ZydisDecodedInstruction instruction;
        ZydisDecoderDecodeInstruction(&zydis_decoder_, nullptr, address, 15, &instruction);
        return instruction;
    }

    // bytes needed to place a 5-byte near jmp
    size_t get_boundary_length(uint8_t* address, size_t required_length) {
        size_t total_len = 0;
        uint8_t* current = address;
        while (total_len < required_length) {
            auto inst = decode_fast(current);
            if (inst.length == 0) break;
            total_len += inst.length;
            current += inst.length;
        }
        return total_len;
    }

    ZydisDecoder& zydis_decoder() { return zydis_decoder_; }

private:
    ZydisDecoder zydis_decoder_;
};

std::vector<Instruction> decode_range(InstructionView& view, uint8_t* start, size_t max_bytes);
EntryPatchInfo detect_entry_patch(InstructionView& view, uintptr_t address);
uintptr_t follow_jump_chain(InstructionView& view, uintptr_t start, int max_depth);

} // namespace veilhook::decode
