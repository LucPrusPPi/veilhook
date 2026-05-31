#pragma once

#include <cstdint>
#include <vector>
#include <span>

extern "C" {
#include <fadec.h>
}
#include <Zydis/Zydis.h>

namespace veilhook::decode {

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

    // Fast path using fadec
    Instruction decode_fast(uint8_t* address) {
        FdInstr fd_instr;
        int len = fd_decode(address, 15, 64, address, &fd_instr);
        
        Instruction inst{};
        inst.address = address;
        inst.length = (len > 0) ? len : 0;
        
        uint16_t type = FD_TYPE(&fd_instr);
        inst.is_branch = (type == FDI_JMP || (type >= FDI_JA && type <= FDI_JZ));
        inst.is_call = (type == FDI_CALL);
        inst.is_ret = (type == FDI_RET || type == FDI_RETF);

        if (inst.is_branch || inst.is_call) {
            if (fd_instr.operands[0].type == FD_OT_JMP) {
                 inst.absolute_target = reinterpret_cast<uintptr_t>(address) + len + fd_instr.operands[0].val;
            }
        }
        
        return inst;
    }

    // Advanced path using Zydis
    ZydisDecodedInstruction decode_advanced(uint8_t* address) {
        ZydisDecodedInstruction instruction;
        ZydisDecoderDecodeInstruction(&zydis_decoder_, nullptr, address, 15, &instruction);
        return instruction;
    }

    // Get boundaries
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

private:
    ZydisDecoder zydis_decoder_;
};

} // namespace veilhook::decode
