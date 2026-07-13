#include <veilhook/analyzer/prologue.hpp>
#include <cstring>
#include <vector>

namespace veilhook::analyzer {

std::vector<InstructionInfo> Prologue::analyze(uintptr_t target_function, size_t max_bytes) {
    std::vector<InstructionInfo> instructions;
    if (!target_function) return instructions;

    const uint8_t* current = reinterpret_cast<const uint8_t*>(target_function);
    size_t processed = 0;

    while (processed < max_bytes) {
        FdInstr instr;
        int ret = fd_decode(current, max_bytes - processed, 64, target_function + processed, &instr);
        
        if (ret <= 0) {
            break;
        }

        InstructionInfo info{};
        info.address = target_function + processed;
        info.length = instr.size;
        std::memcpy(info.bytes, current, instr.size);
        
        info.is_branch = (instr.type >= FDI_JA && instr.type <= FDI_JZ) || instr.type == FDI_JMP || instr.type == FDI_JMPF;
        info.is_call = (instr.type == FDI_CALL || instr.type == FDI_CALLF);
        info.branch_target = 0;

        if (info.is_branch || info.is_call) {
            for (int i = 0; i < 4; ++i) {
                if (instr.operands[i].type == FD_OT_OFF || instr.operands[i].type == FD_OT_IMM) {
                     if (current[0] == 0xE9 || current[0] == 0xE8) {
                         int32_t rel = *reinterpret_cast<const int32_t*>(current + 1);
                         info.branch_target = info.address + instr.size + rel;
                     }
                     break;
                }
            }
        }

        instructions.push_back(info);
        current += instr.size;
        processed += instr.size;
    }

    return instructions;
}

std::optional<size_t> Prologue::find_safe_hook_boundary(uintptr_t target_function, size_t required_bytes) {
    auto instructions = analyze(target_function, required_bytes + 15);
    size_t length = 0;

    for (const auto& instr : instructions) {
        length += instr.length;
        if (length >= required_bytes) {
            return length;
        }
    }
    return std::nullopt;
}

uintptr_t Prologue::resolve_jmp_chain(uintptr_t target_function, int max_depth) {
    uintptr_t current = target_function;
    int depth = 0;

    while (current && depth < max_depth) {
        const uint8_t* code = reinterpret_cast<const uint8_t*>(current);

        // Near JMP E9
        if (code[0] == 0xE9) {
            int32_t rel = *reinterpret_cast<const int32_t*>(code + 1);
            current = current + 5 + rel;
            depth++;
            continue;
        }

        // Indirect jmp [rip+disp32]
        if (code[0] == 0xFF && code[1] == 0x25) {
            int32_t rel = *reinterpret_cast<const int32_t*>(code + 2);
            uintptr_t ptr_address = current + 6 + rel;
            current = *reinterpret_cast<const uintptr_t*>(ptr_address);
            depth++;
            continue;
        }

        break;
    }

    return current;
}

} // namespace veilhook::analyzer
