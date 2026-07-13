#include <veilhook/reloc.hpp>

#include <Zydis/Decoder.h>
#include <Zydis/Utils.h>
#include <asmjit/asmjit.h>
#include <asmjit/x86.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <unordered_map>
#include <vector>

namespace veilhook::reloc {
namespace {

using asmjit::x86::CondCode;

std::optional<CondCode> mnemonic_to_cond(ZydisMnemonic mnemonic) {
    using namespace asmjit::x86;
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_JO: return CondCode::kO;
    case ZYDIS_MNEMONIC_JNO: return CondCode::kNO;
    case ZYDIS_MNEMONIC_JB: return CondCode::kB;
    case ZYDIS_MNEMONIC_JNB: return CondCode::kAE;
    case ZYDIS_MNEMONIC_JZ: return CondCode::kZ;
    case ZYDIS_MNEMONIC_JNZ: return CondCode::kNZ;
    case ZYDIS_MNEMONIC_JBE: return CondCode::kBE;
    case ZYDIS_MNEMONIC_JNBE: return CondCode::kA;
    case ZYDIS_MNEMONIC_JS: return CondCode::kS;
    case ZYDIS_MNEMONIC_JNS: return CondCode::kNS;
    case ZYDIS_MNEMONIC_JP: return CondCode::kP;
    case ZYDIS_MNEMONIC_JNP: return CondCode::kNP;
    case ZYDIS_MNEMONIC_JL: return CondCode::kL;
    case ZYDIS_MNEMONIC_JNL: return CondCode::kGE;
    case ZYDIS_MNEMONIC_JLE: return CondCode::kLE;
    case ZYDIS_MNEMONIC_JNLE: return CondCode::kG;
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JRCXZ: return std::nullopt;
    default: return std::nullopt;
    }
}

bool is_internal_target(uint64_t target, uint64_t base, size_t size) {
    return target >= base && target < base + size;
}

size_t internal_offset(uint64_t target, uint64_t base) {
    return static_cast<size_t>(target - base);
}

bool instruction_has_rip_relative_memory(
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand* operands,
    const ZydisDecodedOperand** rip_operand) {
    for (ZyanU8 i = 0; i < instruction.operand_count; ++i) {
        if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY &&
            operands[i].mem.base == ZYDIS_REGISTER_RIP) {
            *rip_operand = &operands[i];
            return true;
        }
    }

    if (instruction.raw.disp.size != 0 &&
        instruction.raw.modrm.mod == 0 &&
        instruction.raw.modrm.rm == 5) {
        for (ZyanU8 i = 0; i < instruction.operand_count; ++i) {
            if (operands[i].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                *rip_operand = &operands[i];
                return true;
            }
        }
    }

    return false;
}

bool patch_rip_relative(
    std::vector<uint8_t>& bytes,
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand& operand,
    uint64_t old_runtime_ip,
    uint64_t new_runtime_ip,
    Status& status) {
    uint64_t absolute = 0;
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(
            &instruction, &operand, old_runtime_ip, &absolute))) {
        status = Status::UnsupportedInstruction;
        return true;
    }

    const int64_t new_disp = static_cast<int64_t>(absolute) -
        static_cast<int64_t>(new_runtime_ip + instruction.length);

    if (instruction.raw.disp.size == 8) {
        if (new_disp < INT8_MIN || new_disp > INT8_MAX) {
            status = Status::DispOverflow;
            return true;
        }
        if (instruction.raw.disp.offset == 0) {
            status = Status::UnsupportedInstruction;
            return true;
        }
        const auto disp8 = static_cast<int8_t>(new_disp);
        std::memcpy(bytes.data() + instruction.raw.disp.offset, &disp8, sizeof(disp8));
        return true;
    }

    if (instruction.raw.disp.size != 32) {
        status = Status::UnsupportedInstruction;
        return true;
    }

    if (new_disp < INT32_MIN || new_disp > INT32_MAX) {
        status = Status::DispOverflow;
        return true;
    }

    if (instruction.raw.disp.offset == 0) {
        status = Status::UnsupportedInstruction;
        return true;
    }

    const auto disp32 = static_cast<int32_t>(new_disp);
    std::memcpy(bytes.data() + instruction.raw.disp.offset, &disp32, sizeof(disp32));
    return true;
}

Status emit_raw_with_rip_fixup(
    asmjit::x86::Assembler& a,
    const uint8_t* bytes,
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand* operands,
    uint64_t old_runtime_ip,
    uint64_t emit_runtime_base) {
    std::vector<uint8_t> copy(bytes, bytes + instruction.length);

    const uint64_t new_runtime_ip = emit_runtime_base + static_cast<uint64_t>(a.offset());

    Status status = Status::Ok;
    const ZydisDecodedOperand* rip_operand = nullptr;
    if (!instruction_has_rip_relative_memory(instruction, operands, &rip_operand)) {
        a.embed(bytes, instruction.length);
        return Status::Ok;
    }

    if (patch_rip_relative(
            copy, instruction, *rip_operand, old_runtime_ip, new_runtime_ip, status)) {
        if (status != Status::Ok) {
            return status;
        }
        a.embed(copy.data(), copy.size());
        return Status::Ok;
    }

    a.embed(bytes, instruction.length);
    return Status::Ok;
}

Status emit_external_branch(asmjit::x86::Assembler& a, CondCode cond, uint64_t absolute_target) {
    using namespace asmjit::x86;
    asmjit::Label skip = a.newLabel();
    a.j(reverseCond(cond), skip);
    a.mov(rax, absolute_target);
    a.jmp(rax);
    a.bind(skip);
    return Status::Ok;
}

Status emit_relative_control_flow(
    asmjit::x86::Assembler& a,
    const ZydisDecodedInstruction& instruction,
    const ZydisDecodedOperand& operand,
    uint64_t old_runtime_ip,
    uint64_t stolen_runtime_base,
    size_t stolen_size,
    std::unordered_map<size_t, asmjit::Label>& internal_labels) {
    using namespace asmjit::x86;
    uint64_t absolute_target = 0;
    if (ZYAN_FAILED(ZydisCalcAbsoluteAddress(
            &instruction, &operand, old_runtime_ip, &absolute_target))) {
        return Status::UnsupportedInstruction;
    }

    if (is_internal_target(absolute_target, stolen_runtime_base, stolen_size)) {
        const size_t offset = internal_offset(absolute_target, stolen_runtime_base);
        asmjit::Label& target = internal_labels[offset];

        if (instruction.meta.category == ZYDIS_CATEGORY_CALL) {
            a.call(target);
            return Status::Ok;
        }

        if (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
            a.jmp(target);
            return Status::Ok;
        }

        const auto cond = mnemonic_to_cond(instruction.mnemonic);
        if (!cond) {
            return Status::UnsupportedInstruction;
        }

        a.j(*cond, target);
        return Status::Ok;
    }

    if (instruction.meta.category == ZYDIS_CATEGORY_CALL) {
        a.mov(rax, absolute_target);
        a.call(rax);
        return Status::Ok;
    }

    if (instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
        a.mov(rax, absolute_target);
        a.jmp(rax);
        return Status::Ok;
    }

    const auto cond = mnemonic_to_cond(instruction.mnemonic);
    if (!cond) {
        return Status::UnsupportedInstruction;
    }

    return emit_external_branch(a, *cond, absolute_target);
}

} // namespace

Status emit_stolen_range(
    asmjit::x86::Assembler& a,
    ZydisDecoder& decoder,
    const uint8_t* stolen,
    size_t stolen_size,
    uint64_t stolen_runtime_base,
    uint64_t emit_runtime_base) {
    using Label = asmjit::Label;
    if (!stolen || stolen_size == 0) {
        return Status::DecodeFailed;
    }

    std::unordered_map<size_t, Label> internal_labels;
  {
        size_t offset = 0;
        while (offset < stolen_size) {
            internal_labels.emplace(offset, a.newLabel());

            ZydisDecodedInstruction instruction{};
            if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(
                    &decoder, nullptr, stolen + offset, stolen_size - offset, &instruction)) ||
                instruction.length == 0) {
                return Status::DecodeFailed;
            }

            offset += instruction.length;
        }
    }

    size_t offset = 0;
    while (offset < stolen_size) {
        a.bind(internal_labels[offset]);

        const uint8_t* current = stolen + offset;
        ZydisDecodedInstruction instruction{};
        ZydisDecoderContext context{};
        if (ZYAN_FAILED(ZydisDecoderDecodeInstruction(
                &decoder, &context, current, stolen_size - offset, &instruction)) ||
            instruction.length == 0) {
            return Status::DecodeFailed;
        }

        std::array<ZydisDecodedOperand, ZYDIS_MAX_OPERAND_COUNT> operands{};
        if (instruction.operand_count > 0 &&
            ZYAN_FAILED(ZydisDecoderDecodeOperands(
                &decoder, &context, &instruction, operands.data(), instruction.operand_count))) {
            return Status::DecodeFailed;
        }

        const uint64_t old_runtime_ip = stolen_runtime_base + offset;
        bool emitted = false;

        if (instruction.meta.category == ZYDIS_CATEGORY_CALL ||
            instruction.meta.category == ZYDIS_CATEGORY_COND_BR ||
            instruction.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
            for (ZyanU8 i = 0; i < instruction.operand_count_visible; ++i) {
                if (operands[i].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[i].imm.is_relative) {
                    const Status status = emit_relative_control_flow(
                        a,
                        instruction,
                        operands[i],
                        old_runtime_ip,
                        stolen_runtime_base,
                        stolen_size,
                        internal_labels);
                    if (status != Status::Ok) {
                        return status;
                    }
                    emitted = true;
                    break;
                }
            }
        }

        if (!emitted) {
            const Status status = emit_raw_with_rip_fixup(
                a, current, instruction, operands.data(), old_runtime_ip, emit_runtime_base);
            if (status != Status::Ok) {
                return status;
            }
        }

        offset += instruction.length;
    }

    return Status::Ok;
}

} // namespace veilhook::reloc
